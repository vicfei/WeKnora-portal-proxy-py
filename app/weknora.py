"""HTTP client for the WeKnora API channel:
tenant key + X-Tenant-ID + per-request X-External-User-Token (D002/D007).
The external JWT carries sub=uum_user_id so WeKnora attributes sessions and
audit to api_external_user:{tenant}:{sub}."""
import time

import httpx
import jwt

EXTERNAL_JWT_TTL = 30 * 60  # well under WeKnora's 24h cap (D007)


class WeKnoraError(Exception):
    pass


def _kb(raw: dict) -> dict:
    return {"ID": raw.get("id", ""), "Name": raw.get("name", ""),
            "Description": raw.get("description", ""), "Type": raw.get("type", ""),
            "KnowledgeCount": raw.get("knowledge_count", 0), "ChunkCount": raw.get("chunk_count", 0)}


class Client:
    def __init__(self, base_url: str, tenant_id: int, api_key: str, hmac: str):
        self.base_url = base_url
        self.tenant_id = tenant_id
        self.api_key = api_key
        self.hmac = hmac
        self.http = httpx.AsyncClient(timeout=120)
        # long-lived SSE stream: no read timeout (Go used a dedicated 300s client)
        self.stream_http = httpx.AsyncClient(timeout=httpx.Timeout(300, read=None))

    async def close(self):
        await self.http.aclose()
        await self.stream_http.aclose()

    def sign_external_jwt(self, sub: str) -> str:
        """Mint the per-user virtual principal token (HS256)."""
        now = int(time.time())
        claims = {"sub": sub, "tenant_id": self.tenant_id, "aud": "weknora",
                  "iat": now, "exp": now + EXTERNAL_JWT_TTL}
        return jwt.encode(claims, self.hmac, algorithm="HS256")

    def _headers(self, sub: str) -> dict:
        return {
            "X-API-Key": self.api_key,
            "X-Tenant-ID": str(self.tenant_id),
            "X-External-User-Token": self.sign_external_jwt(sub),
        }

    async def _do(self, method: str, path: str, sub: str, **kw) -> object:
        extra_headers = kw.pop("headers", {})
        headers = {**self._headers(sub), **extra_headers}
        resp = await self.http.request(method, self.base_url + path, headers=headers, **kw)
        try:
            env = resp.json()
        except Exception:
            raise WeKnoraError(f"weknora {path}: non-JSON response (HTTP {resp.status_code})")
        if not env.get("success"):
            msg = (env.get("error") or {}).get("message", "unknown error")
            raise WeKnoraError(f"weknora {path}: HTTP {resp.status_code}: {msg}")
        return env.get("data")

    # ── knowledge bases ────────────────────────────────────────────

    async def list_kbs(self, sub: str) -> list[dict]:
        data = await self._do("GET", "/knowledge-bases", sub)
        return [_kb(x) for x in (data or [])]

    async def get_kb(self, sub: str, kb_id: str) -> dict:
        data = await self._do("GET", f"/knowledge-bases/{kb_id}", sub)
        return _kb(data or {})

    async def list_docs(self, sub: str, kb_id: str) -> list[dict]:
        data = await self._do("GET", f"/knowledge-bases/{kb_id}/knowledge?page=1&page_size=50", sub)
        # Response may be a bare array or {list:[...]}: accept both.
        items = data if isinstance(data, list) else (data or {}).get("list", [])
        return [{"ID": x.get("id", ""), "Title": x.get("title", ""), "Type": x.get("type", ""),
                 "ParseStatus": x.get("parse_status", ""),
                 "CreatedAt": x.get("created_at", "")} for x in items or []]

    async def hybrid_search(self, sub: str, kb_id: str, payload: bytes) -> object:
        return await self._do("POST", f"/knowledge-bases/{kb_id}/hybrid-search", sub,
                              content=payload, headers={"Content-Type": "application/json"})

    async def upload_file(self, sub: str, kb_id: str, filename: str, content: bytes) -> object:
        return await self._do("POST", f"/knowledge-bases/{kb_id}/knowledge/file", sub,
                              files={"file": (filename, content)})

    # ── chat sessions ──────────────────────────────────────────────

    async def create_session(self, sub: str) -> str:
        data = await self._do("POST", "/sessions", sub, json={})
        return (data or {}).get("id", "")

    async def list_sessions(self, sub: str) -> list[dict]:
        data = await self._do("GET", "/sessions", sub)
        return [{"ID": x.get("id", ""), "Title": x.get("title", "")} for x in (data or [])]

    async def chat_sse(self, sub: str, session_id: str, payload: bytes):
        """Stream WeKnora's knowledge-chat response verbatim (no parsing /
        rewriting — 架构设计.md 流 3). Yields raw chunks."""
        req = self.stream_http.build_request(
            "POST", f"{self.base_url}/knowledge-chat/{session_id}",
            headers={**self._headers(sub), "Accept": "text/event-stream"},
            content=payload)
        return await self.stream_http.send(req, stream=True)

    async def ping(self):
        """Verify the whole signed-token channel end to end."""
        await self._do("GET", "/knowledge-bases", "healthcheck")
