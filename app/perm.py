"""The permission engine: the ONLY place that decides which KBs a user may
see and at what level. WeKnora itself enforces nothing per-user for this
key — correctness lives here (架构设计 §六-1), which is why every rule is
unit-tested (see test_perm.py)."""
from .store import Store


class Engine:
    def __init__(self, store: Store):
        self.store = store

    async def filter_kbs(self, uum_user_id: str, kbs: list[dict]) -> list[dict]:
        """Keep only KBs with an effective grant and decorate them.
        Duplicate KB ids in grants: the editor permission wins (higher)."""
        grants = await self.store.active_grants_by_user(uum_user_id)
        by_kb: dict[str, dict] = {}
        for g in grants:
            if not g["Effective"]:
                continue  # revoked or lazily expired (D009)
            prev = by_kb.get(g["KBID"])
            if prev is not None:
                if g["Permission"] == "editor" and prev["Permission"] != "editor":
                    by_kb[g["KBID"]] = g
                continue
            by_kb[g["KBID"]] = g
        out = []
        for kb in kbs:
            g = by_kb.get(kb["ID"])
            if not g:
                continue
            decorated = dict(kb)
            decorated["Category"] = g["Category"]
            decorated["Permission"] = g["Permission"]
            out.append(decorated)
        return out

    async def authorize(self, uum_user_id: str, kb_id: str) -> dict | None:
        """Effective grant for one KB. None means the caller must answer
        404 (not 403 — do not reveal existence, D008)."""
        grants = await self.store.active_grants_by_user(uum_user_id)
        for g in grants:
            if g["KBID"] == kb_id and g["Effective"]:
                return g
        return None

    async def can_edit(self, uum_user_id: str, kb_id: str) -> bool:
        g = await self.authorize(uum_user_id, kb_id)
        return bool(g) and g["Permission"] == "editor"
