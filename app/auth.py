"""Portal sessions (cookie ↔ portal_sessions row). The dependency re-checks
employee.is_active on every request so a disabled employee loses access
immediately (功能文档 模块一)."""
import secrets
from datetime import timedelta

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse

COOKIE_NAME = "portal_session"
SESSION_TTL = 8 * 3600


class Identity:
    def __init__(self, uum_user_id: str, display_name: str, is_admin: bool):
        self.UUMUserID = uum_user_id
        self.DisplayName = display_name
        self.IsAdmin = is_admin


class AuthRequired(Exception):
    """Raised when no live session resolves; the handler turns this into a
    401 JSON (API/chat paths) or a /login redirect (pages)."""


class AdminRequired(Exception):
    pass


def _is_api_path(p: str) -> bool:
    return p.startswith("/api/") or p.startswith("/chat/")


async def start_session(resp, store, uum_user_id: str):
    sid = secrets.token_hex(16)
    await store.create_session(sid, uum_user_id, timedelta(seconds=SESSION_TTL))
    resp.set_cookie(COOKIE_NAME, sid, httponly=True, samesite="lax", path="/",
                    max_age=SESSION_TTL)


async def end_session(resp, request: Request, store):
    sid = request.cookies.get(COOKIE_NAME, "")
    if sid:
        await store.delete_session(sid)
    resp.delete_cookie(COOKIE_NAME, path="/")


# wired by app.web at startup (avoids a circular import and keeps the
# dependency signature FastAPI-friendly: only Request-annotated params)
store = None


def init(store_impl):
    global store
    store = store_impl


async def resolve_identity(request: Request) -> Identity:
    """FastAPI dependency: session cookie → session row → live employee."""
    sid = request.cookies.get(COOKIE_NAME, "")
    if not sid:
        raise AuthRequired()
    uum = await store.get_session_user(sid)
    if not uum:
        raise AuthRequired()
    emp = await store.get_employee(uum)
    if not emp or not emp["IsActive"]:
        # disabled employee: drop the session, refuse
        await store.delete_session(sid)
        raise AuthRequired()
    return Identity(emp["UUMUserID"], emp["DisplayName"], emp["IsAdmin"])


async def require_admin(identity: Identity):
    if not identity.IsAdmin:
        raise AdminRequired()


def auth_responses(request: Request, exc: Exception):
    if isinstance(exc, AdminRequired):
        return JSONResponse(
            {"success": False, "error": {"code": "forbidden", "message": "需要管理员权限"}},
            status_code=403)
    if _is_api_path(request.url.path):
        return JSONResponse(
            {"success": False, "error": {"code": "unauthorized", "message": "未登录或会话已过期"}},
            status_code=401)
    return RedirectResponse("/login", status_code=302)
