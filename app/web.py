"""portal-proxy-py: the B1-route portal proxy (Python port).

独立门户代理服务:持有「用户↔知识库」权限表,经 tenant-key API 通道调用
WeKnora,逐请求按用户过滤后呈现。WeKnora **零代码改动**,所有对接均为
运行时配置。

    browser ──> portal proxy(:8081) ──> WeKnora(:8080, tenant key + signed_token)
                    └── 权限表(独立数据库 portal_proxy,不进 WeKnora 库)
"""
import asyncio
import json
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import urlencode, quote

import bcrypt
from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import auth
from .auth import AdminRequired, AuthRequired, Identity, auth_responses, resolve_identity
from .config import Config
from .perm import Engine
from .sso import Provider
from .store import NotFound, Store
from .weknora import Client, WeKnoraError

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("proxy")

cfg = Config.load(os.environ.get("PROXY_ENV_FILE", ".env"))
missing = cfg.validate()
if missing:
    raise SystemExit(f"missing required config: {missing} (see .env.example / 外部接口.md §六)")

templates = Jinja2Templates(directory="templates")
store: Store | None = None
idp = Provider()
wk: Client | None = None
engine: Engine | None = None


async def sweep_loop():
    """Background session sweeper (every 10 min)."""
    while True:
        await asyncio.sleep(600)
        try:
            await store.sweep_sessions()
        except Exception as e:  # never let the sweeper die
            log.warning("session sweep failed: %s", e)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global store, wk, engine
    store = await Store.open(cfg.db_kwargs())
    auth.init(store)
    wk = Client(cfg.weknora_base_url, cfg.weknora_tenant_id, cfg.weknora_api_key, cfg.weknora_hmac)
    engine = Engine(store)
    task = asyncio.create_task(sweep_loop())
    yield
    task.cancel()
    await store.close()
    await wk.close()


app = FastAPI(title="WeKnora-portal-proxy-py", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
app.add_exception_handler(AuthRequired, auth_responses)
app.add_exception_handler(AdminRequired, auth_responses)


def write_err(status: int, code: str, msg: str):
    return JSONResponse({"success": False, "error": {"code": code, "message": msg}}, status_code=status)


def ok_json(data) -> Response:
    """data envelope with lenient serialization (datetimes → ISO strings)."""
    return Response(json.dumps({"success": True, "data": data}, default=str, ensure_ascii=False),
                    media_type="application/json")


def render(request: Request, name: str, title: str, user: Identity | None, ctx: dict | None = None):
    ctx = dict(ctx or {})
    ctx.update({"request": request, "Title": title,
                "User": {"UUMUserID": user.UUMUserID, "DisplayName": user.DisplayName,
                         "IsAdmin": user.IsAdmin} if user else None})
    return templates.TemplateResponse(request, name + ".html", ctx)


async def deny_kb(user: Identity, kb_id: str, via: str):
    """Answer 404 (never 403 — do not reveal KB existence, D008) and audit."""
    await store.insert_audit(user.UUMUserID, "denied", f"kb:{kb_id}", {"via": via})
    return Response("404 page not found", status_code=404, media_type="text/plain")


# ── static & health ────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return JSONResponse({"success": True, "data": "ok"})


@app.get("/healthz/weknora")
async def healthz_weknora():
    try:
        await wk.ping()
    except Exception as e:
        return write_err(502, "weknora_unreachable", str(e))
    return JSONResponse({"success": True, "data": "weknora ok"})


# ── SSO mock + session ─────────────────────────────────────────────

@app.get("/login")
async def login():
    return RedirectResponse("/sso/authorize?redirect_uri=/sso/callback", status_code=302)


@app.get("/sso/authorize", response_class=HTMLResponse)
async def sso_authorize_page(request: Request):
    return render(request, "sso_login", "登录", None, {
        "RedirectURI": request.query_params.get("redirect_uri", ""),
        "Error": request.query_params.get("error", ""),
    })


@app.post("/sso/authorize")
async def sso_authorize_submit(request: Request,
                               uum_user_id: str = Form(""), password: str = Form(""),
                               redirect_uri: str = Form("")):
    redirect_uri = redirect_uri or "/sso/callback"

    def deny(reason: str):
        return RedirectResponse(
            "/sso/authorize?" + urlencode({"redirect_uri": redirect_uri, "error": reason}),
            status_code=302)

    emp = await store.get_employee(uum_user_id)
    ok = False
    if emp is not None:
        try:
            ok = bcrypt.checkpw(password.encode(), emp["PasswordHash"].encode())
        except ValueError:
            ok = False
    if emp is None or not ok:
        await store.insert_audit(uum_user_id, "login", "sso", {"ok": False, "reason": "bad_credentials"})
        return deny("工号或密码错误")
    if not emp["IsActive"]:
        await store.insert_audit(uum_user_id, "login", "sso", {"ok": False, "reason": "inactive"})
        return deny("账号已禁用")
    code = await idp.issue(uum_user_id, redirect_uri)
    return RedirectResponse(f"{redirect_uri}?code={code}", status_code=302)


@app.get("/sso/callback")
async def sso_callback(request: Request):
    code = request.query_params.get("code", "")
    # Exchange returns ONLY the user id — the "SSO gives just user_id" contract (D004).
    uum = await idp.exchange(code, "/sso/callback")
    if not uum:
        return RedirectResponse(
            "/sso/authorize?redirect_uri=/sso/callback&error=" + quote("code 无效或已过期"),
            status_code=302)
    resp = RedirectResponse("/", status_code=302)
    await auth.start_session(resp, store, uum)
    await store.insert_audit(uum, "login", "portal", {"ok": True})
    return resp


@app.post("/logout")
async def logout(request: Request, user: Identity = Depends(resolve_identity)):
    await store.insert_audit(user.UUMUserID, "logout", "portal", None)
    resp = RedirectResponse("/login", status_code=302)
    await auth.end_session(resp, request, store)
    return resp


# ── end-user pages ─────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def home(request: Request, user: Identity = Depends(resolve_identity)):
    try:
        kbs = await wk.list_kbs(user.UUMUserID)
    except WeKnoraError as e:
        return Response(f"WeKnora 列表获取失败: {e}", status_code=502)
    view = await engine.filter_kbs(user.UUMUserID, kbs)
    order = ["个人", "团队", "公共"]
    groups = [{"Category": c, "KBs": []} for c in order]
    idx = {g["Category"]: i for i, g in enumerate(groups)}
    for kb in view:
        if kb["Category"] not in idx:
            idx[kb["Category"]] = len(groups)
            groups.append({"Category": kb["Category"], "KBs": []})
        groups[idx[kb["Category"]]]["KBs"].append(kb)
    return render(request, "home", "知识库", user, {"Groups": groups})


@app.get("/kb/{kb_id}", response_class=HTMLResponse)
async def kb_detail(request: Request, kb_id: str, user: Identity = Depends(resolve_identity)):
    g = await engine.authorize(user.UUMUserID, kb_id)
    if not g:
        return await deny_kb(user, kb_id, "page")
    try:
        kb = await wk.get_kb(user.UUMUserID, kb_id)
    except WeKnoraError as e:
        return Response(f"WeKnora 详情获取失败: {e}", status_code=502)
    docs = await wk.list_docs(user.UUMUserID, kb_id) or []
    return render(request, "kb_detail", kb["Name"], user, {
        "KB": kb, "Docs": docs, "Permission": g["Permission"],
        "CanEdit": g["Permission"] == "editor"})


@app.post("/kb/{kb_id}/search")
async def kb_search(request: Request, kb_id: str, user: Identity = Depends(resolve_identity)):
    if not await engine.authorize(user.UUMUserID, kb_id):
        await deny_kb(user, kb_id, "search")
        return write_err(404, "not_found", "知识库不存在")
    payload = await request.body()
    await store.insert_audit(user.UUMUserID, "search", f"kb:{kb_id}", None)
    try:
        data = await wk.hybrid_search(user.UUMUserID, kb_id, payload)
    except WeKnoraError as e:
        return write_err(502, "weknora_error", str(e))
    return JSONResponse({"success": True, "data": data})


@app.post("/kb/{kb_id}/upload")
async def kb_upload(kb_id: str, file: UploadFile = File(...),
                    user: Identity = Depends(resolve_identity)):
    g = await engine.authorize(user.UUMUserID, kb_id)
    if not g:
        return await deny_kb(user, kb_id, "upload")  # no access at all → 404 (D008)
    if g["Permission"] != "editor":
        await store.insert_audit(user.UUMUserID, "denied", f"kb:{kb_id}",
                                 {"via": "upload", "reason": "viewer"})
        return write_err(403, "forbidden", "需要 editor 权限")
    content = await file.read()
    try:
        data = await wk.upload_file(user.UUMUserID, kb_id, file.filename or "upload", content)
    except WeKnoraError as e:
        return write_err(502, "weknora_error", str(e))
    await store.insert_audit(user.UUMUserID, "upload", f"kb:{kb_id}", {"file": file.filename})
    return JSONResponse({"success": True, "data": data})


# ── chat ───────────────────────────────────────────────────────────

@app.get("/chat", response_class=HTMLResponse)
async def chat_page(request: Request, user: Identity = Depends(resolve_identity)):
    kbs = await wk.list_kbs(user.UUMUserID)
    view = await engine.filter_kbs(user.UUMUserID, kbs)
    sessions = await wk.list_sessions(user.UUMUserID)
    return render(request, "chat", "问答", user, {
        "KBs": view, "Sessions": sessions,
        "InitSession": sessions[0]["ID"] if sessions else ""})


@app.post("/chat/session")
async def chat_session_create(user: Identity = Depends(resolve_identity)):
    try:
        sid = await wk.create_session(user.UUMUserID)
    except WeKnoraError as e:
        return write_err(502, "weknora_error", str(e))
    return JSONResponse({"success": True, "data": {"session_id": sid}})


@app.post("/chat/{sid}")
async def chat_send(sid: str, request: Request, user: Identity = Depends(resolve_identity)):
    try:
        body = json.loads(await request.body())
    except Exception:
        body = None
    if not body or not body.get("query_text"):
        return write_err(400, "bad_body", "query_text 必填")
    kb_ids = body.get("kb_ids") or []
    # Every referenced KB must pass the permission gate before forwarding.
    for kb_id in kb_ids:
        if not await engine.authorize(user.UUMUserID, kb_id):
            await deny_kb(user, kb_id, "chat")
            return write_err(404, "not_found", f"引用的知识库不存在: {kb_id}")
    # Portal contract uses query_text; WeKnora's QA DTO expects "query".
    payload = json.dumps({"query": body["query_text"], "knowledge_base_ids": kb_ids,
                          "disable_title": False}).encode()
    upstream = await wk.chat_sse(user.UUMUserID, sid, payload)

    async def stream():
        try:
            async for chunk in upstream.aiter_raw():
                if chunk:
                    yield chunk
        except Exception as e:
            yield f'data: {{"response_type":"error","error":"{e}"}}\n\n'.encode()
        finally:
            await upstream.aclose()

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


# ── admin ──────────────────────────────────────────────────────────

async def admin_identity(user: Identity = Depends(resolve_identity)) -> Identity:
    if not user.IsAdmin:
        raise AdminRequired()
    return user


@app.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, user: Identity = Depends(admin_identity)):
    employees = await store.search_employees("", 100)
    all_kbs = await wk.list_kbs(user.UUMUserID)
    grants = await store.list_grants("")
    kb_name = {kb["ID"]: kb["Name"] for kb in all_kbs}
    rows = []
    for g in grants:
        row = dict(g)
        row["KBName"] = kb_name.get(g["KBID"], "")
        rows.append(row)
    audit = await store.list_audit("", "", 100)
    return render(request, "admin", "管理后台", user, {
        "Employees": employees, "AllKBs": all_kbs, "GrantRows": rows, "AuditRows": audit})


@app.get("/api/admin/employees")
async def admin_employees(request: Request, user: Identity = Depends(admin_identity)):
    employees = await store.search_employees(request.query_params.get("q", ""), 50)
    return ok_json(employees)


@app.get("/api/admin/kbs")
async def admin_kbs(user: Identity = Depends(admin_identity)):
    try:
        kbs = await wk.list_kbs(user.UUMUserID)
    except WeKnoraError as e:
        return write_err(502, "weknora_error", str(e))
    return ok_json(kbs)


@app.get("/api/admin/permissions")
async def admin_permissions(request: Request, user: Identity = Depends(admin_identity)):
    grants = await store.list_grants(request.query_params.get("uum_user_id", ""))
    return ok_json(grants)


@app.post("/api/admin/permissions")
async def admin_upsert_permission(request: Request, user: Identity = Depends(admin_identity)):
    try:
        req = json.loads(await request.body())
    except Exception:
        req = None
    if not req or not req.get("uum_user_id") or not req.get("kb_id"):
        return write_err(400, "bad_body", "uum_user_id 与 kb_id 必填")
    permission = req.get("permission") or "viewer"
    category = req.get("category") or "团队"
    if permission not in ("viewer", "editor"):
        return write_err(400, "bad_perm", "permission 仅支持 viewer/editor")
    g = {"UUMUserID": req["uum_user_id"], "KBID": req["kb_id"], "Permission": permission,
         "Category": category, "GrantedBy": user.UUMUserID, "Reason": req.get("reason", ""),
         "ValidUntil": None}
    if req.get("valid_until"):
        try:
            g["ValidUntil"] = datetime.fromisoformat(req["valid_until"].replace("Z", "+00:00"))
        except ValueError:
            return write_err(400, "bad_valid_until", "valid_until 须为 RFC3339")
    await store.upsert_grant(g)
    await store.insert_audit(user.UUMUserID, "grant",
                             f"kb:{req['kb_id']} user:{req['uum_user_id']}",
                             {"permission": permission, "category": category,
                              "valid_until": req.get("valid_until", "")})
    return JSONResponse({"success": True, "data": "ok"})


@app.delete("/api/admin/permissions/{gid}")
async def admin_revoke_permission(gid: int, user: Identity = Depends(admin_identity)):
    try:
        g = await store.get_grant(gid)
    except NotFound:
        return write_err(404, "not_found", "授权不存在")
    if not g:
        return write_err(404, "not_found", "授权不存在")
    await store.revoke_grant(gid)
    await store.insert_audit(user.UUMUserID, "revoke", f"kb:{g['KBID']} user:{g['UUMUserID']}", None)
    return JSONResponse({"success": True, "data": "ok"})


@app.get("/api/admin/audit")
async def admin_audit(request: Request, user: Identity = Depends(admin_identity)):
    q = request.query_params
    audit = await store.list_audit(q.get("actor", ""), q.get("action", ""), 100)
    return ok_json(audit)
