# WeKnora-portal-proxy-py（B1 路线 POC · Python 版）

`WeKnora-portal-proxy`（Go 原作）的 Python 移植。独立门户代理服务：持有「用户↔知识库」
权限表，经 tenant-key API 通道调用 WeKnora，逐请求按用户过滤后呈现。WeKnora
**零代码改动**，所有对接均为运行时配置。

## 架构位置

```
浏览器 ──> 公司门户/本代理(:8081) ──> WeKnora app(:8080, tenant key + signed_token)
                │
                └── 权限表（独立数据库 portal_proxy，不进 WeKnora 库）
```

## 与 Go 原作的关系

逐语义移植：tenant key + `X-Tenant-ID` + 每请求 `X-External-User-Token`
（HS256 HMAC 自签外部用户 JWT，TTL 30 分钟，D002/D007）；权限引擎
（filter/authorize/can_edit，惰性过期 D009、重复授权 editor 优先）；SSO 模拟
（授权码一次性 + 60s TTL，只返回 user_id，D004）；portal_sessions（8h + 10 分钟清扫）；
审计四表（`schema/portal_proxy.sql`）；404 不暴露存在性（D008）；admin 管理台。
UI 模板由 Go html/template 机械转换为 Jinja2，HTML/CSS/JS 逐字节保留。

| Go 件 | Python 件 |
|---|---|
| `internal/weknora`（golang-jwt HS256） | `app/weknora.py`（PyJWT） |
| `internal/perm`（权限引擎） | `app/perm.py`（+ `test_perm.py` 单测） |
| `internal/store`（pgx） | `app/store.py`（asyncpg） |
| `internal/sso`（模拟 IdP） | `app/sso.py` |
| `internal/auth`（会话中间件） | `app/auth.py`（FastAPI dependency） |
| `internal/web`（路由+模板） | `app/web.py`（FastAPI + Jinja2） |

## 运行

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
# 建库（幂等）:
sudo docker exec WeKnora-postgres-dev psql -U postgres -c "CREATE DATABASE portal_proxy;"
sudo docker exec -i WeKnora-postgres-dev psql -U postgres -d portal_proxy < schema/portal_proxy.sql
cp .env.example .env    # 填租户/key/hmac（需在 WeKnora 侧开通 signed_token principal）
.venv/bin/python -m unittest test_perm -v   # 权限引擎单测
.venv/bin/python -m app --env .env
```

WeKnora 侧开通（管理员）：

```bash
PUT /api/v1/tenants/{id}/api-principal-config  {"mode":"signed_token","hmac_secret":"..."}
POST /api/v1/tenants/{id}/api-keys            {"name":"portal-proxy-poc",
                                                "capabilities":["retrieve","ingest","chat"]}
```

## 纪律（POC 期间必须遵守，与 Go 版同款）

1. WeKnora 仓库零接触：若发现必须改 WeKnora 代码才能继续，立即停下重新评估路线；
2. 权限表建在独立数据库，POC 结束一条 `DROP DATABASE` 清场；
3. tenant key 能力最小化（仅 retrieve/ingest/chat，不发放 full access）；
4. 测试数据使用 `REVIEW-` 前缀工号（密码 review123456），不触碰演示数据。

## POC 验收剧本（与 v2 路线共用同一考题）

登录（桩）→ 分组 KB 列表 → KB 检索 → SSE 聊天（带引用）→ 上传文档 →
越权验证（A 访问 B 的 KB 必须被拒，404 不暴露存在性）
