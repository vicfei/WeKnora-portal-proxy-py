"""Postgres access to the portal_proxy database
(employees / kb_permissions / portal_sessions / audit_log).

无外键(跨库 + 沿用 WeKnora "No FK by design");时间一律 TIMESTAMPTZ。
Grant expiry is LAZY (D009): status stays 'active' in the DB; readers judge.
"""
import json
from datetime import datetime, timedelta, timezone

import asyncpg


class NotFound(Exception):
    pass


GRANT_COLS = ("id, uum_user_id, kb_id, permission, category, status, "
              "valid_until, granted_by, coalesce(reason,'') AS reason, created_at, updated_at")


def _grant_row(row) -> dict:
    valid_until = row["valid_until"]
    expired = valid_until is not None and valid_until < datetime.now(timezone.utc)
    return {
        "ID": row["id"], "UUMUserID": row["uum_user_id"], "KBID": row["kb_id"],
        "Permission": row["permission"], "Category": row["category"], "Status": row["status"],
        "ValidUntil": valid_until,
        "ValidUntilFmt": valid_until.strftime("%Y-%m-%d %H:%M") if valid_until else "永久",
        "GrantedBy": row["granted_by"], "Reason": row["reason"],
        "CreatedAt": row["created_at"], "UpdatedAt": row["updated_at"],
        "Expired": expired,
        "Effective": row["status"] == "active" and not expired,
    }


class Store:
    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    @classmethod
    async def open(cls, db_kwargs: dict) -> "Store":
        pool = await asyncpg.create_pool(**db_kwargs, min_size=1, max_size=8)
        return cls(pool)

    async def close(self):
        await self.pool.close()

    # ── employees ──────────────────────────────────────────────────

    async def get_employee(self, uum_user_id: str) -> dict | None:
        row = await self.pool.fetchrow(
            "SELECT uum_user_id, display_name, password_hash, is_admin, is_active "
            "FROM employees WHERE uum_user_id = $1", uum_user_id)
        if not row:
            return None
        return {"UUMUserID": row["uum_user_id"], "DisplayName": row["display_name"],
                "PasswordHash": row["password_hash"],
                "IsAdmin": row["is_admin"], "IsActive": row["is_active"]}

    async def search_employees(self, q: str = "", limit: int = 50) -> list[dict]:
        limit = max(1, min(limit, 100))
        rows = await self.pool.fetch(
            "SELECT uum_user_id, display_name, is_admin, is_active FROM employees "
            "WHERE ($1 = '' OR uum_user_id ILIKE '%'||$1||'%' OR display_name ILIKE '%'||$1||'%') "
            "AND is_active = true ORDER BY uum_user_id LIMIT $2", q, limit)
        return [{"UUMUserID": r["uum_user_id"], "DisplayName": r["display_name"],
                 "IsAdmin": r["is_admin"], "IsActive": r["is_active"]} for r in rows]

    # ── portal_sessions ────────────────────────────────────────────

    async def create_session(self, sid: str, uum_user_id: str, ttl: timedelta):
        await self.pool.execute(
            "INSERT INTO portal_sessions (id, uum_user_id, expires_at) "
            "VALUES ($1, $2, now() + make_interval(secs => $3))", sid, uum_user_id,
            int(ttl.total_seconds()))

    async def get_session_user(self, sid: str) -> str | None:
        return await self.pool.fetchval(
            "SELECT uum_user_id FROM portal_sessions WHERE id = $1 AND expires_at > now()", sid)

    async def delete_session(self, sid: str):
        await self.pool.execute("DELETE FROM portal_sessions WHERE id = $1", sid)

    async def sweep_sessions(self):
        await self.pool.execute("DELETE FROM portal_sessions WHERE expires_at <= now()")

    # ── kb_permissions ─────────────────────────────────────────────

    async def active_grants_by_user(self, uum_user_id: str) -> list[dict]:
        rows = await self.pool.fetch(
            f"SELECT {GRANT_COLS} FROM kb_permissions WHERE uum_user_id = $1 AND status = 'active'",
            uum_user_id)
        return [_grant_row(r) for r in rows]

    async def list_grants(self, uum_filter: str = "") -> list[dict]:
        rows = await self.pool.fetch(
            f"SELECT {GRANT_COLS} FROM kb_permissions "
            "WHERE ($1 = '' OR uum_user_id = $1) ORDER BY updated_at DESC LIMIT 500", uum_filter)
        return [_grant_row(r) for r in rows]

    async def get_grant(self, gid: int) -> dict | None:
        row = await self.pool.fetchrow(
            f"SELECT {GRANT_COLS} FROM kb_permissions WHERE id = $1", gid)
        return _grant_row(row) if row else None

    async def upsert_grant(self, g: dict):
        await self.pool.execute(
            "INSERT INTO kb_permissions (uum_user_id, kb_id, permission, category, status, valid_until, granted_by, reason) "
            "VALUES ($1,$2,$3,$4,'active',$5,$6,$7) "
            "ON CONFLICT (uum_user_id, kb_id) DO UPDATE SET "
            "permission = EXCLUDED.permission, category = EXCLUDED.category, "
            "status = 'active', valid_until = EXCLUDED.valid_until, "
            "granted_by = EXCLUDED.granted_by, reason = EXCLUDED.reason, updated_at = now()",
            g["UUMUserID"], g["KBID"], g["Permission"], g["Category"],
            g.get("ValidUntil"), g["GrantedBy"], g.get("Reason", ""))

    async def revoke_grant(self, gid: int) -> bool:
        n = await self.pool.execute(
            "UPDATE kb_permissions SET status='revoked', updated_at=now() WHERE id=$1 AND status='active'", gid)
        return n == "UPDATE 1"

    # ── audit_log ──────────────────────────────────────────────────

    async def insert_audit(self, actor: str, action: str, target: str, detail: dict | None = None):
        await self.pool.execute(
            "INSERT INTO audit_log (actor, action, target, detail) VALUES ($1,$2,$3,$4)",
            actor, action, target, json.dumps(detail or {}))

    async def list_audit(self, actor: str = "", action: str = "", limit: int = 100) -> list[dict]:
        limit = max(1, min(limit, 200))
        rows = await self.pool.fetch(
            "SELECT id, actor, action, target, detail::text, created_at FROM audit_log "
            "WHERE ($1='' OR actor=$1) AND ($2='' OR action=$2) ORDER BY id DESC LIMIT $3",
            actor, action, limit)
        return [{"ID": r["id"], "Actor": r["actor"], "Action": r["action"], "Target": r["target"],
                 "Detail": r["detail"], "CreatedAt": r["created_at"],
                 "CreatedAtFmt": r["created_at"].strftime("%m-%d %H:%M:%S")} for r in rows]
