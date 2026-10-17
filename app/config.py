"""portal-proxy configuration: env vars win over the optional .env file
(decision D010: secrets live only in env/.env — never in the repo)."""
import os
from dataclasses import dataclass
from pathlib import Path


def load_env_file(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {}
    vals = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        vals[k.strip()] = v.strip()
    return vals


@dataclass
class Config:
    addr: str                  # PROXY_ADDR, default :8081
    db_dsn: str                # PORTAL_DB_DSN
    weknora_base_url: str      # WEKNORA_BASE_URL, e.g. http://localhost:8080/api/v1
    weknora_tenant_id: int     # WEKNORA_TENANT_ID
    weknora_api_key: str       # WEKNORA_TENANT_KEY (plaintext tenant key)
    weknora_hmac: str          # WEKNORA_HMAC_SECRET (signed_token secret)
    cookie_secret: str         # PORTAL_COOKIE_SECRET

    @classmethod
    def load(cls, env_file: str) -> "Config":
        file_vals = load_env_file(env_file)

        def get(key, default=""):
            if os.environ.get(key, ""):
                return os.environ[key]
            return file_vals.get(key, "") or default

        tenant_id = 0
        raw = get("WEKNORA_TENANT_ID", "")
        if raw:
            try:
                tenant_id = int(raw)
            except ValueError:
                tenant_id = 0
        return cls(
            addr=get("PROXY_ADDR", ":8081"),
            db_dsn=get("PORTAL_DB_DSN", ""),
            weknora_base_url=get("WEKNORA_BASE_URL", "").rstrip("/"),
            weknora_tenant_id=tenant_id,
            weknora_api_key=get("WEKNORA_TENANT_KEY", ""),
            weknora_hmac=get("WEKNORA_HMAC_SECRET", ""),
            cookie_secret=get("PORTAL_COOKIE_SECRET", ""),
        )

    def validate(self) -> list:
        return [k for k, v in [
            ("PORTAL_DB_DSN", self.db_dsn),
            ("WEKNORA_BASE_URL", self.weknora_base_url),
            ("WEKNORA_TENANT_ID", self.weknora_tenant_id),
            ("WEKNORA_TENANT_KEY", self.weknora_api_key),
            ("WEKNORA_HMAC_SECRET", self.weknora_hmac),
        ] if not v]

    def db_kwargs(self) -> dict:
        """libpq keyword DSN -> asyncpg kwargs (values like 'p@ss w0rd!#' break
        asyncpg's own parser, so tokenize ourselves)."""
        kwargs = {"database": "postgres"}
        for token in self.db_dsn.split():
            if "=" not in token:
                continue
            k, _, v = token.partition("=")
            v = v.strip("'\"")
            if k in ("host", "port", "user", "password"):
                kwargs[k] = v
            elif k == "dbname":
                kwargs["database"] = v
        if "port" in kwargs:
            kwargs["port"] = int(kwargs["port"])
        return kwargs
