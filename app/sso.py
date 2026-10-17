"""Mock Identity Provider (OAuth-style authorization-code flow).

Exchange returns ONLY the uum_user_id — modelling the "SSO returns just the
user id" contract so a real SSO (KIP) can replace this module without
touching the rest (D004).
"""
import asyncio
import secrets
import time

CODE_TTL = 60  # seconds


class Provider:
    def __init__(self):
        self.codes: dict[str, tuple[str, str, float]] = {}  # code -> (uum, redirect_uri, expires_at)
        self.mu = asyncio.Lock()

    def _sweep(self):
        now = time.time()
        for code in [c for c, (_, _, exp) in self.codes.items() if exp < now]:
            del self.codes[code]

    async def issue(self, uum_user_id: str, redirect_uri: str) -> str:
        """Create a one-time authorization code bound to (user, redirectURI)."""
        async with self.mu:
            self._sweep()
            code = secrets.token_hex(16)
            self.codes[code] = (uum_user_id, redirect_uri, time.time() + CODE_TTL)
            return code

    async def exchange(self, code: str, redirect_uri: str) -> str | None:
        """Consume a code (one-time). The identity payload intentionally
        contains nothing but the user id."""
        async with self.mu:
            entry = self.codes.pop(code, None)  # one-time use even when invalid
            if not entry:
                return None
            uum, bound_uri, expires_at = entry
            if expires_at < time.time() or bound_uri != redirect_uri:
                return None
            return uum
