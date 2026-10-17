"""Permission engine unit tests (port of internal/perm/perm_test.go —
"correctness lives here, which is why every rule is unit-tested").

Run: .venv/bin/python -m unittest test_perm -v
"""
import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from app.perm import Engine


class FakeStore:
    def __init__(self, grants):
        self.grants = grants

    async def active_grants_by_user(self, uum):
        return [g for g in self.grants if g["UUMUserID"] == uum]


def grant(kb, perm="viewer", cat="团队", status="active", valid_until=None, uum="U1"):
    return {"UUMUserID": uum, "KBID": kb, "Permission": perm, "Category": cat,
            "Status": status, "ValidUntil": valid_until,
            "Effective": status == "active" and (valid_until is None or valid_until > datetime.now(timezone.utc))}


def kb(kid):
    return {"ID": kid, "Name": f"kb-{kid}", "KnowledgeCount": 0, "ChunkCount": 0}


class TestFilterKBs(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro) if False else asyncio.run(coro)

    def test_only_granted_kbs_survive(self):
        e = Engine(FakeStore([grant("a"), grant("b")]))
        out = self.run_async(e.filter_kbs("U1", [kb("a"), kb("c")]))
        self.assertEqual([k["ID"] for k in out], ["a"])

    def test_revoked_grant_filters_out(self):
        e = Engine(FakeStore([grant("a", status="revoked")]))
        out = self.run_async(e.filter_kbs("U1", [kb("a")]))
        self.assertEqual(out, [])

    def test_lazily_expired_grant_filters_out(self):
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        e = Engine(FakeStore([grant("a", valid_until=past)]))
        out = self.run_async(e.filter_kbs("U1", [kb("a")]))
        self.assertEqual(out, [])

    def test_duplicate_grants_editor_wins(self):
        e = Engine(FakeStore([grant("a", perm="viewer"), grant("a", perm="editor")]))
        out = self.run_async(e.filter_kbs("U1", [kb("a")]))
        self.assertEqual(out[0]["Permission"], "editor")
        self.assertEqual(out[0]["Category"], "团队")

    def test_decoration_carries_category(self):
        e = Engine(FakeStore([grant("a", cat="个人")]))
        out = self.run_async(e.filter_kbs("U1", [kb("a")]))
        self.assertEqual(out[0]["Category"], "个人")


class TestAuthorize(unittest.TestCase):
    def run_async(self, coro):
        return asyncio.run(coro)

    def test_authorize_ok(self):
        e = Engine(FakeStore([grant("a", perm="editor")]))
        g = self.run_async(e.authorize("U1", "a"))
        self.assertIsNotNone(g)
        self.assertTrue(self.run_async(e.can_edit("U1", "a")))

    def test_authorize_missing_is_none(self):
        e = Engine(FakeStore([grant("a")]))
        self.assertIsNone(self.run_async(e.authorize("U1", "zzz")))
        self.assertFalse(self.run_async(e.can_edit("U1", "zzz")))

    def test_viewer_cannot_edit(self):
        e = Engine(FakeStore([grant("a", perm="viewer")]))
        self.assertFalse(self.run_async(e.can_edit("U1", "a")))

    def test_expired_grant_not_effective(self):
        past = datetime.now(timezone.utc) - timedelta(minutes=1)
        e = Engine(FakeStore([grant("a", valid_until=past)]))
        self.assertIsNone(self.run_async(e.authorize("U1", "a")))


if __name__ == "__main__":
    unittest.main()
