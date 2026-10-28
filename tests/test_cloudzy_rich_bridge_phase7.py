"""Phase 7 stage-2 opt-in bot callback integration tests. No Telegram network."""
import asyncio
from contextlib import contextmanager
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_rich_bridge import (
    ENTRY, can_view, configured_admin_ids, empty_card,
    handle_rich_admin_callback, latest_owned_operation,
)
from cloudzy_rich_transport import RichDeliveryHold

A = "a"*32
B = "b"*32
C = "c"*32
ENV = {
    "NVL_CLOUDZY_RICH_UI_ENABLED": "1",
    "NVL_CLOUDZY_RICH_ADMIN_IDS": "7,9,11",
}


class NoNetworkAPI:
    calls = []

    def __init__(self, token):
        assert token == "test-token"
        self.calls = NoNetworkAPI.calls

    async def send(self, *, chat_id, rich_message):
        self.calls.append(("SEND", chat_id, rich_message))
        return 123

    async def edit(self, *, chat_id, message_id, rich_message):
        self.calls.append(("EDIT", chat_id, rich_message))
        assert message_id == 123
        return True


class FakeQuery:
    def __init__(self, message_id=None):
        self.message = type("Msg", (), {"message_id": message_id})()


class Phase7BridgeTests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name)/"test.db"

        @contextmanager
        def db_conn():
            conn = sqlite3.connect(str(path))
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

        self.db_conn = db_conn
        self.context = type(
            "Ctx", (), {"bot": type("Bot", (), {"token": "test-token"})()})()
        NoNetworkAPI.calls = []
        with db_conn() as db:
            db.executescript("""
                CREATE TABLE cloudzy_cz07_jobs(
                    id TEXT PRIMARY KEY,actor INTEGER,chat INTEGER,
                    status TEXT,code TEXT,source TEXT,target TEXT,
                    moved INTEGER,total INTEGER,started_at INTEGER);
                CREATE TABLE cloudzy_cz07_events(
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,job_id TEXT,
                    stage TEXT,code TEXT);
                CREATE TABLE cloudzy_uo_operations(
                    id TEXT PRIMARY KEY,actor INTEGER,chat INTEGER,
                    step TEXT,state TEXT,code TEXT,version INTEGER,
                    updated_at INTEGER);
            """)
            db.execute(
                "INSERT INTO cloudzy_cz07_jobs VALUES(?,?,?,?,?,?,?,?,?,?)",
                (A,7,7,"VERIFYING","AWAITING_BUSINESS_E2E",
                 "45.61.180.119","144.172.68.100",200,488,100))
            db.execute(
                "INSERT INTO cloudzy_cz07_events(job_id,stage,code)"
                " VALUES (?,?,?)", (A,"VERIFYING","AWAITING_BUSINESS_E2E"))
            db.execute(
                "INSERT INTO cloudzy_cz07_jobs VALUES(?,?,?,?,?,?,?,?,?,?)",
                (B,9,9,"HOLD","PROVIDER_RESULT_UNCERTAIN",
                 "45.61.180.119","144.172.68.111",0,9,600))
            db.execute(
                "INSERT INTO cloudzy_uo_operations VALUES(?,?,?,?,?,?,?,?)",
                (C,7,7,"DNS_CUTOVER","RECONCILE_REQUIRED",
                 "DNS_OR_DEFAULT_UNCERTAIN_LOCK_HELD",4,150))

    def open(self, data, actor=7, chat=7, role="admin", private=True,
             message_id=None, env=ENV):
        return asyncio.run(handle_rich_admin_callback(
            data=data, query=FakeQuery(message_id),
            context=self.context, db_factory=self.db_conn, role=role,
            actor=actor, chat=chat, is_private=private,
            api_factory=NoNetworkAPI, env=env))

    def test_requires_private_real_admin_allowlist_and_optin(self):
        self.assertEqual(configured_admin_ids(ENV), frozenset({7,9,11}))
        for field in (
            {"NVL_CLOUDZY_RICH_UI_ENABLED": "0", "NVL_CLOUDZY_RICH_ADMIN_IDS": "7,9,11"},
            {"NVL_CLOUDZY_RICH_UI_ENABLED": "1", "NVL_CLOUDZY_RICH_ADMIN_IDS": "7,7"},
            {"NVL_CLOUDZY_RICH_UI_ENABLED": "1", "NVL_CLOUDZY_RICH_ADMIN_IDS": "7,9,11,13"},
        ):
            self.assertFalse(can_view(role="admin", actor=7, chat=7,
                                      is_private=True, env=field))
            self.assertEqual(self.open(ENTRY, env=field), "DENIED")
        for role, actor, chat, private in [
            ("agent",7,7,True), ("admin",8,8,True),
            ("admin",7,-100,False), ("admin",9,7,True),
            ("admin",7,7,False), ("accountant",7,7,True),
        ]:
            self.assertFalse(can_view(role=role,actor=actor,chat=chat,
                                      is_private=private,env=ENV))
            self.assertEqual(self.open(
                ENTRY, role=role, actor=actor, chat=chat,
                private=private), "DENIED")
        self.assertEqual(NoNetworkAPI.calls, [])

    def test_latest_owner_isolated_and_source_only(self):
        with self.db_conn() as db:
            db.execute("PRAGMA query_only=ON")
            self.assertEqual(latest_owned_operation(db,actor=7,chat=7),
                             ("UO", C))
            self.assertEqual(latest_owned_operation(db,actor=9,chat=9),
                             ("CZ07", B))
            self.assertIsNone(latest_owned_operation(db,actor=11,chat=11))
        self.assertEqual(self.open(ENTRY), "SENT")
        self.assertEqual(self.open(ENTRY, actor=9,chat=9), "SENT")
        self.assertEqual(self.open(ENTRY, actor=11,chat=11), "EMPTY")
        self.assertEqual(len(NoNetworkAPI.calls), 3)
        self.assertEqual(NoNetworkAPI.calls[0][1],7)
        self.assertIn("blocks", NoNetworkAPI.calls[0][2])
        self.assertNotIn("html",NoNetworkAPI.calls[0][2])

    def test_reauthenticates_source_and_acknowledged_message_each_click(self):
        self.assertEqual(self.open(ENTRY), "SENT")
        self.assertEqual(self.open("u7:d:uo:"+C, message_id=123), "SENT")
        self.assertEqual(self.open("u7:r:uo:"+C, message_id=123), "SENT")
        self.assertEqual(self.open("u7:r:uo:"+C, message_id=123), "UNCHANGED")
        self.assertEqual([item[0] for item in NoNetworkAPI.calls],
                         ["SEND","EDIT","EDIT"])
        for forged in (
            "u7:d:uo:"+B,    # other owner's account / ID
            "u7:x:uo:"+C,    # mutation prefix forbidden
            "u7:d:uo:"+("d"*32),
            "u7:d:cz07:"+A,  # valid own ID but no acknowledged Rich pointer
        ):
            self.assertEqual(self.open(forged,message_id=123), "HOLD")
        self.assertEqual(self.open("u7:d:uo:"+C,message_id=999), "HOLD")
        self.assertEqual(self.open("u7:d:uo:"+C,actor=9,chat=9,
                                   message_id=123), "HOLD")
        self.assertEqual(len(NoNetworkAPI.calls),3)

    def test_new_journal_event_updates_one_card_and_not_business_state(self):
        self.assertEqual(self.open(ENTRY), "SENT")
        with self.db_conn() as db:
            db.execute("UPDATE cloudzy_uo_operations SET version=5 "
                       "WHERE id=?", (C,))
        self.assertEqual(self.open("u7:r:uo:"+C,message_id=123), "SENT")
        self.assertEqual(NoNetworkAPI.calls[-1][0],"EDIT")
        with self.db_conn() as db:
            self.assertEqual(db.execute(
                "SELECT state FROM cloudzy_uo_operations WHERE id=?",
                (C,)).fetchone()[0], "RECONCILE_REQUIRED")

    def test_empty_no_credentials_no_actions(self):
        card=empty_card()
        self.assertTrue(card["is_rtl"])
        self.assertEqual(len(card["blocks"]),3)
        self.assertTrue(all(block.get("type") not in (
            "buttons","thinking") for block in card["blocks"]))
        self.assertEqual(self.open(ENTRY,actor=11,chat=11), "EMPTY")

    def test_business_callback_routes_still_unchanged_in_source(self):
        """Verify Rich branch occurs BEFORE original CZ07 and is read-only."""
        source=(Path(__file__).parent.parent/"bot_final_v49-2.py").read_text()
        entry=source.index('if d == "apps_cz_rich_home" or d.startswith("u7:")')
        existing=source.index('elif d.startswith("apps_cz7_")')
        self.assertLess(entry,existing)
        self.assertIn('await _cloudzy_rich_admin_callback(',source)
        self.assertIn('actor in _cloudzy_rich_admin_ids()',source)
        self.assertIn('_build_admin_programs_kb(actor=actor, chat=chat)',source)
        self.assertNotIn("_cloudzy_07.handle_callback(",source[entry:existing])


if __name__=="__main__":
    unittest.main()
