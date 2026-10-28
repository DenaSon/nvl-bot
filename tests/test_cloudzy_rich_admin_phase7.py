"""Offline, read-only and fake-Telegram Phase-7 Rich admin regressions."""
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
import asyncio
import json
import sqlite3
import unittest

from cloudzy_rich_admin import (
    read_operation, render_card, parse_callback, RichViewHold,
)
from cloudzy_rich_transport import (
    RichBotAPI, RichDeliveryHold, DurableRichDelivery,
)

OP = "a" * 32


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.fail = False

    async def send(self, **kwargs):
        self.calls.append(("send", kwargs))
        if self.fail:
            raise RichDeliveryHold("TELEGRAM_DELIVERY_UNCERTAIN")
        return 909

    async def edit(self, **kwargs):
        self.calls.append(("edit", kwargs))
        if self.fail:
            raise RichDeliveryHold("TELEGRAM_MESSAGE_UNAVAILABLE")
        return True


class RichPhase7Tests(unittest.TestCase):
    def setUp(self):
        tmp = TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "rich.db"

        @contextmanager
        def factory():
            db = sqlite3.connect(str(path))
            try:
                yield db
                db.commit()
            except Exception:
                db.rollback()
                raise
            finally:
                db.close()

        self.factory = factory
        with factory() as db:
            db.executescript("""
                CREATE TABLE cloudzy_cz07_jobs (
                  id TEXT PRIMARY KEY, actor INTEGER, chat INTEGER,
                  status TEXT, code TEXT, source TEXT, target TEXT,
                  moved INTEGER, total INTEGER
                );
                CREATE TABLE cloudzy_cz07_events (
                  seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT,
                  stage TEXT, code TEXT
                );
                CREATE TABLE cloudzy_uo_operations (
                  id TEXT PRIMARY KEY, actor INTEGER, chat INTEGER,
                  step TEXT, state TEXT, code TEXT, version INTEGER
                );
            """)
            db.execute(
                "INSERT INTO cloudzy_cz07_jobs VALUES (?,?,?,?,?,?,?,?,?)",
                (OP, 7, 8, "VERIFYING", "AWAITING_BUSINESS_E2E",
                 "10.0.0.1", "10.0.0.2", 488, 488)
            )
            db.execute(
                "INSERT INTO cloudzy_cz07_events(job_id,stage,code) "
                "VALUES (?,?,?)", (OP, "VERIFYING", "AWAITING_BUSINESS_E2E")
            )
            db.execute(
                "INSERT INTO cloudzy_uo_operations VALUES (?,?,?,?,?,?,?)",
                ("b"*32, 7, 8, "DNS_CUTOVER", "RECONCILE_REQUIRED",
                 "DNS_OR_DEFAULT_UNCERTAIN_LOCK_HELD", 4)
            )

    def view(self):
        with self.factory() as db:
            return read_operation(db, kind="CZ07", operation_id=OP,
                                  actor=7, chat=8)

    def test_cz07_is_select_only_and_owner_bound(self):
        with self.factory() as db:
            db.execute("PRAGMA query_only=ON")
            view = read_operation(db, kind="CZ07", operation_id=OP,
                                  actor=7, chat=8)
        self.assertEqual((view.stage, view.total, view.moved), (7, 488, 488))
        with self.assertRaisesRegex(RichViewHold, "OPERATION_OWNER_MISMATCH"):
            with self.factory() as db:
                read_operation(db, kind="CZ07", operation_id=OP,
                               actor=9, chat=8)
        with self.assertRaisesRegex(RichViewHold, "OPERATION_OWNER_MISMATCH"):
            with self.factory() as db:
                read_operation(db, kind="CZ07", operation_id=OP,
                               actor=7, chat=9)

    def test_rich_blocks_only_no_false_success_and_read_only_actions(self):
        result = render_card(self.view(), details=True)
        self.assertEqual(result["is_rtl"], True)
        self.assertNotIn("html", result)
        self.assertNotIn("markdown", result)
        self.assertTrue(any(block["type"] == "table"
                            and block.get("is_compact") is True
                            for block in result["blocks"]))
        details = [b for b in result["blocks"] if b["type"] == "details"]
        self.assertEqual(len(details), 1)
        self.assertTrue(details[0]["is_open"])
        self.assertTrue(any("ساخت" in b["text"] for b in details[0]["blocks"]
                            if isinstance(b.get("text"), str)))
        buttons = [b for b in result["blocks"] if b["type"] == "buttons"]
        self.assertEqual(len(buttons), 1)
        self.assertEqual(len(buttons[0]["buttons"]), 2)
        for b in buttons[0]["buttons"]:
            self.assertLessEqual(len(b["callback_data"].encode()), 64)
            kind, ref, action = parse_callback(b["callback_data"])
            self.assertEqual((kind, ref), ("CZ07", OP))
            self.assertIn(action, ("r", "d"))
        self.assertFalse(any("✅" in b.get("text", "")
                             for b in result["blocks"]
                             if b["type"] == "paragraph"
                             and isinstance(b.get("text"), str)))
        self.assertIn("blocks", json.loads(json.dumps(result, ensure_ascii=False)))

    def test_unknown_error_is_non_assumptive_and_not_raw(self):
        view = self.view()
        from dataclasses import replace
        payload = render_card(replace(
            view, code="PASSWORD_AND_TOKEN_IN_LOG_NOT_APPROVED"))
        details = [b for b in payload["blocks"] if b["type"] == "details"][0]
        joined = "|".join(b["text"] for b in details["blocks"])
        self.assertIn("RECONCILE_FIRST", joined)
        self.assertNotIn("Cloudzy outage", joined)

    def test_uo_read_only_has_no_invented_customer_progress(self):
        with self.factory() as db:
            view = read_operation(
                db, kind="UO", operation_id="b"*32, actor=7, chat=8)
        payload = render_card(view)
        self.assertEqual(view.stage, 5)
        self.assertIsNone(view.total)
        self.assertEqual(view.version, 4)
        table = next(b for b in payload["blocks"] if b["type"] == "table")
        self.assertTrue(any(
            "آمار تأیید نشده" in cell["text"] for row in table["cells"]
            for cell in row
        ))

    def test_callback_rejects_mutation_and_overlong_values(self):
        with self.assertRaisesRegex(RichViewHold, "CALLBACK_INVALID"):
            parse_callback("u7:x:cz07:" + OP)
        with self.assertRaisesRegex(RichViewHold, "CALLBACK_INVALID"):
            parse_callback("u7:r:cz07:" + "a"*64)
        with self.assertRaisesRegex(RichViewHold, "INVALID_OPERATION_IDENTITY"):
            with self.factory() as db:
                read_operation(db, kind="CZ07", operation_id="123", actor=7, chat=8)

    def test_transport_uses_real_rich_methods_no_html_fallback(self):
        calls = []
        def fake_post(method, payload):
            calls.append((method, payload))
            return {"message_id": 909}
        client = RichBotAPI("fake-test-token", transport=fake_post)
        rich = render_card(self.view())
        sent = asyncio.run(client.send(chat_id=8, rich_message=rich))
        edited = asyncio.run(client.edit(
            chat_id=8, message_id=909, rich_message=rich))
        self.assertEqual(sent, 909)
        self.assertTrue(edited)
        self.assertEqual([name for name, payload in calls],
                         ["sendRichMessage", "editMessageText"])
        for name, payload in calls:
            self.assertIn("rich_message", payload)
            self.assertNotIn("text", payload)
            self.assertEqual(payload["rich_message"]["is_rtl"], True)

    def test_durable_send_edit_and_version_deduplication(self):
        api = FakeAPI()
        delivery = DurableRichDelivery(db_conn=self.factory, api=api,
                                       now=lambda: 100)
        self.assertEqual(asyncio.run(delivery.render_once(
            kind="CZ07", operation_id=OP, actor=7, chat=8)), "SENT")
        self.assertEqual(asyncio.run(delivery.render_once(
            kind="CZ07", operation_id=OP, actor=7, chat=8)), "UNCHANGED")
        self.assertEqual(asyncio.run(delivery.render_once(
            kind="CZ07", operation_id=OP, actor=7, chat=8,
            details=True)), "SENT")
        with self.factory() as db:
            db.execute("INSERT INTO cloudzy_cz07_events(job_id,stage,code) "
                       "VALUES (?,?,?)", (OP, "VERIFYING", "NEW_EVENT"))
        self.assertEqual(asyncio.run(delivery.render_once(
            kind="CZ07", operation_id=OP, actor=7, chat=8,
            details=True)), "SENT")
        self.assertEqual([c[0] for c in api.calls], ["send", "edit", "edit"])
        with self.factory() as db:
            self.assertEqual(db.execute(
                "SELECT message_id,delivered_version FROM "
                "cloudzy_rich_message_pointers").fetchone(), (909, 2))
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_rich_delivery_outbox "
                "WHERE status != 'SENT'").fetchone()[0], 0)

    def test_uncertain_delivery_is_not_replayed_or_business_failure(self):
        api = FakeAPI()
        api.fail = True
        delivery = DurableRichDelivery(db_conn=self.factory, api=api,
                                       now=lambda: 100)
        with self.assertRaisesRegex(RichDeliveryHold, "TELEGRAM_DELIVERY_UNCERTAIN"):
            asyncio.run(delivery.render_once(
                kind="CZ07", operation_id=OP, actor=7, chat=8))
        api.fail = False
        with self.assertRaisesRegex(RichDeliveryHold,
                                    "PRIOR_TELEGRAM_DELIVERY_UNCERTAIN"):
            asyncio.run(delivery.render_once(
                kind="CZ07", operation_id=OP, actor=7, chat=8))
        self.assertEqual(len(api.calls), 1)
        self.assertEqual(len(delivery.pending(
            kind="CZ07", operation_id=OP, chat=8)), 1)
        self.assertEqual(self.view().state, "VERIFYING")

    def test_crash_after_intent_does_not_duplicate_send(self):
        api = FakeAPI()
        delivery = DurableRichDelivery(db_conn=self.factory, api=api,
                                       now=lambda: 100)
        intent = delivery._intent(self.view(), details=False)
        self.assertEqual(intent[1], "SEND")
        # Simulated crash before HTTP return or SQLite ACK.
        restarted = DurableRichDelivery(db_conn=self.factory, api=api,
                                        now=lambda: 120)
        with self.assertRaisesRegex(RichDeliveryHold,
                                    "PRIOR_TELEGRAM_DELIVERY_UNCERTAIN"):
            asyncio.run(restarted.render_once(
                kind="CZ07", operation_id=OP, actor=7, chat=8))
        self.assertEqual(api.calls, [])


if __name__ == "__main__":
    unittest.main()
