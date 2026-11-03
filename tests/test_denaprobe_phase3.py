"""R3 Hermetic incident, Rich UX, and alert delivery acceptance tests."""
import asyncio
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from denaprobe_ingest import collector, dpt2, detector
from denaprobe_alerts import tick
from denaprobe_rich_admin import (ENTRY, render_home, render_detail, render_active,
                                  render_history, render_transition, handle_callback)
from cloudzy_rich_transport import RichDeliveryHold

DEVICE = "dp-lab-01"
BOOT = "0123456789abcdef0123456789abcdef"
NOW = 2_000_000_000_000


class FakeRichAPI:
    def __init__(self, token=None, fail=False):
        self.sent = []
        self.edited = []
        self.fail = fail

    async def send(self, *, chat_id, rich_message):
        if self.fail:
            raise RichDeliveryHold("TELEGRAM_DELIVERY_UNCERTAIN")
        self.sent.append((chat_id, rich_message))
        return 1000 + len(self.sent)

    async def edit(self, *, chat_id, message_id, rich_message):
        self.edited.append((chat_id, message_id, rich_message))
        return True


class TestPhase3(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "isolated.sqlite3"
        collector.initialize(self.db)
        dpt2.initialize(self.db)
        collector.register_target(self.db, 1, "relay.test.invalid", 2252)
        self.q = 1
        self.now = NOW
        body = {"v": 2, "id": DEVICE, "b": BOOT, "q": 1,
                "u": 500, "k": 3, "w": 1}
        raw = json.dumps(body, separators=(",", ":")).encode()
        self.assertEqual(dpt2.store(self.db, body, raw, 700,
                                    now_ms=self.now), 0)

    def submit(self, kind, *, direct=True, wifi=1, revision=None):
        del revision
        self.q += 1
        self.now += 30000
        u = self.q * 30000
        body = {
            "v": 2, "id": DEVICE, "b": BOOT, "q": self.q,
            "u": u, "k": 1, "t": 1, "w": wifi,
            "r": -50, "s": 1, "p": 52, "o": 255,
            "d": 12, "x": 3100, "a": 130,
            "c": {"u": u+10, "s": 1, "ms": 125},
        }
        complete = {"s": 1, "r": 16384, "n": 16384, "ms": 500}
        timeout = {"s": 20, "r": 16384, "n": 0, "ms": 10000}
        if kind == "healthy":
            body["z"] = {"u": u+20000, "s": 1, "am": 350, "sm": 18000,
                         "f": complete, "g": complete}
        elif kind == "d0":
            body.update(s=30, p=30, o=0)
            body["c"]["s"] = 20
            body.pop("a")
        elif kind == "d1":
            body["z"] = {"u": u+20000, "s": 20, "am": 350, "sm": 19000,
                         "f": complete, "g": timeout}
        elif kind == "d2":
            body["z"] = {"u": u+20000, "s": 40, "am": 350, "sm": 19000,
                         "f": complete, "g": timeout}
        elif kind == "auth_failure":
            body["z"] = {"u": u+20000, "s": 10, "am": 200}
        elif kind == "preauth":
            pass
        else:
            raise ValueError(kind)
        if wifi == 0:
            # DPT/1 inherited semantics forbid Wi-Fi RSSI when down.
            body.pop("r", None)
        if direct:
            body["h"] = {"u": u+21000, "c": 1, "n": 65536, "bt": 2200}
        signed_uptime = max(u, body.get("h", {}).get("u", 0),
                            body.get("z", {}).get("u", 0)) + 100
        raw = json.dumps(body, separators=(",", ":")).encode()
        result = dpt2.store(self.db, body, raw, signed_uptime,
                            allowed_targets=[1], now_ms=self.now)
        return result

    def evaluate(self, extra=1000):
        return detector.evaluate(self.db, now_ms=self.now+extra)

    def dashboard(self):
        return detector.read_dashboard(self.db, now_ms=self.now+1000)

    def ready(self):
        self.assertEqual(self.submit("healthy"), 0)
        self.assertFalse(self.evaluate())
        self.assertEqual(self.submit("healthy"), 0)
        self.assertFalse(self.evaluate())
        with collector.connect_db(self.db) as db:
            self.assertEqual(db.execute(
                "SELECT monitoring_gap FROM dpt2_latest").fetchone()[0], 0)

    def test_d0_requires_two_distinct_fresh_samples_and_no_duplicates(self):
        self.ready()
        self.assertEqual(self.submit("d0"), 0)
        self.assertFalse(self.evaluate())
        self.assertFalse(self.evaluate())  # same q cannot count twice
        self.assertEqual(self.submit("d0"), 0)
        self.assertEqual(self.evaluate()[0]["kind"], "OPEN")
        self.assertEqual(self.dashboard()["active"][0]["observed_class"], detector.D0)
        self.assertFalse(self.evaluate())
        with collector.connect_db(self.db) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM dp3_transitions").fetchone()[0], 1)

    def test_d1_then_d2_then_recovery_and_no_stale_recovery(self):
        self.ready()
        self.submit("d1"); self.evaluate()
        self.submit("d1"); self.assertEqual(self.evaluate()[0]["kind"], "OPEN")
        self.submit("d2"); self.evaluate()
        self.submit("d2"); self.assertEqual(self.evaluate()[0]["kind"], "CHANGE")
        self.assertEqual(self.dashboard()["active"][0]["observed_class"], detector.D2)
        # Silence is UNKNOWN and must NEVER close an active incident.
        self.assertEqual(self.evaluate(extra=190000), [])
        self.assertEqual(len(self.dashboard()["active"]), 1)
        self.submit("healthy"); self.evaluate()
        self.submit("healthy")
        self.assertEqual(self.evaluate()[0]["kind"], "RECOVERED")
        self.assertFalse(self.dashboard()["active"])
        self.assertEqual(len(self.dashboard()["incidents"]), 1)

    def test_preauth_pass_is_never_full_health_and_wifi_gap_never_alerts(self):
        self.submit("preauth"); self.evaluate()
        self.submit("preauth"); self.evaluate()
        model = self.dashboard()
        self.assertEqual(model["states"][0]["observation"], detector.PREAUTH_REACHABLE)
        self.assertNotEqual(model["states"][0]["effective"], detector.HEALTHY)
        self.assertFalse(model["active"])
        self.submit("d1", wifi=0)
        self.assertFalse(self.evaluate())
        self.assertEqual(self.dashboard()["stale"], 1)

    def test_monitor_only_d0_opens_and_preauth_recovers_with_clear_scope(self):
        # Normal ESP32 DPT2 has c (TCP) and s (preauth) but no z/Deep.
        self.submit("preauth"); self.evaluate()
        self.submit("preauth"); self.evaluate()
        self.assertFalse(self.dashboard()["active"])
        self.submit("d0"); self.evaluate()
        self.submit("d0")
        self.assertEqual(self.evaluate()[0]["kind"], "OPEN")
        incident_id = self.dashboard()["active"][0]["id"]

        self.submit("preauth")
        self.assertFalse(self.evaluate())  # One pass is not recovery.
        self.assertEqual(len(self.dashboard()["active"]), 1)
        self.submit("preauth")
        self.assertEqual(self.evaluate()[0]["kind"], "RECOVERED")
        model = self.dashboard()
        self.assertFalse(model["active"])
        self.assertEqual(model["states"][0]["effective"],
                         detector.PREAUTH_REACHABLE)
        self.assertNotEqual(model["states"][0]["effective"], detector.HEALTHY)
        card = render_transition(
            model, {"incident_id": incident_id, "kind": "RECOVERED",
                    "occurred_at": self.now, "evidence_sequence": self.q,
                    "observed_class": detector.RECOVERED})
        self.assertIn("TCP/SSH اولیه", card["blocks"][0]["text"])
        self.assertIn("سلامت NPV نامشخص", str(card))

    def test_monitor_only_pass_cannot_recover_deep_d1_incident(self):
        self.ready()
        self.submit("d1"); self.evaluate()
        self.submit("d1")
        self.assertEqual(self.evaluate()[0]["kind"], "OPEN")
        self.submit("preauth"); self.assertFalse(self.evaluate())
        self.submit("preauth"); self.assertFalse(self.evaluate())
        model = self.dashboard()
        self.assertEqual(len(model["active"]), 1)
        self.assertEqual(model["active"][0]["observed_class"], detector.D1)
        self.assertIsNone(model["active"][0]["recovered_at"])

    def test_auth_config_and_missing_direct_are_not_filtering(self):
        self.ready()
        self.submit("auth_failure"); self.evaluate()
        self.submit("auth_failure"); self.evaluate()
        self.assertFalse(self.dashboard()["active"])
        # Complete direct control can become stale even if SSH has a new q.
        self.submit("d0", direct=False); self.evaluate(extra=500000)
        self.submit("d0", direct=False); self.evaluate(extra=500000)
        self.assertFalse(self.dashboard()["active"])

    def test_target_revision_change_is_separate(self):
        self.ready()
        self.submit("d0"); self.evaluate()
        self.submit("d0"); self.evaluate()
        collector.register_target(self.db, 1, "another-target.test.invalid", 2252)
        self.submit("healthy"); self.evaluate()
        self.submit("healthy"); self.evaluate()
        model = self.dashboard()
        self.assertTrue(any(x["revision"] == 1 for x in model["incidents"]))
        self.assertTrue(any(x["revision"] == 2 for x in model["states"]))
        # The old incident is not silently marked recovered in revision 2.
        self.assertIsNone(model["incidents"][0]["recovered_at"])

    def test_native_rich_tables_and_persian_contextual_footer(self):
        self.ready()
        self.submit("d0"); self.evaluate()
        self.submit("d0"); self.evaluate()
        model = self.dashboard()
        for card in (render_home(model), render_active(model),
                     render_history(model), render_detail(
                         model, model["incidents"][0]["id"])):
            self.assertTrue(card["is_rtl"])
            self.assertTrue(any(b["type"] == "table" for b in card["blocks"]))
            self.assertTrue(any("💡" in str(b) for b in card["blocks"]))
            self.assertTrue(any(b["type"] == "buttons" for b in card["blocks"]))
            self.assertFalse(any(b.get("type") == "html" for b in card["blocks"]))

    def test_dashboard_live_admin_and_message_origin_guard(self):
        self.ready()
        api = FakeRichAPI()
        ctx = type("Ctx", (), {"bot": type("B", (), {"token":"test-token"})()})()
        query = type("Q", (), {"message": type("M", (), {"message_id":1001})()})()
        async def open_card(data, *, actor=7, chat=7, active=None, private=True):
            return await handle_callback(
                data=data, query=query, context=ctx, db_path=self.db,
                role="admin", actor=actor, chat=chat, is_private=private,
                active_admin_ids={7} if active is None else active,
                api_factory=lambda _: api)
        self.assertEqual(asyncio.run(open_card(ENTRY, actor=9)), "DENIED")
        self.assertEqual(asyncio.run(open_card(ENTRY, private=False)), "DENIED")
        self.assertEqual(asyncio.run(open_card(ENTRY)), "SENT")
        self.assertEqual(asyncio.run(open_card("dp3:home")), "EDITED")
        query.message.message_id = 10
        self.assertEqual(asyncio.run(open_card("dp3:home")), "STALE_OR_FORWARDED_CARD")

    def test_silent_interval_resets_pending_evidence_streak(self):
        self.ready()
        self.submit("d0"); self.evaluate()
        # The old D0 confirmation cannot survive monitoring silence.
        self.assertEqual(self.evaluate(extra=190000), [])
        with collector.connect_db(self.db) as db:
            state = db.execute(
                "SELECT streak,observation FROM dp3_states").fetchone()
            self.assertEqual(tuple(state), (0, detector.UNKNOWN))
        self.submit("d0")
        self.assertFalse(self.evaluate())
        self.submit("d0")
        self.assertEqual(self.evaluate()[0]["kind"], "OPEN")

    def test_skipped_q_cannot_complete_pending_streak(self):
        self.ready()
        self.submit("d0"); self.evaluate()
        self.submit("healthy")  # ingestion succeeded but skipped by classifier
        self.submit("d0")
        self.assertFalse(self.evaluate())
        self.submit("d0")
        self.assertEqual(self.evaluate()[0]["kind"], "OPEN")

    def test_historical_limit_never_hides_old_active_incident(self):
        self.ready()
        active_id = "a"*24
        with collector.connect_db(self.db) as db:
            db.execute(
                "INSERT INTO dp3_incidents(id,device_id,target_id,revision,"
                "observed_class,confidence,reason,opened_at,last_evidence_at,last_sequence) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (active_id,DEVICE,1,1,detector.D0,"SUSPECTED",
                 "TEST_OPEN", NOW-999000,NOW-999000,1))
            for i in range(60):
                db.execute(
                    "INSERT INTO dp3_incidents(id,device_id,target_id,revision,"
                    "observed_class,confidence,reason,opened_at,last_evidence_at,"
                    "last_sequence,recovered_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (f"{i:024x}",DEVICE,1,1,detector.D1,"INCONCLUSIVE",
                     "TEST_RECOVERED",NOW+i,NOW+i,2,NOW+i+1))
        model=self.dashboard()
        self.assertEqual(len(model["active"]), 1)
        self.assertEqual(model["active"][0]["id"], active_id)
        self.assertEqual(render_home(model)["blocks"][1]["text"], "🔴 اختلال احتمالی")

    def test_superseded_target_never_sends_delayed_outage_alert(self):
        self.ready()
        self.submit("d0"); self.evaluate()
        self.submit("d0"); self.evaluate()
        collector.register_target(self.db, 1, "new.target.test.invalid", 2252)
        self.submit("healthy"); self.evaluate()
        self.submit("healthy"); self.evaluate()
        self.assertFalse(self.dashboard()["active"])
        api=FakeRichAPI()
        result=asyncio.run(tick(self.db, [7], api, now_ms=self.now+1000))
        self.assertEqual(result["sent"],0)
        with collector.connect_db(self.db) as db:
            row=db.execute(
                "SELECT superseded_at,recovered_at FROM dp3_incidents"
            ).fetchone()
            self.assertIsNotNone(row[0])
            self.assertIsNone(row[1])

    def test_revoked_admin_never_receives_queued_rich_alert(self):
        self.ready()
        self.submit("d0"); self.evaluate()
        self.submit("d0"); self.evaluate()
        with collector.connect_db(self.db) as db:
            trans = db.execute("SELECT id FROM dp3_transitions").fetchone()[0]
            db.execute(
                "INSERT INTO dp3_delivery(transition_id,recipient_id,status,updated_at)"
                " VALUES(?,9,'READY',?)", (trans,self.now))
        api = FakeRichAPI()
        result=asyncio.run(tick(self.db, [7], api, now_ms=self.now+1000))
        self.assertEqual(result["sent"],1)
        self.assertEqual([x[0] for x in api.sent],[7])
        with collector.connect_db(self.db) as db:
            status=db.execute(
                "SELECT status FROM dp3_delivery WHERE recipient_id=9"
            ).fetchone()[0]
            self.assertEqual(status,"REVOKED")

    def test_outbox_dedup_sent_and_uncertain_no_duplicate_retry(self):
        self.ready()
        self.submit("d0"); self.evaluate()
        self.submit("d0"); self.evaluate()
        api = FakeRichAPI()
        result = asyncio.run(tick(self.db, [7,7,0], api, now_ms=self.now+1000))
        self.assertEqual(result["sent"], 1)
        self.assertEqual(len(api.sent), 1)
        result = asyncio.run(tick(self.db, [7], api, now_ms=self.now+1100))
        self.assertEqual(result["sent"], 0)
        self.submit("healthy"); self.evaluate()
        self.submit("healthy"); self.evaluate()
        bad = FakeRichAPI(fail=True)
        result = asyncio.run(tick(self.db, [7], bad, now_ms=self.now+1000))
        self.assertEqual(result["held"], 1)
        self.assertEqual(asyncio.run(tick(
            self.db, [7], api, now_ms=self.now+1001))["sent"], 0)
        with collector.connect_db(self.db) as db:
            status = db.execute("SELECT status FROM dp3_delivery "
                                "ORDER BY transition_id DESC LIMIT 1").fetchone()[0]
            self.assertEqual(status, "UNCERTAIN")


if __name__ == "__main__":
    unittest.main()
