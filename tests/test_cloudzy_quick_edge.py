"""CZ-03: hermetic purchase/journal/SSH-pin + Legacy adapter tests."""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
import asyncio
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from cloudzy_quick_edge import QuickEdgeHold, QuickEdgeWizard, ReceiptStore, _public_ipv4
from cloudzy_service import CloudzyUncertainError, CloudzyAPIError


class FakeQuery:
    def __init__(self):
        self.screens = []
        self.message = self

    async def edit_message_text(self, text, **kwargs):
        self.screens.append((text, kwargs))

    async def reply_text(self, text, **kwargs):
        self.screens.append((text, kwargs))

    @property
    def callbacks(self):
        markup = self.screens[-1][1].get("reply_markup", [])
        return [c for row in markup for _, c in row]

    @property
    def text(self):
        return self.screens[-1][0]


class FakeStandby:
    def __init__(self):
        self.registered = False
        self.calls = []

    def _state(self, ip, pid, *, mutation):
        self.calls.append("state")
        return {"active": self.registered, "standby": self.registered,
                "default": False, "listed": False, "users": 0, "auto": False,
                "k2_onboard": False, "port": 2252, "admin_port": 22}

    def _isolated(self, state):
        assert state["active"] is False

    async def _provider(self, pid, ip):
        return "active"

    async def probe(self, ip, port, admin_port):
        return True

    def _reserve(self, actor, chat, ip, pid, action):
        self.calls.append("reserve")
        return "standby-operation"

    def _promote(self, opid, ip, pid):
        self.calls.append("promote")
        self.registered = True

    def _finish(self, opid, status, reason):
        self.calls.append("finish")


class FakeContext:
    def __init__(self):
        self.user_data = {}


class FakeBot:
    def __init__(self):
        self.messages = []

    async def send_message(self, chat, text, **kw):
        self.messages.append((chat, text, kw))


class FakeApp:
    def __init__(self):
        self.bot = FakeBot()
        self.tasks = []

    def create_task(self, coro):
        self.tasks.append(asyncio.create_task(coro))

    async def drain(self):
        jobs, self.tasks = self.tasks, []
        if jobs:
            await asyncio.gather(*jobs)


class FakeCloudzy:
    def __init__(self):
        self.calls = []
        self.fail_create = None
        self.available = True
        self.frankfurt_available = True
        self.amsterdam_available = True
        self.server = {"state": "active", "primaryIpv4": "8.8.8.8",
                       "id": "server-1", "hostname": ""}
        self.keys = []

    def list_regions(self):
        self.calls.append("regions")
        return [
            {"id": "NL-Amsterdam-DC2", "name": "Amsterdam", "isActive": True, "isHidden": False, "isOutOfStock": False},
            {"id": "DE-Frankfurt", "name": "Frankfurt", "isActive": True, "isHidden": False, "isOutOfStock": False}
        ]

    def list_plans(self, *, region, billing_cycle):
        self.calls.append("plans")
        return {"region": region, "billingCycle": billing_cycle, "plans": [{
            "id": "plan-1", "name": "VPS 1 GB", "slug": "vps-1gb",
            "instanceType": "default", "priceScope": "regional_catalog_base",
            "price": {"regionId": region, "billingCycle": "hourly",
                      "amount": 1, "monthlyEquivCents": 695, "currency": "USD"},
        }]}

    def list_plan_availability(self, region):
        self.calls.append("availability")
        available = (self.available and
                     (self.frankfurt_available if region == "DE-Frankfurt" else self.amsterdam_available))
        return {"region": region, "checkedAt": datetime.now(timezone.utc).isoformat(),
                "plans": [{"planId": "plan-1", "slug": "vps-1gb",
                           "available": available, "source": "live",
                           "fitsOnNodes": 2 if available else 0}]}

    def create_server(self, **kw):
        self.calls.append(("create", kw))
        if self.fail_create is not None:
            raise self.fail_create
        self.server["hostname"] = kw["hostname"]
        return {"data": {"id": "server-1"}}

    def wait_for_ready(self, server_id, *, timeout, interval):
        self.calls.append("wait")
        return self.server

    def get_server(self, server_id):
        self.calls.append("get")
        return self.server

    def list_servers(self):
        self.calls.append("list")
        return [self.server]

    def list_ssh_keys(self):
        self.calls.append("keys")
        return list(self.keys)

    def add_ssh_key(self, name, public_key):
        self.calls.append(("add_key", name, public_key))
        self.keys.append({"id": "key1", "publicKey": public_key})
        return {"id": "key1"}


def markup(rows):
    for row in rows:
        for _, cb in row:
            assert len(cb.encode()) <= 64, cb
    return rows


class CZ03Tests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "quick.sqlite"
        self.now = [1000.0]
        self.ctx = FakeContext()
        self.query = FakeQuery()
        self.app = FakeApp()
        self.api = FakeCloudzy()
        self.provisions = []
        self.verifications = []
        self.preflight_calls = []
        self.pub = "ssh-ed25519 AAAAxpublickey nvledge"
        self.fingerprint = ["ssh-ed25519", "AAAAPINNEDPUBLIC", "SHA256:trustedtest"]
        self.gate = True
        self.wizard = QuickEdgeWizard(
            conn_factory=self.db,
            preflight=self._preflight,
            provision=self._provision,
            verify=self._verify,
            cloudzy_factory=lambda: self.api,
            fingerprint=self._fingerprint,
            now=lambda: self.now[0],
        )

    @contextmanager
    def db(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _preflight(self):
        self.preflight_calls.append(True)
        if not self.gate:
            raise QuickEdgeHold("PROTECTED_LEGACY")
        return 2252, self.pub

    def _fingerprint(self, ip):
        assert ip == "8.8.8.8"
        return tuple(self.fingerprint)

    async def _provision(self, *args):
        self.provisions.append(args)
        return True, "8.8.8.8", {"tunnel_ok": True}

    async def _verify(self, *args):
        self.verifications.append(args)
        return True

    async def cb(self, data, *, role="admin", actor=112, chat=334):
        await self.wizard.handle_callback(
            self.query, self.ctx, data,
            role=role, actor=actor, chat=chat, app=self.app, markup=markup)

    async def start_selection(self):
        await self.cb("apps_cz_wizard")
        reg = next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_"))
        await self.cb(reg)
        plan = next(x for x in self.query.callbacks if x.startswith("apps_cz_qp_"))
        await self.cb(plan)
        return next(x for x in self.query.callbacks if x.startswith("apps_cz_qbuy_"))

    async def purchase(self):
        confirmation = await self.start_selection()
        await self.cb(confirmation)
        await self.app.drain()
        return self.wizard.store.latest()

    async def test_auto_skips_unavailable_frankfurt_and_picks_amsterdam(self):
        self.api.frankfurt_available = False
        await self.cb("apps_cz_wizard")
        await self.cb("apps_cz_qauto")
        self.assertEqual(self.ctx.user_data["cz3"]["region"], "NL-Amsterdam-DC2")
        self.assertTrue(any(x.startswith("apps_cz_qp_") for x in self.query.callbacks))
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create" for x in self.api.calls))

    async def test_no_stock_blocks_manual_plan_and_never_creates(self):
        self.api.available = False
        await self.cb("apps_cz_wizard")
        reg = next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_"))
        await self.cb(reg)
        self.assertFalse(any(x.startswith("apps_cz_qp_") for x in self.query.callbacks))
        await self.cb("apps_cz_qauto")
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create" for x in self.api.calls))

    async def test_old_monthly_callback_rejected(self):
        await self.cb("apps_cz_wizard")
        await self.cb("apps_cz_qcy_monthly")
        self.assertIn("INVALID_CYCLE_OR_REGION", self.query.text)
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create" for x in self.api.calls))

    async def test_stock_disappears_at_confirmation_without_charge(self):
        confirm = await self.start_selection()
        self.api.available = False
        await self.cb(confirm)
        self.assertIsNone(self.wizard.store.latest())
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create" for x in self.api.calls))

    async def test_stock_disappears_after_reservation_before_provider_post(self):
        confirm = await self.start_selection()
        original = self.wizard._launch
        def change_stock_before_task(app, opid, task):
            self.api.available = False
            return original(app, opid, task)
        self.wizard._launch = change_stock_before_task
        await self.cb(confirm)
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "REJECTED")
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create" for x in self.api.calls))

    async def test_cz06_disabled_by_default_does_not_purchase(self):
        self.wizard.cz06_enabled = lambda: False
        self.wizard.standby_service = FakeStandby()
        await self.cb("apps_cz6_start")
        self.assertIn("CZ06_DISABLED", self.query.text)
        self.assertEqual(self.api.calls, [])
        self.assertIsNone(self.wizard.store.latest())

    async def test_cz06_quick_relay_from_one_purchase_to_standby(self):
        standby = FakeStandby()
        self.wizard.standby_service = standby
        self.wizard.cz06_enabled = lambda: True
        await self.cb("apps_cz6_start")
        self.assertIn("Quick Relay", self.query.text)
        region = next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_"))
        await self.cb(region)
        plan = next(x for x in self.query.callbacks if x.startswith("apps_cz_qp_"))
        await self.cb(plan)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qbuy_"))
        await self.cb(confirm)
        await self.app.drain()
        record = self.wizard.store.latest()
        self.assertEqual(record["status"], "HOSTKEY_PENDING")
        self.assertEqual(self.wizard.quick_runs.get(record["id"])["stage"], "HOSTKEY_PENDING")
        self.assertEqual(standby.calls, [])
        await self.cb("apps_cz_operations")
        review = next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_"))
        await self.cb(review)
        accept = next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_"))
        await self.cb(accept)
        await self.app.drain()
        run = self.wizard.quick_runs.get(record["id"])
        self.assertEqual(run["stage"], "READY")
        self.assertEqual(standby.calls.count("promote"), 1)
        self.assertEqual(record["billing_cycle"], "hourly")
        self.assertEqual(len(self.provisions), 1)
        self.assertEqual(len([x for x in self.api.calls if isinstance(x, tuple) and x[0] == "create"]), 1)

    async def test_cz06_standby_failure_enters_hold_without_rebuy(self):
        class FailingStandby(FakeStandby):
            async def probe(self, *args):
                return False

        standby = FailingStandby()
        self.wizard.standby_service = standby
        self.wizard.cz06_enabled = lambda: True
        await self.cb("apps_cz6_start")
        region = next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_"))
        await self.cb(region)
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qp_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qbuy_")))
        await self.app.drain()
        record = self.wizard.store.latest()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(record["id"])["status"], "EDGE_READY")
        self.assertEqual(self.wizard.quick_runs.get(record["id"])["stage"], "HOLD")
        self.assertEqual(standby.calls.count("promote"), 0)
        await self.cb("apps_cz_operations")
        self.assertFalse(any(x.startswith("apps_cz6_resume_") for x in self.query.callbacks))
        self.assertEqual(len([x for x in self.api.calls if isinstance(x, tuple) and x[0] == "create"]), 1)

    async def test_explicit_monthly_reservation_is_rejected(self):
        with self.assertRaises(QuickEdgeHold):
            self.wizard.store.reserve(actor=112, chat=334, region="DE-Frankfurt",
                plan="plan-1", cycle="monthly", price=100, port=2252, pubkey=self.pub)

    async def test_crash_during_create_recovers_from_exact_provider_name_without_post(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.api.server["hostname"] = self.wizard.store.get(opid)["hostname"]
        await self.cb("apps_cz_operations")
        self.assertIn("apps_cz_qcheck_" + opid, self.query.callbacks)
        await self.cb("apps_cz_qcheck_" + opid)
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(opid)["status"], "HOSTKEY_PENDING")
        self.assertNotIn("wait", self.api.calls)
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "create" for c in self.api.calls))

    async def test_crash_during_wait_recovers_without_new_order(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.change(opid, "CREATING", "CREATED",
                                 provider_server_id="server-1")
        self.wizard.store.change(opid, "CREATED", "WAITING")
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qcheck_" + opid)
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(opid)["status"], "HOSTKEY_PENDING")
        self.assertEqual(self.api.calls, ["get"])

    async def test_install_failure_logs_precise_safe_stage_without_rebuy(self):
        async def failed(*args):
            self.provisions.append(args)
            return False, None, None
        self.wizard.provision = failed
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        with self.assertLogs("cloudzy_quick_edge", level="ERROR") as logged:
            await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
            await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(len(self.provisions), 1)
        joined = "\n".join(logged.output)
        self.assertIn("stage=LEGACY_PROVISION", joined)
        self.assertIn("code=LEGACY_PROVISION_OR_WG_TUNNEL_NOT_VERIFIED", joined)
        self.assertNotIn(self.pub, joined)
        self.assertEqual(len([x for x in self.api.calls if isinstance(x, tuple) and x[0] == "create"]), 1)

    async def test_postcheck_rejection_never_reports_edge_ready(self):
        async def rejected(*args):
            self.verifications.append(args)
            return False
        self.wizard.verify = rejected
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(len(self.provisions), 1)

    async def test_unauthorized_or_initial_navigation_never_purchases(self):
        await self.cb("apps_cz_wizard", role="agent")
        self.assertEqual(self.api.calls, [])
        self.assertIn("فقط مدیر", self.query.text)
        await self.cb("apps_cz_wizard")
        self.assertIn("ساخت سریع Edge", self.query.text)
        self.assertNotIn("create", self.api.calls)
        self.assertIsNone(self.wizard.store.latest())
        self.assertGreaterEqual(len(self.preflight_calls), 1)

    async def test_confirm_is_one_shot_and_durable_before_charge(self):
        confirmation = await self.start_selection()
        self.assertIsNone(self.wizard.store.latest())
        await self.cb(confirmation)
        await self.cb(confirmation)
        await self.app.drain()
        purchase_calls = [x for x in self.api.calls if isinstance(x, tuple) and x[0] == "create"]
        self.assertEqual(len(purchase_calls), 1)
        args = purchase_calls[0][1]
        self.assertTrue(args["confirm"])
        self.assertEqual(args["os_template_id"], "ubuntu-24.04")
        self.assertEqual(args["billing_cycle"], "hourly")
        self.assertEqual(args["ssh_public_keys"], [self.pub])
        self.assertEqual(args["ip_version"], "ipv4")
        record = self.wizard.store.latest()
        self.assertEqual(record["status"], "HOSTKEY_PENDING")
        self.assertEqual(record["provider_server_id"], "server-1")
        self.assertEqual(record["public_ipv4"], "8.8.8.8")
        self.assertEqual(args["idempotency_key"], record["idempotency_key"])
        self.assertEqual(record["public_key_sha"].__len__(), 64)
        self.assertEqual(self.provisions, [])

    async def test_reviewed_pinned_key_reuses_inactive_legacy_install(self):
        record = await self.purchase()
        await self.cb("apps_cz_operations")
        self.assertIn("HOSTKEY_PENDING", self.query.text)
        review = next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_"))
        await self.cb(review)
        accept = next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_"))
        await self.cb(accept)
        await self.app.drain()
        record = self.wizard.store.latest()
        self.assertEqual(record["status"], "EDGE_READY")
        self.assertEqual(len(self.provisions), 1)
        ip, port, hostname, chat, app, server_id, pinned = self.provisions[0]
        self.assertEqual((ip, port, chat, server_id), ("8.8.8.8", 2252, 334, "server-1"))
        self.assertEqual(pinned, tuple(self.fingerprint[:2]))
        self.assertEqual(self.verifications, [("8.8.8.8", 2252, "server-1")])
        self.assertTrue(hostname.startswith("nvl-edge-"))
        await self.cb(accept)
        self.assertEqual(len(self.provisions), 1)

    async def test_definite_4xx_rejects_without_permanent_purchase_lock(self):
        self.api.fail_create = CloudzyAPIError(402, "private provider rejection")
        record = await self.purchase()
        self.assertEqual(record["status"], "REJECTED")
        self.assertNotIn("private provider rejection", str(self.app.bot.messages))
        self.api.fail_create = None
        await self.cb("apps_cz_wizard")
        self.assertTrue(any(x.startswith("apps_cz_qr_") for x in self.query.callbacks))
        self.assertEqual(len([x for x in self.api.calls
                              if isinstance(x, tuple) and x[0] == "create"]), 1)

    async def test_unknown_create_is_held_and_reconciled_only_by_read(self):
        self.api.fail_create = CloudzyUncertainError("POST /services", idempotency_key="same")
        record = await self.purchase()
        self.assertEqual(record["status"], "CREATE_UNCERTAIN")
        await self.cb("apps_cz_wizard")
        self.assertIn("CREATE_UNCERTAIN", self.query.text)
        self.api.fail_create = None
        await self.cb("apps_cz_operations")
        retry_read = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcheck_"))
        await self.cb(retry_read)
        await self.app.drain()
        purchase_calls = [x for x in self.api.calls if isinstance(x, tuple) and x[0] == "create"]
        self.assertEqual(len(purchase_calls), 1)
        self.assertEqual(self.wizard.store.latest()["status"], "CREATE_UNCERTAIN")

    async def test_host_key_changed_never_executes_legacy_install(self):
        record = await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        self.fingerprint[1] = "different"
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.provisions, [])
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")

    async def test_preflight_gate_refuses_buy_before_journal(self):
        confirm = await self.start_selection()
        self.gate = False
        await self.cb(confirm)
        self.assertIsNone(self.wizard.store.latest())
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create" for x in self.api.calls))

    async def test_owner_and_ttl_limit_confirm(self):
        c = await self.start_selection()
        await self.cb(c, actor=999)
        self.assertIsNone(self.wizard.store.latest())
        self.now[0] += 601
        await self.cb(c)
        self.assertIsNone(self.wizard.store.latest())

    async def test_public_key_register_requires_separate_operator_confirmation(self):
        await self.cb("apps_cz_qsavekey")
        self.assertFalse(any(isinstance(x, tuple) for x in self.api.calls))
        cb = next(x for x in self.query.callbacks if x.startswith("apps_cz_qkeyyes_"))
        await self.cb(cb, actor=999)
        self.assertFalse(any(isinstance(x, tuple) for x in self.api.calls))
        await self.cb(cb)
        self.assertEqual([x[0] for x in self.api.calls if isinstance(x, tuple)], ["add_key"])
        await self.cb(cb)
        self.assertEqual([x[0] for x in self.api.calls if isinstance(x, tuple)], ["add_key"])


    def prepare_cancel_guards(self):
        # Simulate an unchanged Core route; cancelled Edge is not registered.
        with self.db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS host_pool "
                       "(host TEXT,provider TEXT,provider_instance_id TEXT)")
            db.execute("CREATE TABLE IF NOT EXISTS settings "
                       "(key TEXT PRIMARY KEY,value TEXT)")
            db.executemany("INSERT OR REPLACE INTO settings VALUES(?,?)", [
                ("hosts", "1.1.1.1"), ("dns_current_ip", "1.1.1.1"),
                ("core_wg_public_ip", "2.2.2.2"),
            ])

    async def test_failed_cz06_cancel_releases_both_journals_without_provider_write(self):
        self.wizard.standby_service = FakeStandby()
        self.wizard.cz06_enabled = lambda: True

        async def fail_install(*args):
            self.provisions.append(args)
            return False, None, None
        self.wizard.provision = fail_install
        await self.cb("apps_cz6_start")
        region = next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_"))
        await self.cb(region)
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qp_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qbuy_")))
        await self.app.drain()
        op = self.wizard.store.latest()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOLD_PROVISION")
        self.assertEqual(self.wizard.quick_runs.get(op["id"])["stage"], "HOLD")
        self.prepare_cancel_guards()
        before = list(self.api.calls)
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qcancel_" + op["id"])
        self.assertIn("تأیید لغو", self.query.text)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(confirm)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "CANCELLED")
        self.assertEqual(self.wizard.quick_runs.get(op["id"])["stage"], "CANCELLED")
        self.assertEqual(self.api.calls, before)
        with self.db() as db:
            event = db.execute(
                "SELECT actor_id,chat_id,previous_status,previous_reason "
                "FROM cloudzy_edge_cancel_events WHERE operation_id=?", (op["id"],)
            ).fetchone()
        self.assertEqual(event, (112, 334, "HOLD_PROVISION",
                                 "PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL"))
        await self.cb(confirm)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "CANCELLED")
        await self.cb("apps_cz6_start")
        self.assertTrue(any(x.startswith("apps_cz_qr_") for x in self.query.callbacks))
        # Both partial unique indexes allow a NEW reservation, with no paid POST.
        self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub,
            quick_relay=True)
        self.assertEqual(
            len([x for x in self.api.calls if isinstance(x, tuple) and x[0] == "create"]), 1
        )

    async def test_cancel_fails_closed_for_running_or_registered_edge(self):
        op = await self.purchase()
        self.prepare_cancel_guards()
        self.wizard.store.change(op["id"], "HOSTKEY_PENDING", "HOLD_PROVISION",
                                 hold_reason="INSTALL_UNVERIFIED")
        self.wizard._running.add(op["id"])
        await self.cb("apps_cz_operations")
        self.assertFalse(any(x.startswith("apps_cz_qcancel_") for x in self.query.callbacks))
        await self.cb("apps_cz_qcancel_" + op["id"])
        self.assertIn("CANCEL_NOT_ALLOWED_OR_RUNNING", self.query.text)
        self.wizard._running.discard(op["id"])
        with self.db() as db:
            db.execute("INSERT INTO host_pool VALUES (?,?,?)",
                       ("8.8.8.8", "cloudzy", "server-1"))
        await self.cb("apps_cz_qcancel_" + op["id"])
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(confirm)
        self.assertIn("CANCEL_HOST_REGISTERED", self.query.text)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOLD_PROVISION")
        with self.db() as db:
            count = db.execute("SELECT COUNT(*) FROM cloudzy_edge_cancel_events").fetchone()[0]
        self.assertEqual(count, 0)

    async def test_cancel_disallowed_during_uncertain_purchase_and_nonadmin(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.change(opid, "CREATING", "CREATE_UNCERTAIN")
        await self.cb("apps_cz_operations")
        self.assertFalse(any(x.startswith("apps_cz_qcancel_") for x in self.query.callbacks))
        await self.cb("apps_cz_qcancel_" + opid)
        self.assertIn("CANCEL_NOT_ALLOWED_OR_RUNNING", self.query.text)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CREATE_UNCERTAIN")
        self.prepare_cancel_guards()
        with self.assertRaises(QuickEdgeHold):
            self.wizard.store.cancel(opid, actor=112, chat=334,
                                     expected_status="CREATE_UNCERTAIN")
        await self.cb("apps_cz_qcancel_" + opid, role="agent")
        self.assertIn("فقط مدیر", self.query.text)

    async def test_cancel_route_guard_and_stale_confirm(self):
        op = await self.purchase()
        self.prepare_cancel_guards()
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qcancel_" + op["id"])
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        self.now[0] += 181
        await self.cb(confirm)
        self.assertIn("CANCEL_CONFIRMATION_EXPIRED", self.query.text)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOSTKEY_PENDING")
        with self.db() as db:
            db.execute("UPDATE settings SET value='8.8.8.8' WHERE key='dns_current_ip'")
        await self.cb("apps_cz_qcancel_" + op["id"])
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(confirm)
        self.assertIn("CANCEL_ROUTE_REFERENCES_TARGET", self.query.text)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOSTKEY_PENDING")


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dbpath = Path(self.temp.name) / "receipt.sqlite"
        @contextmanager
        def db():
            conn = sqlite3.connect(self.dbpath)
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        self.journal = ReceiptStore(db, now=lambda: 1234)

    def reserve(self):
        return self.journal.reserve(actor=1, chat=2, region="DE-Frankfurt", plan="plan",
            cycle="hourly", price=350, port=2252, pubkey="ssh-ed25519 AAAA")

    def test_stable_unique_and_recoverable_without_recharging(self):
        opid = self.reserve()
        row = self.journal.get(opid)
        self.assertEqual(row["status"], "CREATING")
        self.assertEqual(row["idempotency_key"], "nvl-cz03-" + opid)
        with self.assertRaises(QuickEdgeHold):
            self.reserve()
        self.journal.change(opid, "CREATING", "CREATE_UNCERTAIN", hold_reason="UNCERTAIN")
        with self.assertRaises(QuickEdgeHold):
            self.reserve()
        with self.assertRaises(QuickEdgeHold):
            self.journal.change(opid, "CREATING", "CREATED")
        self.assertEqual(self.journal.get(opid)["status"], "CREATE_UNCERTAIN")

    def test_only_globally_routable_ip_is_accepted(self):
        self.assertEqual(_public_ipv4({"data": {"primaryIpv4": "8.8.4.4"}}), "8.8.4.4")
        for value in ("10.0.0.5", "127.0.0.1", "192.168.1.1", "2001:db8::2", ""):
            with self.subTest(value=value), self.assertRaises(QuickEdgeHold):
                _public_ipv4({"ipAddress": value})

    def test_legacy_endpoints_and_k2_are_untouched(self):
        source = (Path(__file__).resolve().parents[1] / "bot_final_v49-2.py").read_text()
        for old in ('elif d in ("hp_addedge", "hpeg_wizard")',
                    'elif d.startswith("srv_mkactive_")',
                    'elif d.startswith("hpdefmig_yes_")',
                    'elif d == "hpeg_status"'):
            self.assertIn(old, source)
        self.assertIn("pool_active=False", source)
        self.assertIn('trusted_host_key=trusted_host_key', source)
        self.assertIn('paramiko.RejectPolicy()', source)
        self.assertIn('legacy_peer_name = "edge-" + ip.replace(".", "-")', source)


if __name__ == "__main__":
    unittest.main()
