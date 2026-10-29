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

    async def edit_message_text(self, **kw):
        if not hasattr(self, "edits"):
            self.edits = []
        self.edits.append(kw)


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
        with sqlite3.connect(self.path) as db:
            db.execute("CREATE TABLE host_pool (host TEXT PRIMARY KEY, "
                       "active INTEGER,is_default INTEGER,is_standby INTEGER,"
                       "provider TEXT,provider_instance_id TEXT)")
            db.execute("CREATE TABLE ssh_accounts "
                       "(host TEXT,status TEXT,service_type TEXT)")
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

    async def test_transient_cloudzy_read_error_is_friendly_and_safe_to_retry(self):
        from cloudzy_service import CloudzyError
        def interrupted_regions():
            raise CloudzyError("Cloudzy read request failed: TimeoutError PRIVATE")
        self.api.list_regions = interrupted_regions
        await self.cb("apps_cz_wizard")
        self.assertIn("چند ثانیه بعد دوباره تلاش کنید", self.query.text)
        self.assertIn("هیچ خریدی انجام نشده است", self.query.text)
        self.assertNotIn("CloudzyError", self.query.text)
        self.assertNotIn("PRIVATE", self.query.text)
        self.assertIn("پیگیری: CZ05-", self.query.text)
        self.assertIsNone(self.wizard.store.latest())
        self.assertFalse(any(isinstance(c, tuple) and c[0] == "create"
                             for c in self.api.calls))

    async def test_region_page_transient_get_failure_is_friendly(self):
        from cloudzy_service import CloudzyError
        await self.cb("apps_cz_wizard")
        region = next(cb for cb in self.query.callbacks if cb.startswith("apps_cz_qr_"))
        self.api.list_plan_availability = lambda x: (_ for _ in ()).throw(
            CloudzyError("Cloudzy returned invalid JSON PRIVATE"))
        await self.cb(region)
        self.assertIn("چند ثانیه بعد دوباره تلاش کنید", self.query.text)
        self.assertNotIn("CloudzyError", self.query.text)
        self.assertNotIn("PRIVATE", self.query.text)
        self.assertIsNone(self.wizard.store.latest())

    async def test_read_http_429_503_are_friendly_and_401_is_not_retryable(self):
        for status, expected in (
                (429, "کمی بعد"),
                (503, "چند ثانیه بعد"),
                (401, "اعتبار توکن")):
            with self.subTest(status=status):
                def failed_regions():
                    raise CloudzyAPIError(status, "provider PRIVATE data", "secret-code")
                self.api.list_regions = failed_regions
                await self.cb("apps_cz_wizard")
                self.assertIn(expected, self.query.text)
                self.assertNotIn("PRIVATE", self.query.text)
                self.assertNotIn("secret-code", self.query.text)
                self.assertNotIn("CloudzyAPIError", self.query.text)
                if status == 401:
                    self.assertNotIn("دوباره تلاش کنید", self.query.text)
                self.assertIsNone(self.wizard.store.latest())

    async def test_mutating_callback_never_suggests_blind_retry(self):
        from cloudzy_service import CloudzyError
        await self.cb("apps_cz_qsavekey")
        callback = next(cb for cb in self.query.callbacks if cb.startswith("apps_cz_qkeyyes_"))
        def failed_add(*args):
            raise CloudzyError("PRIVATE write failure")
        self.api.add_ssh_key = failed_add
        await self.cb(callback)
        self.assertIn("وضعیت عملیات را بررسی کنید", self.query.text)
        self.assertIn("درخواست را تکرار نکنید", self.query.text)
        self.assertNotIn("چند ثانیه بعد", self.query.text)
        self.assertNotIn("PRIVATE", self.query.text)
        self.assertEqual(self.api.calls.count("keys"), 1)

    async def test_uncertain_provider_write_still_requires_reconciliation(self):
        await self.cb("apps_cz_qsavekey")
        cb = next(c for c in self.query.callbacks if c.startswith("apps_cz_qkeyyes_"))
        self.api.add_ssh_key = lambda *args: (_ for _ in ()).throw(
            CloudzyUncertainError("POST /ssh-keys", idempotency_key="PRIVATE"))
        await self.cb(cb)
        self.assertIn("خرید را تکرار نکنید", self.query.text)
        self.assertIn("نتیجه درخواست Cloudzy نامشخص است", self.query.text)
        self.assertNotIn("چند ثانیه بعد", self.query.text)
        self.assertNotIn("PRIVATE", self.query.text)

    async def test_cz06_disabled_by_default_does_not_purchase(self):
        self.wizard.cz06_enabled = lambda: False
        self.wizard.standby_service = FakeStandby()
        await self.cb("apps_cz6_start")
        self.assertIn("CZ06_DISABLED", self.query.text)
        self.assertEqual(self.api.calls, [])
        self.assertIsNone(self.wizard.store.latest())

    async def test_cz06_quick_relay_from_one_purchase_to_standby(self):
        # Production callbacks have a Telegram message ID; this mock defaults
        # to None, which deliberately skips background progress delivery.
        self.query.message_id = 123
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
        # The hermetic CI intentionally omits python-telegram-bot. Supply its
        # two formatting primitives locally to exercise real background markup.
        from types import SimpleNamespace
        from unittest.mock import patch
        telegram_stub = SimpleNamespace(
            InlineKeyboardButton=lambda text, callback_data: SimpleNamespace(
                text=text, callback_data=callback_data),
            InlineKeyboardMarkup=lambda rows: SimpleNamespace(inline_keyboard=rows),
        )
        with patch.dict("sys.modules", {"telegram": telegram_stub}):
            await self.cb(accept)
            await self.app.drain()
        run = self.wizard.quick_runs.get(record["id"])
        self.assertEqual(run["stage"], "READY")
        # Background CZ06 progress updates retain the operation-status button.
        self.assertTrue(self.app.bot.edits)
        last = self.app.bot.edits[-1]
        self.assertIn("READY", last["text"])
        self.assertEqual(
            last["reply_markup"].inline_keyboard[0][0].callback_data,
            "apps_cz_operations",
        )
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

    async def test_apt_lock_failure_has_explicit_hold_without_reinstall(self):
        async def busy_apt(*args):
            self.provisions.append(args)
            return False, None, {"error_code": "APT_LOCK_BUSY"}
        self.wizard.provision = busy_apt
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        receipt = self.wizard.store.latest()
        self.assertEqual(receipt["status"], "HOLD_PROVISION")
        self.assertEqual(receipt["hold_reason"], "EDGE_APT_LOCK_BUSY")
        self.assertEqual(len(self.provisions), 1)
        self.assertTrue(any("APT" in text and "تکرار نکنید" in text
                            for _, text, _ in self.app.bot.messages))
        self.assertEqual(len([x for x in self.api.calls
                              if isinstance(x, tuple) and x[0] == "create"]), 1)

    async def test_phase2_recovery_uses_existing_vps_without_new_install(self):
        async def failed(*args):
            self.provisions.append(args)
            return False, None, None
        self.wizard.provision = failed
        self.wizard.standby_service = FakeStandby()
        await self.purchase()
        op = self.wizard.store.latest()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOLD_PROVISION")
        self.prepare_cancel_guards()
        with self.db() as db:
            db.execute("ALTER TABLE host_pool ADD COLUMN service_port INTEGER")
            db.execute("ALTER TABLE host_pool ADD COLUMN admin_ssh_port INTEGER")
            db.execute("INSERT INTO host_pool VALUES "
                       "('8.8.8.8',0,0,0,'cloudzy','server-1',2252,22)")

        await self.cb("apps_cz_operations")
        recover = "apps_cz_qrecover_" + op["id"]
        self.assertIn(recover, self.query.callbacks)
        await self.cb(recover)
        self.assertIn("apps_cz_qrinstalled_" + op["id"], self.query.callbacks)
        self.assertEqual(len(self.provisions), 1)
        await self.cb("apps_cz_qrinstalled_" + op["id"])
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qryes_"))
        await self.cb(confirm)
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "EDGE_READY")
        self.assertEqual(len(self.provisions), 1)
        self.assertEqual(len([x for x in self.api.calls
                              if isinstance(x, tuple) and x[0] == "create"]), 1)
        self.assertEqual(self.wizard.quick_runs.get(op["id"]), None)
        await self.cb(confirm)
        self.assertEqual(len(self.provisions), 1)

    async def test_phase2_no_existing_install_evidence_fails_closed(self):
        async def failed(*args):
            self.provisions.append(args)
            return False, None, None
        self.wizard.provision = failed
        await self.purchase()
        op = self.wizard.store.latest()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        await self.cb("apps_cz_qrecover_" + op["id"])
        self.assertIn("apps_cz_servers_0", self.query.callbacks)
        self.assertNotIn("apps_cz_qrinstalled_" + op["id"], self.query.callbacks)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOLD_PROVISION")
        self.assertEqual(len(self.provisions), 1)

    async def test_phase2_standby_hold_reopens_once_after_confirmation(self):
        class OnceBadStandby(FakeStandby):
            def __init__(self):
                super().__init__()
                self.fail = True
            async def probe(self, *args):
                return not self.fail

        standby = OnceBadStandby()
        self.wizard.standby_service = standby
        self.wizard.cz06_enabled = lambda: True
        await self.cb("apps_cz6_start")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qp_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qbuy_")))
        await self.app.drain()
        op = self.wizard.store.latest()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.quick_runs.get(op["id"])["stage"], "HOLD")
        standby.fail = False
        await self.cb("apps_cz_qrecover_" + op["id"])
        self.assertIn("apps_cz_qrstandby_" + op["id"], self.query.callbacks)
        await self.cb("apps_cz_qrstandby_" + op["id"])
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qryes_"))
        await self.cb(confirm)
        await self.app.drain()
        self.assertEqual(self.wizard.quick_runs.get(op["id"])["stage"], "READY")
        self.assertEqual(standby.calls.count("promote"), 1)
        self.assertEqual(len(self.provisions), 1)
        await self.cb(confirm)
        self.assertEqual(standby.calls.count("promote"), 1)

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

    async def test_p4_provider_id_drift_prevents_legacy_install(self):
        await self.purchase()
        op = self.wizard.store.latest()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        self.api.server["id"] = "replaced-vps"
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(self.provisions, [])
        self.assertEqual(self.verifications, [])
        self.assertTrue(any("INSTALL_PROVIDER_ID_CHANGED" in x
                            for _, x, _ in self.app.bot.messages))

    async def test_p4_provider_ipv4_reuse_prevents_legacy_install(self):
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        self.api.server["primaryIpv4"] = "9.9.9.9"
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(self.provisions, [])

    async def test_p4_provider_name_drift_prevents_legacy_install(self):
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        self.api.server["hostname"] = "someone-elses-vps"
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(self.provisions, [])

    async def test_p4_provider_drift_after_installer_never_accepts_receipt(self):
        async def changes_ownership_after_legacy(*args):
            self.provisions.append(args)
            self.api.server["id"] = "new-owner-vps"
            return True, "8.8.8.8", {"tunnel_ok": True}
        self.wizard.provision = changes_ownership_after_legacy
        await self.purchase()
        op = self.wizard.store.latest()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(len(self.provisions), 1)
        self.assertEqual(len(self.verifications), 1)
        self.assertNotIn("EDGE_READY", self.wizard.store.latest()["status"])
        # Bot never repeats the effects of setup_edge_relay.sh after HOLD.
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qrecover_" + op["id"])
        self.assertEqual(len(self.provisions), 1)

    async def test_p4_host_key_changes_after_install_must_hold_receipt(self):
        async def mutates_key(*args):
            self.provisions.append(args)
            self.fingerprint[1] = "DIFFERENT-AFTER-INSTALL"
            return True, "8.8.8.8", {"tunnel_ok": True}
        self.wizard.provision = mutates_key
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(len(self.provisions), 1)
        self.assertTrue(any("HOST_KEY_CHANGED_AFTER_INSTALL" in t
                            for _, t, _ in self.app.bot.messages))

    async def test_p4_core_key_changes_after_install_must_hold_receipt(self):
        async def changes_core_key(*args):
            self.provisions.append(args)
            self.pub = "ssh-ed25519 AAAAChangedUserKey"
            return True, "8.8.8.8", {"tunnel_ok": True}
        self.wizard.provision = changes_core_key
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.store.latest()["status"], "HOLD_PROVISION")
        self.assertEqual(len(self.provisions), 1)
        self.assertTrue(any("CORE_IDENTITY_CHANGED_AFTER_INSTALL" in t
                            for _, t, _ in self.app.bot.messages))

    async def test_p4_apt_lock_does_not_retry_or_accept(self):
        async def apt_lock(*args):
            self.provisions.append(args)
            return False, None, {"error_code": "APT_LOCK_BUSY"}
        self.wizard.provision = apt_lock
        await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(len(self.provisions), 1)
        self.assertEqual(self.wizard.store.latest()["hold_reason"], "EDGE_APT_LOCK_BUSY")

    async def test_reviewed_pinned_key_reuses_inactive_legacy_install(self):
        record = await self.purchase()
        await self.cb("apps_cz_operations")
        self.assertIn("منتظر تأیید اثرانگشت SSH", self.query.text)
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

    async def test_manual_edge_ready_shows_manual_standby_not_automatic_cz07(self):
        op = await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        await self.cb("apps_cz_operations")
        self.assertIn("مسیر دستی", self.query.text)
        self.assertIn("apps_cz4_vps", self.query.callbacks)
        self.assertIn("apps_cz5_home", self.query.callbacks)
        self.assertNotIn("apps_cz7_home", self.query.callbacks)
        self.assertIn("apps_cz_qdetails_" + op["id"], self.query.callbacks)
        await self.cb("apps_cz_qdetails_" + op["id"])
        self.assertIn("Receipt:", self.query.text)
        self.assertIn("EDGE_READY", self.query.text)
        self.assertIn("apps_cz_qview_" + op["id"], self.query.callbacks)
        await self.cb("apps_cz_qdetails_" + op["id"], actor=998)
        self.assertIn("OPERATION_OWNER_MISMATCH", self.query.text)

    async def test_cz06_standby_hold_has_safe_manual_navigation_not_retry(self):
        class FailingStandby(FakeStandby):
            async def probe(self, *args):
                return False

        self.wizard.standby_service = FailingStandby()
        self.wizard.cz06_enabled = lambda: True
        await self.cb("apps_cz6_start")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qp_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qbuy_")))
        await self.app.drain()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.wizard.quick_runs.get(self.wizard.store.latest()["id"])["stage"], "HOLD")
        await self.cb("apps_cz_operations")
        self.assertIn("✅ نصب و بررسی Edge", self.query.text)
        self.assertIn("⚠️ فعال‌سازی Standby", self.query.text)
        self.assertIn("apps_cz4_vps", self.query.callbacks)
        self.assertIn("apps_cz5_home", self.query.callbacks)
        self.assertNotIn("apps_cz7_home", self.query.callbacks)
        self.assertFalse(any(x.startswith("apps_cz6_resume_") for x in self.query.callbacks))

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
        self.assertIn("نتیجه خرید VPS نامشخص است", self.query.text)
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
                       "(host TEXT,active INTEGER,is_default INTEGER,is_standby INTEGER,"
                       "provider TEXT,provider_instance_id TEXT)")
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
            db.execute("INSERT INTO host_pool VALUES (?,?,?,?,?,?)",
                       ("8.8.8.8", 0, 0, 0, "cloudzy", "server-1"))
        await self.cb("apps_cz_qcancel_" + op["id"])
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(confirm)
        self.assertIn("CANCEL_HOST_REGISTERED", self.query.text)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOLD_PROVISION")
        with self.db() as db:
            count = db.execute("SELECT COUNT(*) FROM cloudzy_edge_cancel_events").fetchone()[0]
        self.assertEqual(count, 0)

    async def test_recycled_old_ip_with_detached_host_can_be_cancelled(self):
        # Regression for 144.172.119.6: old Relay is inactive, has no
        # provider owner and no active SSH, but still has historic accounts.
        self.prepare_cancel_guards()
        with self.db() as db:
            db.execute("INSERT INTO host_pool VALUES (?,?,?,?,?,?)",
                       ("8.8.8.8", 0, 0, 0, None, None))
            db.executemany("INSERT INTO ssh_accounts VALUES (?,?,?)", [
                ("8.8.8.8", "🔴 غیرفعال", "ssh"),
                ("8.8.8.8", "🟢 فعال", "v2ray"),
                ("8.8.8.8", "🟢 فعال", "v2ray_vol"),
            ])
        op = await self.purchase()
        await self.cb("apps_cz_operations")
        await self.cb(next(x for x in self.query.callbacks
                           if x.startswith("apps_cz_qreview_")))
        await self.cb(next(x for x in self.query.callbacks
                           if x.startswith("apps_cz_qaccept_")))
        await self.app.drain()
        self.assertEqual(self.provisions, [])  # no remote/WG changes
        blocked = self.wizard.store.get(op["id"])
        self.assertEqual(blocked["status"], "HOLD_PROVISION")
        self.assertEqual(blocked["hold_reason"], "CLOUDZY_IP_ALREADY_REGISTERED")
        self.assertEqual(self.wizard.quick_runs.get(op["id"]), None)
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qcancel_" + op["id"])
        yes = next(x for x in self.query.callbacks
                   if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(yes)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "CANCELLED")
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT active,is_default,is_standby,provider,provider_instance_id "
                "FROM host_pool WHERE host='8.8.8.8'").fetchone(),
                (0, 0, 0, None, None))
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM ssh_accounts WHERE host='8.8.8.8'"
            ).fetchone()[0], 3)
        self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt",
            plan="plan-1", cycle="hourly", price=1,
            port=2252, pubkey=self.pub)

    async def test_recycled_ip_rejects_active_ssh_or_unknown_account(self):
        self.prepare_cancel_guards()
        op = await self.purchase()
        self.wizard.store.change(
            op["id"], "HOSTKEY_PENDING", "HOLD_PROVISION",
            hold_reason="PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL")
        with self.db() as db:
            db.execute("INSERT INTO host_pool VALUES (?,?,?,?,?,?)",
                       ("8.8.8.8", 0, 0, 0, None, None))
            db.execute("INSERT INTO ssh_accounts VALUES (?,?,?)",
                       ("8.8.8.8", "🟢 فعال", "ssh"))
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qcancel_" + op["id"])
        yes = next(x for x in self.query.callbacks
                   if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(yes)
        self.assertIn("CANCEL_ACTIVE_SSH_ACCOUNTS_ATTACHED", self.query.text)
        with self.db() as db:
            db.execute("UPDATE ssh_accounts SET service_type=NULL")
        await self.cb("apps_cz_qcancel_" + op["id"])
        yes = next(x for x in self.query.callbacks
                   if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(yes)
        self.assertIn("CANCEL_ACTIVE_SSH_ACCOUNTS_ATTACHED", self.query.text)
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOLD_PROVISION")

    async def test_recycled_ip_rejects_provider_owned_or_live_host(self):
        self.prepare_cancel_guards()
        op = await self.purchase()
        self.wizard.store.change(
            op["id"], "HOSTKEY_PENDING", "HOLD_PROVISION",
            hold_reason="PARTIAL_OR_UNVERIFIED_LEGACY_INSTALL")
        for values in [
            (1, 0, 0, None, None),
            (0, 1, 0, None, None),
            (0, 0, 1, None, None),
            (0, 0, 0, "cloudzy", "server-1"),
            (0, 0, 0, "cloudzy", "another-server"),
        ]:
            with self.subTest(values=values):
                with self.db() as db:
                    db.execute("DELETE FROM host_pool")
                    db.execute("INSERT INTO host_pool VALUES (?,?,?,?,?,?)",
                               ("8.8.8.8", *values))
                with self.assertRaisesRegex(QuickEdgeHold, "CANCEL_HOST_REGISTERED"):
                    self.wizard.store.cancel(
                        op["id"], actor=112, chat=334,
                        expected_status="HOLD_PROVISION")
        self.assertEqual(self.wizard.store.get(op["id"])["status"], "HOLD_PROVISION")

    async def test_refresh_identical_telegram_message_is_not_cloudzy_error(self):
        class BadRequest(Exception):
            pass

        original = self.query.edit_message_text
        async def unchanged(_text, **_kw):
            raise BadRequest("Message is not modified: content and markup identical")
        self.query.edit_message_text = unchanged
        try:
            await self.cb("apps_cz_operations")
        finally:
            self.query.edit_message_text = original
        self.assertFalse(any("خطای غیرمنتظره" in text
                             for text, _kw in self.query.screens))

    async def test_uncertain_purchase_quarantine_is_owner_confirmed_and_audited(self):
        self.wizard.standby_service = FakeStandby()
        self.wizard.cz06_enabled = lambda: True
        self.api.fail_create = CloudzyUncertainError("POST /services", idempotency_key="same")
        await self.cb("apps_cz6_start")
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qr_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qp_")))
        await self.cb(next(x for x in self.query.callbacks if x.startswith("apps_cz_qbuy_")))
        await self.app.drain()
        op = self.wizard.store.latest()
        opid = op["id"]
        self.assertEqual(op["status"], "CREATE_UNCERTAIN")
        self.prepare_cancel_guards()
        await self.cb("apps_cz_operations")
        self.assertTrue(any(x.startswith("apps_cz_qcancel_") for x in self.query.callbacks))
        before_create = len([x for x in self.api.calls
                             if isinstance(x, tuple) and x[0] == "create"])
        await self.cb("apps_cz_qcancel_" + opid, role="agent")
        self.assertIn("فقط مدیر", self.query.text)
        with self.assertRaisesRegex(QuickEdgeHold, "UNCERTAIN_CREATE_REQUIRES"):
            self.wizard.store.cancel(opid, actor=112, chat=334,
                                     expected_status="CREATE_UNCERTAIN")
        await self.cb("apps_cz_qcancel_" + opid)
        self.assertIn("لغو محلی بدون تماس با Cloudzy", self.query.text)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(confirm)
        self.assertIn("UNCERTAIN_CREATE_SETTLEMENT_GRACE", self.query.text)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CREATE_UNCERTAIN")
        self.now[0] += 121
        await self.cb(confirm)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CANCELLED")
        self.assertEqual(self.wizard.quick_runs.get(opid)["stage"], "CANCELLED")
        self.assertEqual(
            len([x for x in self.api.calls
                 if isinstance(x, tuple) and x[0] == "create"]), before_create)
        with self.db() as db:
            quarantine = db.execute(
                "SELECT disposition,provider_observation FROM cloudzy_purchase_quarantine "
                "WHERE operation_id=?", (opid,)).fetchone()
            uo = db.execute(
                "SELECT state,code,external_intent FROM cloudzy_uo_operations WHERE id=?",
                (opid,)).fetchone()
            cancel_events = db.execute(
                "SELECT COUNT(*) FROM cloudzy_edge_cancel_events WHERE operation_id=?",
                (opid,)).fetchone()[0]
        self.assertEqual(quarantine,
                         ("PENDING_PROVIDER_RECONCILIATION", "NOT_CHECKED"))
        self.assertEqual(uo, ("RECONCILE_REQUIRED",
                              "PROVIDER_PURCHASE_QUARANTINED", 1))
        self.assertEqual(cancel_events, 1)
        await self.cb("apps_cz6_start")
        self.assertTrue(any(x.startswith("apps_cz_qr_") for x in self.query.callbacks))

    async def test_quarantine_with_provider_api_unavailable_is_explicit_not_automatic(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.mark_paid_intent(opid)
        self.wizard.store.change(opid, "CREATING", "CREATE_UNCERTAIN")
        self.prepare_cancel_guards()
        def down():
            raise CloudzyUncertainError("GET list")
        self.api.list_servers = down
        self.now[0] += 125
        await self.cb("apps_cz_operations")
        self.assertEqual(self.wizard.store.latest()["status"], "CREATE_UNCERTAIN")
        await self.cb("apps_cz_qcancel_" + opid)
        self.assertIn("لغو محلی بدون تماس با Cloudzy", self.query.text)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(confirm)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CANCELLED")
        with self.db() as db:
            q = db.execute(
                "SELECT provider_observation FROM cloudzy_purchase_quarantine"
            ).fetchone()[0]
        self.assertEqual(q, "NOT_CHECKED")

    async def test_uncertain_purchase_local_close_does_not_consult_live_provider(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.mark_paid_intent(opid)
        self.wizard.store.change(opid, "CREATING", "CREATE_UNCERTAIN")
        self.prepare_cancel_guards()
        self.now[0] += 125
        # Even a VPS visible at Cloudzy cannot silently block LOCAL withdrawal;
        # any VPS remains billable and explicitly quarantined.
        self.api.server["hostname"] = "nvl-edge-" + opid[:12]
        before = list(self.api.calls)
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qcancel_" + opid)
        self.assertIn("لغو محلی بدون تماس با Cloudzy", self.query.text)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(confirm)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CANCELLED")
        self.assertEqual(self.api.calls, before)
        with self.db() as db:
            row = db.execute(
                "SELECT provider_observation,disposition FROM cloudzy_purchase_quarantine"
            ).fetchone()
        self.assertEqual(
            row, ("NOT_CHECKED", "PENDING_PROVIDER_RECONCILIATION"))

    async def test_uncertain_cancel_nonce_survives_bot_context_reset(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.mark_paid_intent(opid)
        self.wizard.store.change(opid, "CREATING", "CREATE_UNCERTAIN")
        self.prepare_cancel_guards()
        self.now[0] += 125
        await self.cb("apps_cz_qcancel_" + opid)
        confirm = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        self.ctx.user_data.clear()   # Simulate restart / lost in-memory PTB session.
        await self.cb(confirm)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CANCELLED")
        with self.db() as db:
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM cloudzy_edge_cancel_intents").fetchone()[0], 0)
        await self.cb(confirm)
        self.assertIn("CANCEL_CONFIRMATION_EXPIRED", self.query.text)

    async def test_uncertain_cancel_requires_current_nonce_and_expires_safely(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.mark_paid_intent(opid)
        self.wizard.store.change(opid, "CREATING", "CREATE_UNCERTAIN")
        self.prepare_cancel_guards()
        self.now[0] += 125
        await self.cb("apps_cz_qcancel_" + opid)
        first = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb("apps_cz_qcancel_" + opid)
        second = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(first)
        self.assertIn("CANCEL_CONFIRMATION_EXPIRED", self.query.text)
        self.now[0] += 901
        await self.cb(second)
        self.assertIn("CANCEL_CONFIRMATION_EXPIRED", self.query.text)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CREATE_UNCERTAIN")
        await self.cb("apps_cz_qcancel_" + opid)
        new = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        await self.cb(new)
        self.assertEqual(self.wizard.store.get(opid)["status"], "CANCELLED")

    async def test_quarantine_rejects_identity_route_and_stale_owner(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.mark_paid_intent(opid)
        self.wizard.store.change(opid, "CREATING", "CREATE_UNCERTAIN")
        self.prepare_cancel_guards()
        self.now[0] += 125
        await self.cb("apps_cz_qcancel_" + opid)
        intent = next(x for x in self.query.callbacks if x.startswith("apps_cz_qcancelyes_"))
        with self.assertRaisesRegex(QuickEdgeHold, "CANCEL_OWNER_MISMATCH"):
            self.wizard.store.cancel(opid, actor=999, chat=999,
                                     expected_status="CREATE_UNCERTAIN",
                                     uncertain_ack=True, provider_observation="NOT_CHECKED",
                                     confirmation_nonce=intent.split("_")[-1])
        await self.cb("apps_cz_qcancel_" + opid, actor=999, chat=999)
        self.assertIn("CANCEL_OWNER_MISMATCH", self.query.text)
        # The old generic cancellation API must reject a missing explicit ACK.
        with self.assertRaisesRegex(QuickEdgeHold, "UNCERTAIN_CREATE_REQUIRES"):
            self.wizard.store.cancel(opid, actor=112, chat=334,
                                     expected_status="CREATE_UNCERTAIN")
        self.wizard.store.change(opid, "CREATE_UNCERTAIN", "CREATE_UNCERTAIN",
                                 provider_server_id="server-1")
        with self.assertRaisesRegex(QuickEdgeHold, "HAS_PROVIDER_IDENTITY"):
            self.wizard.store.cancel(opid, actor=112, chat=334,
                                     expected_status="CREATE_UNCERTAIN",
                                     uncertain_ack=True, provider_observation="NOT_CHECKED",
                                     confirmation_nonce=intent.split("_")[-1])

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


    async def test_p3_provider_get_401_after_reservation_has_distinct_reason(self):
        confirm = await self.start_selection()
        original = self.wizard._launch
        def switch_to_unauthorized_get(app, opid, task):
            def forbidden(region):
                raise CloudzyAPIError(401, "private provider payload")
            self.api.list_plan_availability = forbidden
            return original(app, opid, task)
        self.wizard._launch = switch_to_unauthorized_get
        await self.cb(confirm)
        await self.app.drain()
        op = self.wizard.store.latest()
        self.assertEqual(op["status"], "REJECTED")
        self.assertEqual(op["hold_reason"], "CLOUDZY_PREFLIGHT_HTTP_401")
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create"
                             for x in self.api.calls))
        self.assertTrue(any("دسترسی" in text and "401" in text
                            for _, text, _ in self.app.bot.messages))

    async def test_p3_get_timeout_is_bounded_and_never_repeats_paid_post(self):
        from cloudzy_service import CloudzyError
        confirm = await self.start_selection()
        original = self.wizard._launch
        attempts = []
        def switch_to_network_failure(app, opid, task):
            def unavailable(region):
                attempts.append(region)
                raise CloudzyError("read timeout private secret")
            self.api.list_plan_availability = unavailable
            return original(app, opid, task)
        self.wizard._launch = switch_to_network_failure
        await self.cb(confirm)
        await self.app.drain()
        op = self.wizard.store.latest()
        self.assertEqual(op["hold_reason"], "CLOUDZY_PREFLIGHT_READ_FAILED")
        self.assertEqual(op["status"], "REJECTED")
        self.assertEqual(len(attempts), 2)
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create"
                             for x in self.api.calls))
        self.assertNotIn("secret", str(self.app.bot.messages))

    async def test_p3_hourly_base_ceiling_blocks_before_reservation(self):
        from unittest.mock import patch
        confirm = await self.start_selection()
        with patch.dict("os.environ", {"NVL_CLOUDZY_MAX_BASE_HOURLY_CENTS": "0"}):
            await self.cb(confirm)
        self.assertIsNone(self.wizard.store.latest())
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create"
                             for x in self.api.calls))

    async def test_p3_duplicate_provider_hostname_cannot_reconcile(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="DE-Frankfurt", plan="plan-1",
            cycle="hourly", price=1, port=2252, pubkey=self.pub)
        self.wizard.store.change(
            opid, "CREATING", "CREATE_UNCERTAIN",
            hold_reason="CREATE_RESULT_UNCERTAIN")
        self.api.server["hostname"] = self.wizard.store.get(opid)["hostname"]
        self.api.list_servers = lambda: [dict(self.api.server), dict(self.api.server)]
        await self.cb("apps_cz_qcheck_" + opid)
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(opid)["status"], "CREATE_UNCERTAIN")
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create"
                             for x in self.api.calls))

    async def test_p3_failed_preflight_telegram_delivery_does_not_create(self):
        confirm = await self.start_selection()
        original = self.wizard._launch
        def switch_to_unauthorized_get(app, opid, task):
            self.api.list_plan_availability = lambda region: (_ for _ in ()).throw(
                CloudzyAPIError(403, "unauthorized"))
            return original(app, opid, task)
        self.wizard._launch = switch_to_unauthorized_get
        async def delivery_failure(*args, **kwargs):
            raise TimeoutError("telegram timeout")
        self.app.bot.send_message = delivery_failure
        await self.cb(confirm)
        await self.app.drain()
        op = self.wizard.store.latest()
        self.assertEqual(op["status"], "REJECTED")
        self.assertEqual(op["hold_reason"], "CLOUDZY_PREFLIGHT_HTTP_403")
        self.assertFalse(any(isinstance(x, tuple) and x[0] == "create"
                             for x in self.api.calls))


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
                    'elif d.startswith(("hpdef_migrate_", "hpdefmig_yes_", "hpdef_"))',
                    'elif d == "hpeg_status"'):
            self.assertIn(old, source)
        self.assertIn("pool_active=False", source)
        self.assertIn('trusted_host_key=trusted_host_key', source)
        self.assertIn('paramiko.RejectPolicy()', source)
        self.assertIn('legacy_peer_name = "edge-" + ip.replace(".", "-")', source)


if __name__ == "__main__":
    unittest.main()
