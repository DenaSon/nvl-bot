"""CZ-03: hermetic purchase/journal/SSH-pin + Legacy adapter tests."""
from contextlib import contextmanager
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
        self.server = {"state": "active", "primaryIpv4": "8.8.8.8",
                       "id": "server-1", "hostname": ""}
        self.keys = []

    def list_regions(self):
        self.calls.append("regions")
        return [{"id": "fra", "name": "Frankfurt"}]

    def list_plans(self, *, region, billing_cycle):
        self.calls.append("plans")
        return {"plans": [{
            "id": "plan-1", "name": "Small", "priceScope": "regional_catalog_base",
            "price": {"amountCents": 250},
        }]}

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

    async def test_crash_during_create_recovers_from_exact_provider_name_without_post(self):
        opid = self.wizard.store.reserve(
            actor=112, chat=334, region="fra", plan="plan-1",
            cycle="monthly", price=250, port=2252, pubkey=self.pub)
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
            actor=112, chat=334, region="fra", plan="plan-1",
            cycle="monthly", price=250, port=2252, pubkey=self.pub)
        self.wizard.store.change(opid, "CREATING", "CREATED",
                                 provider_server_id="server-1")
        self.wizard.store.change(opid, "CREATED", "WAITING")
        await self.cb("apps_cz_operations")
        await self.cb("apps_cz_qcheck_" + opid)
        await self.app.drain()
        self.assertEqual(self.wizard.store.get(opid)["status"], "HOSTKEY_PENDING")
        self.assertEqual(self.api.calls, ["get"])

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
        self.assertEqual(args["billing_cycle"], "monthly")
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
        return self.journal.reserve(actor=1, chat=2, region="fra", plan="plan",
            cycle="monthly", price=350, port=2252, pubkey="ssh-ed25519 AAAA")

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


if __name__ == "__main__":
    unittest.main()
