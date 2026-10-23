"""CZ-02 phase 1 tests: offline fake API, fake Telegram, zero VPS changes."""
import asyncio
import base64
from pathlib import Path
import unittest

from cloudzy_admin_panel import CloudzyAdminPanel, _public_key


def fake_public_key():
    body = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + b"x" * 32
    return "ssh-ed25519 " + base64.b64encode(body).decode("ascii") + " demo"


class FakeMessage:
    def __init__(self):
        self.sent = []

    async def reply_text(self, text, **kwargs):
        self.sent.append((text, kwargs))


class FakeQuery:
    def __init__(self):
        self.message = FakeMessage()
        self.edits = []

    async def edit_message_text(self, text, **kwargs):
        self.edits.append((text, kwargs))

    @property
    def text(self):
        return self.edits[-1][0]

    @property
    def callbacks(self):
        return [value for row in self.edits[-1][1]["reply_markup"]
                for _, value in row]


class Context:
    def __init__(self):
        self.user_data = {}


class FakeCloudzy:
    def __init__(self):
        self.calls = []
        self.keys = [{"id": "k1", "name": "owner"},
                     {"id": "k2", "name": "operator"}]

    def _called(self, name, *args):
        self.calls.append((name, args))

    def list_servers(self):
        self._called("list_servers")
        return {"data": [
            {"id": "srv" + str(i), "hostname": "node" + str(i),
             "credentials": "MUST_NOT_PERSIST"} for i in range(8)
        ]}

    def get_server(self, key):
        self._called("get_server", key)
        return {"data": {"id": key, "hostname": "node & <test>",
                         "state": "active", "primaryIpv4": "203.0.113.2"}}

    def get_server_status(self, key):
        self._called("get_server_status", key)
        return {"data": {"state": "active"}}

    def get_server_usage(self, key):
        self._called("get_server_usage", key)
        return {"data": {"cpuPercent": 27, "memoryUsage": "12 MB"}}

    def list_regions(self):
        self._called("list_regions")
        return {"data": [{"id": "fra", "name": "Frankfurt"},
                         {"id": "sgp", "name": "Singapore"}]}

    def list_plans(self, **kwargs):
        self._called("list_plans", kwargs["region"], kwargs["billing_cycle"])
        return {"plans": [
            {"id": "p1", "name": "<small>", "price": {
                "monthlyEquivCents": 1700, "regionId": "fra"}},
            {"id": "p2", "slug": "medium", "price": None},
        ]}

    def whoami(self):
        self._called("whoami")
        return {"data": {"name": "Admin", "email": "admin@example.org", "id": "42"}}

    def get_balance(self):
        self._called("get_balance")
        return {"data": {"balanceCents": 2134, "currency": "USD"}}

    def list_ssh_keys(self):
        self._called("list_ssh_keys")
        return {"data": list(self.keys)}

    def add_ssh_key(self, name, key):
        self._called("add_ssh_key", name, key)
        self.keys.append({"id": "newkey", "name": name})
        return {"id": "newkey"}

    def delete_ssh_key(self, key_id, *, confirm):
        self._called("delete_ssh_key", key_id, confirm)
        self.keys = [k for k in self.keys if k["id"] != key_id]

    # Mutating VPS operations must NEVER be requested in phase 1.
    def create_server(self, *args, **kwargs):
        raise AssertionError("phase 1 must not purchase VPS")

    def delete_server(self, *args, **kwargs):
        raise AssertionError("phase 1 must not delete VPS")

    def power_on(self, *args, **kwargs):
        raise AssertionError("phase 1 must not power VPS")

    def power_off(self, *args, **kwargs):
        raise AssertionError("phase 1 must not power VPS")

    def restart_server(self, *args, **kwargs):
        raise AssertionError("phase 1 must not restart VPS")


def markup(rows):
    for row in rows:
        for _, callback in row:
            if not isinstance(callback, str) or len(callback.encode("utf-8")) > 64:
                raise AssertionError("oversized/invalid Telegram callback")
    return rows


class Phase1PanelTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.api = FakeCloudzy()
        self.panel = CloudzyAdminPanel(factory=lambda: self.api, now=lambda: self.now[0])
        self.context = Context()
        self.query = FakeQuery()

    def cb(self, data, *, role="admin", actor=123, chat=345):
        asyncio.run(self.panel.handle_callback(
            self.query, self.context, data, role=role,
            actor=actor, chat=chat, markup=markup,
        ))

    def inp(self, text, *, role="admin", actor=123, chat=345):
        message = FakeMessage()
        outcome = asyncio.run(self.panel.handle_text(
            message, self.context, text, role=role,
            actor=actor, chat=chat, markup=markup,
        ))
        return outcome, message

    def test_hub_has_real_entries_but_no_mutating_vps_action(self):
        self.cb("apps_cz_home")
        self.assertIn("مدیریت Cloudzy", self.query.text)
        self.assertIn("apps_cz_servers_0", self.query.callbacks)
        self.assertIn("apps_cz_regions_0", self.query.callbacks)
        self.assertIn("apps_cz_keys_0", self.query.callbacks)
        self.assertNotIn("hpeg_status", self.query.callbacks)
        self.assertEqual(self.api.calls, [])
        self.cb("apps_cz_wizard")
        self.assertIn("فاز ۲", self.query.text)
        self.assertEqual(self.api.calls, [])

    def test_pages_and_server_details_status_usage_and_escaping(self):
        self.cb("apps_cz_servers_0")
        self.assertIn("8", self.query.text)
        self.assertIn("apps_cz_servers_1", self.query.callbacks)
        self.assertEqual(len(self.context.user_data["cz_refs"]["items"]), 6)
        self.assertNotIn("MUST_NOT_PERSIST", str(self.context.user_data))
        token = next(x[len("apps_cz_sv_"):] for x in self.query.callbacks
                     if x.startswith("apps_cz_sv_"))
        self.cb("apps_cz_sv_" + token)
        self.assertIn("node &amp; &lt;test&gt;", self.query.text)
        self.assertNotIn("MUST_NOT_PERSIST", self.query.text)
        self.cb("apps_cz_st_" + token)
        self.assertIn("active", self.query.text)
        self.cb("apps_cz_use_" + token)
        self.assertIn("27", self.query.text)
        self.cb("apps_cz_servers_1")
        self.assertIn("صفحه 2 از 2", self.query.text)
        self.assertEqual([name for name, _ in self.api.calls].count("list_servers"), 2)
        self.assertNotIn("create_server", [name for name, _ in self.api.calls])

    def test_region_plan_price_and_balance(self):
        self.cb("apps_cz_regions_0")
        token = next(x[len("apps_cz_rg_"):] for x in self.query.callbacks
                     if x.startswith("apps_cz_rg_"))
        self.cb("apps_cz_rg_" + token)
        self.assertIn("&lt;small&gt;", self.query.text)
        self.assertIn("1700", self.query.text)
        self.assertIn("هزینه IPv4", self.query.text)
        self.cb("apps_cz_balance")
        self.assertIn("2134", self.query.text)
        self.cb("apps_cz_account")
        self.assertIn("admin@example.org", self.query.text)

    def test_admin_denied_and_forged_selector(self):
        self.cb("apps_cz_home", role="agent")
        self.assertEqual(self.query.edits, [])
        self.assertIn("فقط مدیر", self.query.message.sent[-1][0])
        self.cb("apps_cz_servers_0")
        count = len(self.query.edits)
        self.cb("apps_cz_sv_forged")
        self.assertEqual(len(self.query.edits), count)
        self.assertIn("معتبر نیست", self.query.message.sent[-1][0])
        token = next(x[len("apps_cz_sv_"):] for x in self.query.callbacks
                     if x.startswith("apps_cz_sv_"))
        self.cb("apps_cz_sv_" + token, actor=999)
        self.assertEqual(len(self.query.edits), count)
        self.now[0] += 601
        self.cb("apps_cz_sv_" + token)
        self.assertEqual(len(self.query.edits), count)

    def test_delete_key_needs_one_shot_actor_bound_confirmation(self):
        self.cb("apps_cz_keys_0")
        token = next(x[len("apps_cz_kdel_"):] for x in self.query.callbacks
                     if x.startswith("apps_cz_kdel_"))
        self.cb("apps_cz_kdel_" + token)
        nonce_cb = next(x for x in self.query.callbacks if x.startswith("apps_cz_kconfirm_"))
        self.cb(nonce_cb, actor=999)
        self.assertEqual(len(self.api.keys), 2)
        self.cb(nonce_cb)
        self.assertEqual(len(self.api.keys), 2)
        self.cb("apps_cz_keys_0")
        token = next(x[len("apps_cz_kdel_"):] for x in self.query.callbacks
                     if x.startswith("apps_cz_kdel_"))
        self.cb("apps_cz_kdel_" + token)
        nonce_cb = next(x for x in self.query.callbacks if x.startswith("apps_cz_kconfirm_"))
        self.cb(nonce_cb)
        self.assertEqual(len(self.api.keys), 1)
        self.cb(nonce_cb)
        self.assertEqual(len(self.api.keys), 1)

    def test_add_key_requires_valid_public_key_and_confirmation(self):
        self.cb("apps_cz_kadd")
        self.assertEqual(self.context.user_data["state"], "CZ_KEY_NAME")
        worked, msg = self.inp("owner-machine")
        self.assertTrue(worked)
        self.assertEqual(self.context.user_data["state"], "CZ_KEY_PUBLIC")
        worked, msg = self.inp("-----BEGIN OPENSSH PRIVATE KEY-----")
        self.assertIn("معتبر نیست", msg.sent[-1][0])
        worked, msg = self.inp(fake_public_key())
        self.assertTrue(worked)
        nonce_cb = msg.sent[-1][1]["reply_markup"][0][0][1]
        self.assertNotIn("CZ_KEY_PUBLIC", self.context.user_data.values())
        self.assertEqual(len(self.api.keys), 2)
        self.cb(nonce_cb)
        self.assertEqual(len(self.api.keys), 3)
        self.cb(nonce_cb)
        self.assertEqual(len(self.api.keys), 3)

    def test_add_key_timeout_cancel_and_cross_chat(self):
        self.cb("apps_cz_kadd")
        worked, msg = self.inp("some-key", actor=123, chat=999)
        self.assertTrue(worked)
        self.assertIn("مهلت", msg.sent[-1][0])
        self.cb("apps_cz_kadd")
        self.now[0] += 200
        worked, msg = self.inp("another-name")
        self.assertTrue(worked)
        self.assertIn("مهلت", msg.sent[-1][0])
        self.cb("apps_cz_kadd")
        worked, msg = self.inp("لغو")
        self.assertTrue(worked)
        self.assertNotIn("state", self.context.user_data)

    def test_no_hidden_mutations_and_legacy_callbacks_remain_in_source(self):
        source = (Path(__file__).resolve().parents[1] / "bot_final_v49-2.py").read_text("utf-8")
        start = source.index("def _build_admin_programs_kb()")
        end = source.index("async def _show_admin_programs_hub(", start)
        programs = source[start:end]
        self.assertIn('callback_data="apps_cz_home"', programs)
        self.assertNotIn('callback_data="hpeg_status"', programs)
        for original in ('elif d in ("hp_addedge", "hpeg_wizard")',
                         'elif d.startswith("srv_mkactive_")',
                         'elif d.startswith("hpdefmig_yes_")',
                         'elif d.startswith("hpdef_")',
                         'elif d == "hpeg_status"'):
            self.assertIn(original, source)
        self.assertIn('elif d.startswith("apps_cz_")', source)


class KeyValidationTests(unittest.TestCase):
    def test_openssh_key_validation(self):
        self.assertEqual(_public_key(fake_public_key()), fake_public_key())
        for invalid in ("ssh-ed25519 XXXX", "ssh-rsa ????",
                        "-----BEGIN PRIVATE KEY-----", "ssh-ed25519 AAAA\nXX",
                        "not-a-key", "ssh-ed25519 " + "x" * 10000):
            with self.subTest(invalid=invalid[:25]), self.assertRaises(ValueError):
                _public_key(invalid)


if __name__ == "__main__":
    unittest.main()
