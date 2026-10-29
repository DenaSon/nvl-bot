"""Cloudzy read-only panel tests and CZ-03 home/callback contracts."""
import asyncio
from pathlib import Path
import unittest

from cloudzy_admin_panel import CloudzyAdminPanel
from cloudzy_service import CloudzyAPIError, CloudzyError


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
        return [v for row in self.edits[-1][1]["reply_markup"] for _, v in row]


class Context:
    def __init__(self):
        self.user_data = {}


class FakeCloudzy:
    def __init__(self):
        self.calls = []

    def _called(self, method, *args):
        self.calls.append((method, args))

    def list_servers(self):
        self._called("list_servers")
        return {"data": [
            {"id": f"srv{i}", "hostname": f"node{i}", "credentials": "MUST_NOT_PERSIST"}
            for i in range(8)
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
        return {"plans": [{"id": "p1", "name": "<small>", "price": {
            "monthlyEquivCents": 1700, "regionId": "fra"}},
            {"id": "p2", "slug": "medium", "price": None}]}

    def whoami(self):
        self._called("whoami")
        return {"data": {"name": "Admin", "email": "admin@example.org", "id": "42"}}

    def get_balance(self):
        self._called("get_balance")
        return {"data": {"balanceCents": 2134, "currency": "USD"}}

    def list_ssh_keys(self):
        self._called("list_ssh_keys")
        return {"data": [{"id": "k1", "name": "owner", "publicKey": "PRIVATE_NO"},
                         {"id": "k2", "name": "operator"}]}

    # Any unexpected write is a hard failure, rather than a mocked success.
    def __getattr__(self, method):
        if method in ("create_server", "delete_server", "power_on", "power_off",
                      "restart_server", "rename_server", "rebuild_server",
                      "reset_server_password", "add_ssh_key", "delete_ssh_key"):
            raise AssertionError("No Cloudzy writes in phase 1")
        raise AttributeError(method)


def markup(rows):
    for row in rows:
        for _, cb in row:
            if not isinstance(cb, str) or len(cb.encode("utf-8")) > 64:
                raise AssertionError("invalid callback length")
    return rows


class Phase1PanelTests(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.api = FakeCloudzy()
        self.panel = CloudzyAdminPanel(factory=lambda: self.api, now=lambda: self.now[0])
        self.context = Context()
        self.query = FakeQuery()

    def cb(self, data, *, role="admin", actor=123, chat=345):
        asyncio.run(self.panel.handle_callback(self.query, self.context, data,
            role=role, actor=actor, chat=chat, markup=markup))

    def test_home_has_distinct_manual_and_cloudzy_entries_without_api_reads(self):
        self.cb("apps_cz_home")
        self.assertIn("مدیریت Edge", self.query.text)
        self.assertIn("Cloudflare", self.query.text)
        self.assertNotIn("CZ-04B", self.query.text)
        labels = {cb: label for row in self.query.edits[-1][1]["reply_markup"]
                  for label, cb in row}
        for cb in ("apps_cz_servers_0", "apps_cz_regions_0",
                   "apps_cz_keys_0", "apps_cz6_start", "apps_cz_edge",
                   "apps_cz_operations", "apps_cz_account", "apps_cz_balance",
                   "apps_edge_manual_home"):
            self.assertIn(cb,labels)
        self.assertIn("Cloudzy",labels["apps_cz6_start"])
        self.assertIn("دستی",labels["apps_edge_manual_home"])
        self.assertNotEqual(labels["apps_cz6_start"],labels["apps_edge_manual_home"])
        self.assertIn("apps_cz7_home",labels)
        self.assertNotIn("hpeg_status",self.query.callbacks)
        self.assertEqual(self.api.calls,[])

    def test_cz03_wizard_operations_and_key_add_dispatched_first(self):
        # The read-only presentation module should never intercept CZ-03 actions.
        source = (Path(__file__).resolve().parents[1] / "bot_final_v49-2.py").read_text("utf-8")
        self.assertIn('"apps_cz_operations", "apps_cz6_start"', source)
        self.assertIn('"apps_cz6_status"', source)
        self.assertIn('d == "apps_cz_edge" or d.startswith("apps_cz4_")', source)
        self.assertIn('d.startswith(("apps_cz_q", "apps_cz6_resume_"))', source)
        self.assertLess(source.index("_cloudzy_quick_edge.handle_callback("),
                        source.index("_cloudzy_admin_panel.handle_callback("))
        self.cb("apps_cz_keys_0")
        self.assertIn("apps_cz_qsavekey", self.query.callbacks)
        self.assertIn("ثبت کلید عمومی Core", self.query.text)
        self.assertNotIn("افزودن/حذف کلید در فازهای بعد", self.query.text)

    def test_servers_paginated_and_detail_status_usage_html_safe(self):
        self.cb("apps_cz_servers_0")
        self.assertIn("تعداد دریافت‌شده: 8", self.query.text)
        self.assertIn("apps_cz_servers_1", self.query.callbacks)
        self.assertEqual(len(self.context.user_data["cz_refs"]["items"]), 6)
        self.assertNotIn("MUST_NOT_PERSIST", str(self.context.user_data))
        tok = next(v[len("apps_cz_sv_"):] for v in self.query.callbacks
                   if v.startswith("apps_cz_sv_"))
        self.cb("apps_cz_sv_" + tok)
        self.assertIn("node &amp; &lt;test&gt;", self.query.text)
        self.cb("apps_cz_st_" + tok)
        self.assertIn("active", self.query.text)
        self.cb("apps_cz_use_" + tok)
        self.assertIn("27", self.query.text)
        self.cb("apps_cz_servers_1")
        self.assertIn("صفحه 2 از 2", self.query.text)
        self.assertEqual([m for m, _ in self.api.calls].count("list_servers"), 2)

    def test_regions_plans_account_balance_and_saved_public_keys(self):
        self.cb("apps_cz_regions_0")
        tok = next(v[len("apps_cz_rg_"):] for v in self.query.callbacks
                   if v.startswith("apps_cz_rg_"))
        self.cb("apps_cz_rg_" + tok)
        self.assertIn("&lt;small&gt;", self.query.text)
        self.assertIn("1700", self.query.text)
        self.assertIn("هزینه IPv4", self.query.text)
        self.assertIn("apps_cz_pl_hourly_" + tok, self.query.callbacks)
        self.cb("apps_cz_pl_hourly_" + tok)
        self.assertIn("ساعتی", self.query.text)
        self.cb("apps_cz_pl_quarterly_" + tok)
        self.assertIn("سه‌ماهه", self.query.text)
        self.cb("apps_cz_pl_annually_" + tok)
        self.assertIn("سالانه", self.query.text)
        self.cb("apps_cz_balance")
        self.assertIn("2134", self.query.text)
        self.cb("apps_cz_account")
        self.assertIn("admin@example.org", self.query.text)
        self.cb("apps_cz_keys_0")
        self.assertIn("کلیدهای عمومی", self.query.text)
        self.assertFalse(any(x.startswith(("apps_cz_kdel_", "apps_cz_kadd", "apps_cz_kconfirm_"))
                             for x in self.query.callbacks))
        self.assertNotIn("PRIVATE_NO", str(self.context.user_data))
        tok = next(v[len("apps_cz_key_"):] for v in self.query.callbacks
                   if v.startswith("apps_cz_key_"))
        self.cb("apps_cz_key_" + tok)
        self.assertIn("مشخصات", self.query.text)

    def test_cross_user_stale_and_forged_callbacks(self):
        self.cb("apps_cz_home", role="agent")
        self.assertEqual(self.query.edits, [])
        self.assertIn("فقط مدیر", self.query.message.sent[-1][0])
        self.cb("apps_cz_servers_0")
        size = len(self.query.edits)
        self.cb("apps_cz_sv_forged")
        self.assertEqual(len(self.query.edits), size)
        tok = next(v[len("apps_cz_sv_"):] for v in self.query.callbacks
                   if v.startswith("apps_cz_sv_"))
        self.cb("apps_cz_sv_" + tok, actor=999)
        self.assertEqual(len(self.query.edits), size)
        self.now[0] += 601
        self.cb("apps_cz_sv_" + tok)
        self.assertEqual(len(self.query.edits), size)

    def test_api_errors_do_not_show_secrets_and_empty_inventory_is_safe(self):
        class Denied(FakeCloudzy):
            def list_servers(self):
                raise CloudzyAPIError(403, "topsecret_value")
        self.panel = CloudzyAdminPanel(factory=Denied, now=lambda: self.now[0])
        self.cb("apps_cz_servers_0")
        self.assertIn("403", self.query.message.sent[-1][0])
        self.assertNotIn("topsecret_value", self.query.message.sent[-1][0])
        class Empty(FakeCloudzy):
            def list_servers(self):
                return {"data": []}
            def list_regions(self):
                return {"data": []}
        self.panel = CloudzyAdminPanel(factory=Empty, now=lambda: self.now[0])
        self.cb("apps_cz_servers_0")
        self.assertIn("تعداد دریافت‌شده: 0", self.query.text)
        self.cb("apps_cz_regions_0")
        self.assertIn("تعداد: 0", self.query.text)

    def test_zero_provider_mutation_and_old_manual_paths_present(self):
        source = (Path(__file__).resolve().parents[1] / "bot_final_v49-2.py").read_text("utf-8")
        menu = source[source.index("def _build_admin_programs_kb"):source.index("_MIGRATION_INPUT_STATES =")]
        self.assertIn('callback_data="apps_cz_home"', menu)
        self.assertNotIn('callback_data="hpeg_status"', menu)
        for original in ('elif d in ("hp_addedge", "hpeg_wizard")',
                         'elif d.startswith("srv_mkactive_")',
                         'elif d.startswith(("hpdef_migrate_", "hpdefmig_yes_", "hpdef_"))',
                         'elif d.startswith(("hpdef_migrate_", "hpdefmig_yes_", "hpdef_"))',
                         'elif d == "hpeg_status"'):
            self.assertIn(original, source)
        self.assertIn('elif d.startswith("apps_cz_")', source)
        for cb in ("apps_cz_home", "apps_cz_servers_0", "apps_cz_regions_0",
                   "apps_cz_keys_0", "apps_cz_balance"):
            self.cb(cb)
        self.assertTrue(all(m in {
            "list_servers", "list_regions", "list_ssh_keys", "get_balance"}
            for m, _ in self.api.calls))
        panel_source = (Path(__file__).resolve().parents[1] / "cloudzy_admin_panel.py").read_text("utf-8")
        for forbidden in ("create_server(", "delete_server(", "power_on(",
                          "reset_server_password(", "add_ssh_key(", "delete_ssh_key("):
            self.assertNotIn(forbidden, panel_source)


if __name__ == "__main__":
    unittest.main()
