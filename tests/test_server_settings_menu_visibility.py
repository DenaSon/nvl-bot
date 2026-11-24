"""Regression tests for hiding obsolete NVL server-menu entries without removing handlers."""
from __future__ import annotations

import ast
import asyncio
from types import SimpleNamespace
from pathlib import Path
import unittest


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class InlineButton:
    def __init__(self, text, *, callback_data):
        self.text = text
        self.callback_data = callback_data


def load_source():
    return BOT.read_text(encoding="utf-8")


def load_server_settings_keyboard(source, **kwargs):
    tree = ast.parse(source)
    function = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_build_server_settings_kb"
    )
    namespace = {"InlineKeyboardButton": InlineButton}
    exec(
        compile(ast.Module(body=[function], type_ignores=[]), str(BOT), "exec"),
        namespace,
    )
    return namespace["_build_server_settings_kb"](**kwargs)


def load_ip_service_keyboard(source):
    tree = ast.parse(source)
    branch = next(
        node for node in ast.walk(tree)
        if isinstance(node, ast.If) and "ipsvc_menu" in ast.unparse(node.test)
    )
    assignment = next(
        node for node in branch.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "kb"
                for target in node.targets)
    )
    namespace = {
        "InlineKeyboardButton": InlineButton,
        "filter_icon": "🟢",
        "filter_enabled": True,
        "filter_threshold": 8.0,
    }
    exec(
        compile(ast.Module(body=[assignment], type_ignores=[]), str(BOT), "exec"),
        namespace,
    )
    return namespace["kb"]


def flatten(keyboard):
    return [button for row in keyboard for button in row]


class ServerMenuVisibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = load_source()

    def test_server_settings_menu_hides_only_requested_entries(self):
        buttons = flatten(load_server_settings_keyboard(self.source))
        callbacks = {button.callback_data for button in buttons}

        hidden = {
            "srv_direct_menu",
            "srv_tls",
            "srv_ssh_debug",
            "srv_ssh_diag",
            "orphan_menu",
            "srv_rb",
        }
        retained = {
            "srv_status",
            "apps_home",
            "hp_filtering",
            "srv_udpgw",
            "srv_health",
            "ipsvc_menu",
            "dom_menu",
            "uact_back_to_menu",
        }

        self.assertTrue(hidden.isdisjoint(callbacks))
        self.assertTrue(retained.issubset(callbacks))

    def test_edge_navigation_requires_explicit_authorized_ui(self):
        new_rows = [[("➕ افزودن Edge جدید · AWG", "apps_edge_manual_new_awg")]]
        for allowed in (False, True):
            with self.subTest(allowed=allowed):
                buttons = flatten(load_server_settings_keyboard(
                    self.source, edge_allowed=allowed, new_edge_rows=new_rows))
                callbacks = {button.callback_data for button in buttons}
                self.assertEqual("apps_edge_quick_home" in callbacks, allowed)
                self.assertEqual("apps_edge_manual_new_awg" in callbacks, allowed)

    def test_ip_service_menu_hides_legacy_entries_and_keeps_active_actions(self):
        buttons = flatten(load_ip_service_keyboard(self.source))
        callbacks = {button.callback_data for button in buttons}

        self.assertNotIn("ipsvc_distribute", callbacks)
        self.assertNotIn("ipsvc_auto", callbacks)
        self.assertTrue({
            "ipsvc_search",
            "ipsvc_allusers",
            "hp_menu",
            "ipsvc_filter_settings",
            "srv_menu_back",
        }.issubset(callbacks))

    def test_hidden_entries_keep_their_existing_admin_handlers(self):
        for callback in (
            "srv_direct_menu",
            "srv_tls",
            "srv_ssh_debug",
            "srv_ssh_diag",
            "orphan_menu",
            "srv_rb",
            "ipsvc_distribute",
            "ipsvc_auto",
        ):
            with self.subTest(callback=callback):
                self.assertIn(f'd == "{callback}"', self.source)



class InfrastructureAccessTests(unittest.IsolatedAsyncioTestCase):
    async def test_direct_edge_buttons_only_for_live_private_admin(self):
        tree = ast.parse(load_source())
        names = {"_show_nav_infrastructure", "_build_server_settings_kb"}
        nodes = [node for node in tree.body
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                 and node.name in names]
        active = {77}
        wizard_rows = [[("AWG", "apps_edge_manual_new_awg")]]
        namespace = {
            "asyncio": asyncio,
            "InlineKeyboardButton": InlineButton,
            "InlineKeyboardMarkup": lambda rows: rows,
            "_db_get_admin_chat_ids": lambda: active,
            "_manual_edge": SimpleNamespace(_new_edge_buttons=lambda: wizard_rows),
        }
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(BOT), "exec"),
             namespace)
        for actor, chat, kind, expected in (
            (77, 77, "private", True),
            (78, 78, "private", False),
            (77, 77, "group", False),
            (77, 99, "private", False),
        ):
            with self.subTest(actor=actor, chat=chat, kind=kind):
                views = []
                async def reply_text(text, *, reply_markup, parse_mode):
                    views.append((text, reply_markup, parse_mode))
                target = SimpleNamespace(from_user=SimpleNamespace(id=actor),
                                         chat_id=chat, chat=SimpleNamespace(type=kind),
                                         reply_text=reply_text)
                await namespace["_show_nav_infrastructure"](target)
                title, rows, mode = views[0]
                callbacks = {button.callback_data for button in flatten(rows)}
                self.assertIn("<b>زیرساخت</b>", title)
                self.assertEqual(mode, "HTML")
                self.assertEqual("apps_edge_quick_home" in callbacks, expected)
                self.assertEqual("apps_edge_manual_new_awg" in callbacks, expected)
        wizard_rows.clear()
        views = []
        target = SimpleNamespace(from_user=SimpleNamespace(id=77), chat_id=77,
                                 chat=SimpleNamespace(type="private"),
                                 reply_text=reply_text)
        await namespace["_show_nav_infrastructure"](target)
        callbacks = {button.callback_data for button in flatten(views[0][1])}
        self.assertIn("apps_edge_quick_home", callbacks)
        self.assertNotIn("apps_edge_manual_new_awg", callbacks)


if __name__ == "__main__":
    unittest.main()
