"""Regression tests for hiding obsolete NVL server-menu entries without removing handlers."""
from __future__ import annotations

import ast
from pathlib import Path
import unittest


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class InlineButton:
    def __init__(self, text, *, callback_data):
        self.text = text
        self.callback_data = callback_data


def load_source():
    return BOT.read_text(encoding="utf-8")


def load_server_settings_keyboard(source):
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
    return namespace["_build_server_settings_kb"]()


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


if __name__ == "__main__":
    unittest.main()
