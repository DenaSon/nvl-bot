"""D1-C2B: cover ALL high-risk legacy manual Edge callback/text entry points.

No running bot import and no network, DB, or customer changes in tests.
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from edge_egress_entrypoints import (
    EdgeOperation, LEGACY_MANUAL_UNSAFE, UNKNOWN_MODE, UNAUTHORIZED,
    classify_edge_callback, classify_edge_text, evaluate_manual_edge_gate,
    edge_guard_message,
)
from edge_egress_lifecycle import PROTECTED_SETTING_KEY, PROTECTED_SETTING_DEFAULT

if sys.version_info >= (3, 12):
    from test_edge_egress_bot_integration import get_function


class EdgeEntryPointClassificationTests(unittest.TestCase):
    def test_all_high_risk_manual_callbacks_are_classified(self):
        callbacks = {
            "hp_add": EdgeOperation.REGISTER,
            "hp_addedge": EdgeOperation.REGISTER,
            "srv_mkactive_172.86.94.174": EdgeOperation.ACTIVATE,
            "hpdef_172.86.94.174": EdgeOperation.DEFAULT,
            "hpdef_migrate_172.86.94.174": EdgeOperation.ASSIGN,
            "hpdefmig_yes_172.86.94.174": EdgeOperation.ASSIGN,
            "hpblk_172.86.94.174": EdgeOperation.BLOCK,
            "hpact_172.86.94.174": EdgeOperation.UNBLOCK,
            "hpdelconfirm_172.86.94.174": EdgeOperation.DELETE,
            "hpdelyes_172.86.94.174": EdgeOperation.DELETE,
            "hpstandby_172.86.94.174": EdgeOperation.STANDBY,
            "srv_wiz_promote_start": EdgeOperation.CORE_MIGRATION,
            "srv_run_promote": EdgeOperation.CORE_MIGRATION,
            "srv_run_demote": EdgeOperation.CORE_MIGRATION,
        }
        for data, expected in callbacks.items():
            with self.subTest(data=data):
                self.assertEqual(classify_edge_callback(data), expected)

    def test_read_only_and_unrelated_callbacks_not_blocked(self):
        for data in (None, "", "hp_menu", "hp_speedtest_all", "srv_status",
                     "hpdef_", "hpdef_migrate_", "apps_menu", "mza_ncreate"):
            with self.subTest(data=data):
                self.assertIsNone(classify_edge_callback(data))

    def test_text_entry_states_and_existing_tls_command(self):
        for state in (
            "HOSTS_INPUT", "HOSTS_APPEND_INPUT", "HOSTPOOL_ADD_INPUT",
            "EDGE_NEW_IP", "EDGE_NEW_ROOTPASS", "EDGE_NEW_PORT",
            "SRV_PROMOTE_PORT_INPUT", "SRV_PROMOTE_GOST_PORTS",
            "SRV_PROMOTE_PASS_INPUT",
        ):
            with self.subTest(state=state):
                self.assertIsNotNone(classify_edge_text(state, "redacted"))
        self.assertEqual(classify_edge_text(None, "tlstoedge"), EdgeOperation.DNS)
        self.assertIsNone(classify_edge_text(None, "some unrelated command"))
        self.assertIsNone(classify_edge_text("MIG_SOURCE_HOST", "example.com"))

    def test_default_setting_preserves_unprotected_administrator(self):
        for action in EdgeOperation:
            for value in (None, "0"):
                with self.subTest(action=action, value=value):
                    gate = evaluate_manual_edge_gate(action, value, role="admin")
                    self.assertTrue(gate.allowed)
                    self.assertFalse(gate.protected_mode)

    def test_protected_setting_denies_every_manual_legacy_action(self):
        for action in EdgeOperation:
            gate = evaluate_manual_edge_gate(action, "1", role="admin")
            self.assertFalse(gate.allowed)
            self.assertEqual(gate.reason, LEGACY_MANUAL_UNSAFE)
            self.assertTrue(gate.protected_mode)

    def test_unknown_setting_denies_every_action(self):
        for value in ("yes", "on", "", " 0 ", "2"):
            with self.subTest(value=value):
                gate = evaluate_manual_edge_gate(EdgeOperation.ACTIVATE, value, role="admin")
                self.assertFalse(gate.allowed)
                self.assertEqual(gate.reason, UNKNOWN_MODE)

    def test_non_admin_is_rejected_even_if_unprotected(self):
        for role in ("agent", "accountant", "user", None):
            with self.subTest(role=role):
                gate = evaluate_manual_edge_gate(EdgeOperation.DEFAULT, "0", role=role)
                self.assertEqual(gate.reason, UNAUTHORIZED)
                self.assertFalse(gate.allowed)

    def test_denial_message_does_not_include_host_or_credentials(self):
        msg = edge_guard_message(LEGACY_MANUAL_UNSAFE)
        self.assertIn("Egress Manager", msg)
        self.assertNotIn("172.86.94.174", msg)
        self.assertNotIn("root", msg.lower())


@unittest.skipIf(sys.version_info < (3, 12), "NVL bot baseline parses on Python 3.12+")
class LiveBotEntryPointVetoTests(unittest.TestCase):
    def callback(self, data, setting="1", role="admin"):
        query = SimpleNamespace(
            data=data,
            answer=AsyncMock(),
            message=SimpleNamespace(reply_text=AsyncMock()),
        )
        bot = get_function("callback_handler", {
            "is_auth": lambda ctx: True,
            "asyncio": asyncio,
            "_db_get_setting": lambda key, default: setting,
            "PROTECTED_SETTING_KEY": PROTECTED_SETTING_KEY,
            "PROTECTED_SETTING_DEFAULT": PROTECTED_SETTING_DEFAULT,
            "classify_edge_callback": classify_edge_callback,
            "evaluate_manual_edge_gate": evaluate_manual_edge_gate,
            "edge_guard_message": edge_guard_message,
        })
        ctx = SimpleNamespace(user_data={"role": role, "agent_id": 0})
        asyncio.run(bot(SimpleNamespace(callback_query=query), ctx))
        return query

    def test_all_manual_callbacks_abort_before_any_side_effects(self):
        for d in (
            "hp_addedge", "hp_add", "srv_mkactive_216.126.229.12",
            "hpdef_216.126.229.12", "hpdef_migrate_216.126.229.12",
            "hpdefmig_yes_216.126.229.12", "hpblk_172.86.94.174",
            "hpact_172.86.94.174", "hpdelyes_172.86.94.174",
            "hpstandby_172.86.94.174", "srv_run_promote",
        ):
            with self.subTest(callback=d):
                query = self.callback(d)
                query.answer.assert_awaited_once()
                query.message.reply_text.assert_awaited_once()
                self.assertIn("Egress Manager", query.message.reply_text.await_args.args[0])

    def test_non_admin_cannot_invoke_manual_edge_callbacks(self):
        query = self.callback("hpdef_216.126.229.12", setting="0", role="agent")
        query.message.reply_text.assert_awaited_once()
        self.assertIn("مدیر", query.message.reply_text.await_args.args[0])

    def text_action(self, state, txt, setting="1"):
        msg = SimpleNamespace(text=txt, delete=AsyncMock(), reply_text=AsyncMock())
        ctx = SimpleNamespace(user_data={"role": "admin", "state": state})
        update = SimpleNamespace(message=msg, effective_chat=SimpleNamespace(id=51234))
        secrets = {51234: "do-not-log-password"}
        bot = get_function("text_handler", {
            "asyncio": asyncio,
            "_db_get_setting": lambda key, default: setting,
            "PROTECTED_SETTING_KEY": PROTECTED_SETTING_KEY,
            "PROTECTED_SETTING_DEFAULT": PROTECTED_SETTING_DEFAULT,
            "classify_edge_text": classify_edge_text,
            "evaluate_manual_edge_gate": evaluate_manual_edge_gate,
            "edge_guard_message": edge_guard_message,
            "_EDGE_PROVISION_SECRETS": secrets,
            "contextlib": __import__("contextlib"),
        })
        asyncio.run(bot(update, ctx))
        return msg, ctx, secrets

    def test_password_wizard_is_cancelled_and_secret_discarded(self):
        msg, ctx, secrets = self.text_action("EDGE_NEW_ROOTPASS", "super-secret")
        msg.delete.assert_awaited_once()
        msg.reply_text.assert_awaited_once()
        self.assertNotIn("super-secret", msg.reply_text.await_args.args[0])
        self.assertNotIn("state", ctx.user_data)
        self.assertEqual(secrets, {})

    def test_manual_host_pool_text_mutation_is_denied_early(self):
        for state in ("HOSTS_INPUT", "HOSTPOOL_ADD_INPUT", "EDGE_NEW_PORT"):
            with self.subTest(state=state):
                msg, ctx, secrets = self.text_action(state, "216.126.229.12")
                msg.reply_text.assert_awaited_once()
                self.assertEqual(secrets, {})
                self.assertNotIn("state", ctx.user_data)

    def test_tls_to_edge_command_is_guarded(self):
        msg, ctx, _ = self.text_action(None, "tlstoedge")
        msg.reply_text.assert_awaited_once()
        self.assertIn("Egress Manager", msg.reply_text.await_args.args[0])


if __name__ == "__main__":
    unittest.main()
