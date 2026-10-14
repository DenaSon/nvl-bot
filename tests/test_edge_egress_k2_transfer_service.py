"""P3-A Telegram execution ticket is separate from Phase2 read acknowledgment.

Source tests never register a live bot worker or touch Linux/network.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
import time
import unittest

from edge_egress_k2_transfer_service import (
    K2_TELEGRAM_TRANSFER_ENABLED, GuardedK2TelegramTransferService,
    TransferRegistrationHold,
)
from edge_egress_p3_executor import (
    ExecutionScope, FreshEvidence, BASE_GATES, ATTACH_GATES,
)

BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class K2TelegramTransferServiceTests(unittest.TestCase):
    def setUp(self):
        self.scope = ExecutionScope(
            "UID_ATTACH", "fra1", "104.194.144.195", "216.126.229.12",
            username="canary", uid=1655,
        )
        self.review = lambda _: FreshEvidence(
            digest="b"*64, checked_at=int(time.time()),
            gates=BASE_GATES | ATTACH_GATES,
        )

    def make(self, **overrides):
        args = dict(
            db_conn=lambda:None, acquire_fn=lambda *_:(None,1),
            journal_fn=lambda *a,**kw:None,
            resolve_scope=lambda user,eid:self.scope,
            independent_review=self.review,
            make_host_port=lambda scope,ticket:object(),
            geteuid=lambda:0,
        )
        args.update(overrides)
        return GuardedK2TelegramTransferService(**args)

    def test_no_release_default(self):
        self.assertIs(K2_TELEGRAM_TRANSFER_ENABLED,False)
        s=self.make()
        with self.assertRaisesRegex(TransferRegistrationHold,"NOT_ATTESTED"):
            s.prepare(username="canary",edge_id="fra1",actor_id=123,chat_id=99)

    def test_no_root_even_with_opt_in(self):
        s=self.make(geteuid=lambda:1000,release_enabled=True)
        with self.assertRaisesRegex(TransferRegistrationHold,"NOT_ATTESTED"):
            s.prepare(username="canary",edge_id="fra1",actor_id=123,chat_id=99)

    def test_p3a_ticket_is_independently_bound_and_not_review_ack(self):
        s=self.make(release_enabled=True)
        prepared=s.prepare(username="canary",edge_id="fra1",
                           actor_id=123,chat_id=99)
        self.assertEqual(prepared.ticket.actor_id,123)
        self.assertEqual(prepared.ticket.chat_id,99)
        self.assertEqual(len(prepared.ticket.nonce),32)
        with self.assertRaisesRegex(TransferRegistrationHold,"ACTOR_OR_CHAT_CHANGED"):
            asyncio.run(s.execute(prepared,actor_id=123,chat_id=100))
        with self.assertRaisesRegex(TransferRegistrationHold,"AUDITED_COMPOSITE"):
            asyncio.run(s.execute(prepared,actor_id=123,chat_id=99))

    def test_scope_drift_rejected_before_ticket(self):
        s=self.make(resolve_scope=lambda user,eid:self.scope,release_enabled=True)
        with self.assertRaisesRegex(TransferRegistrationHold,"SELECTED_UID"):
            s.prepare(username="other",edge_id="fra1",actor_id=123,chat_id=99)


class K2TelegramCallbackIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = BOT.read_text(encoding="utf-8")

    def test_only_one_explicit_release_entry_with_default_absence(self):
        src=self.s
        self.assertIn("context.application.bot_data.get('k2_transfer_service')",src)
        self.assertIn('    elif d.startswith("hpeg_xfer_prepare_"):',src)
        self.assertIn('    elif d.startswith("hpeg_xfer_confirm_"):',src)
        self.assertIn('service.prepare, username=username, edge_id=edge_id,',src)
        self.assertIn('receipt = await service.execute(',src)
        self.assertNotIn("context.application.bot_data['k2_transfer_service'] =",src)

    def test_confirmation_is_admin_only_and_consumes_before_execution(self):
        first=self.s.index('    elif d.startswith("hpeg_xfer_confirm_"):')
        end=self.s.index('    elif d.startswith("hpeg_transfer_"):',first)
        handler=self.s[first:end]
        self.assertLess(handler.index("if role != 'admin':"),
                        handler.index("context.user_data.pop('k2_transfer_prepared'"))
        self.assertLess(handler.index("context.user_data.pop('k2_transfer_prepared'"),
                        handler.index("await service.execute("))
        self.assertIn("token != prepared.ticket.nonce",handler)
        self.assertNotIn("_db_set_all_accounts_host",handler)
        self.assertNotIn("_update_cloudflare_dns",handler)


if __name__ == "__main__":
    unittest.main()
