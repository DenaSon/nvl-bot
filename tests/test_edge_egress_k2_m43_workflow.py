"""M4.3 actor/chat/message scoped, volatile and one-shot Telegram approval."""
from __future__ import annotations
from pathlib import Path
import unittest

from edge_egress_k2_m4_telegram import parse_callback,preview_buttons
from edge_egress_k2_migration_inventory import select_migration
from edge_egress_k2_m43_client import M43ClientHold
from edge_egress_k2_m43_workflow import (
    PendingTelegramApproval,EphemeralApprovalStore,confirmation_buttons,
    confirmation_html,result_html,halted_html,
)

NOW=1792010100


def make(mode="SINGLE",names=("nvl0555",)):
    sel=select_migration(mode,names,"e9")
    reply={"state":"PREPARED","request_id":"a"*32,"edge_id":"e9",
           "user_count":len(names),"expires_at":NOW+90}
    return PendingTelegramApproval.create(
        selection=sel,actor_id=11,chat_id=-222,message_id=77,
        result=reply,now=NOW,
    )


class M43ApprovalTests(unittest.TestCase):
    def test_exact_actor_chat_message_and_edge(self):
        pending=make()
        pending.check(actor_id=11,chat_id=-222,message_id=77,
                      edge_id="e9",now=NOW+2)
        for kwargs in (
            {"actor_id":12},{"chat_id":-333},{"message_id":78},
            {"edge_id":"e7"},{"now":NOW+90},
        ):
            good=dict(actor_id=11,chat_id=-222,message_id=77,
                      edge_id="e9",now=NOW+2)
            good.update(kwargs)
            with self.subTest(kwargs=kwargs),self.assertRaises(M43ClientHold):
                pending.check(**good)

    def test_rejects_forged_scope_count_and_long_approval(self):
        sel=select_migration("SINGLE",("nvl0555",),"e9")
        for override in ({"edge_id":"e7"},{"user_count":2},
                         {"request_id":".."*16},{"expires_at":NOW+91},
                         {"expires_at":NOW}):
            reply={"state":"PREPARED","request_id":"a"*32,
                   "edge_id":"e9","user_count":1,"expires_at":NOW+90}
            reply.update(override)
            with self.subTest(override=override),self.assertRaises(M43ClientHold):
                PendingTelegramApproval.create(
                    selection=sel,actor_id=11,chat_id=-222,
                    message_id=77,result=reply,now=NOW)

    def test_one_shot_store_cannot_replay_old_message(self):
        store=EphemeralApprovalStore()
        epoch=store.begin(11,-222)
        store.finish(make(),epoch)
        record=store.consume(actor_id=11,chat_id=-222,message_id=77,
                             edge_id="e9",now=NOW)
        self.assertEqual(record.request_id,"a"*32)
        with self.assertRaises(M43ClientHold):
            store.consume(actor_id=11,chat_id=-222,message_id=77,
                          edge_id="e9",now=NOW)

    def test_concurrent_prepares_and_navigation_cancel_inflight(self):
        store=EphemeralApprovalStore()
        one=store.begin(11,-222)
        with self.assertRaisesRegex(M43ClientHold,"IN_PROGRESS"):
            store.begin(11,-222)
        store.discard(11,-222)
        with self.assertRaisesRegex(M43ClientHold,"INVALIDATED"):
            store.finish(make(),one)
        store.release(11,-222)
        other=store.begin(11,-222)
        self.assertNotEqual(one,other)
        store.finish(make(),other)
        with self.assertRaises(M43ClientHold):
            store.consume(actor_id=11,chat_id=-222,message_id=88,
                          edge_id="e9",now=NOW)
        # A wrong-message tap cannot consume the valid confirmation.
        store.consume(actor_id=11,chat_id=-222,message_id=77,
                      edge_id="e9",now=NOW)

    def test_expiration_does_not_execute(self):
        store=EphemeralApprovalStore()
        epoch=store.begin(11,-222)
        store.finish(make(),epoch)
        with self.assertRaises(M43ClientHold):
            store.consume(actor_id=11,chat_id=-222,message_id=77,
                          edge_id="e9",now=NOW+90)

    def test_result_never_labels_partial_as_success(self):
        sel=make().selection
        success={"state":"COMPLETED","accounts":[
            {"username":"nvl0555","state":"VERIFIED"}]}
        html=result_html(success,selection=sel)
        self.assertIn("تکمیل",html)
        hold={"state":"HOLD","accounts":[
            {"username":"nvl0555","state":"HOLD"}]}
        self.assertIn("متوقف",result_html(hold,selection=sel))
        self.assertIn("نامشخص",halted_html())
        wrong={"state":"COMPLETED","accounts":[
            {"username":"nvl0557","state":"VERIFIED"}]}
        with self.assertRaises(M43ClientHold):
            result_html(wrong,selection=sel)

    def test_two_tap_callbacks_have_no_nonce(self):
        self.assertEqual(parse_callback("hpeg_m4_prepare_e9"),("prepare","e9"))
        self.assertEqual(parse_callback("hpeg_m4_confirm_e9"),("confirm","e9"))
        self.assertEqual(parse_callback("hpeg_m4_abort_e9"),("abort","e9"))
        items=[x for row in confirmation_buttons("e9") for x in row]
        self.assertEqual(len(items),2)
        # A STATUS / post-CONFIRM view without a fresh inventory must
        # not show an actionable PREPARE; fresh positive source+F4 previews
        # are tested separately by M4OperatorReadOnlyTests.
        self.assertNotIn(("🔐 درخواست تأیید","hpeg_m4_prepare_e9"),
                         [x for row in preview_buttons("e9") for x in row])
        self.assertNotIn("a"*32,str(items))
        self.assertLessEqual(max(len(x[1]) for x in items),64)
        self.assertNotIn("a"*32,confirmation_html(make()))

    def test_bot_source_routes_after_admin_and_no_pickle_approval(self):
        text=(Path(__file__).resolve().parents[1]/"bot_final_v49-2.py").read_text()
        begin=text.index('    elif d.startswith("hpeg_m4_"):')
        end=text.index('    elif d.startswith("hpeg_transfer_"):',begin)
        handler=text[begin:end]
        self.assertLess(handler.index("if role != 'admin':"),
                        handler.index("k2_m43_approvals.consume("))
        self.assertIn('k2_m43_approvals.begin(actor_id,chat_id)',handler)
        self.assertIn('k2_m43_approvals.consume(',handler)
        self.assertNotIn("context.user_data['k2_m4_pending']",handler)
        self.assertNotIn("context.user_data.get('k2_m4_pending')",handler)
        self.assertNotIn("Existing6GGuardedExecutor(",handler)
        self.assertNotIn("run_migration_wave(",handler)


if __name__=="__main__":
    unittest.main()
