"""K2 Phase 2 final unified Wizard: real installer opt-in, no parallel wizard.

All bot functions are AST-extracted with fake I/O. No VPS, Core or network.
"""
import asyncio
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from edge_egress_phase2_wizard import new_edge_prompt, staged_edge_result
from edge_egress_entrypoints import (
    classify_edge_callback, EdgeOperation, evaluate_manual_edge_gate,
)
from edge_egress_v1_console import EgressConsoleHold

if sys.version_info >= (3, 12):
    from test_edge_egress_bot_integration import get_function


class PureUnifiedWizardTests(unittest.TestCase):
    def test_entrypoint_reuses_existing_registration_safety_gate(self):
        for callback in ("hp_addedge", "hpeg_wizard"):
            operation = classify_edge_callback(callback)
            self.assertEqual(operation, EdgeOperation.REGISTER)
            self.assertFalse(
                evaluate_manual_edge_gate(operation,"1",role="admin").allowed)
            self.assertFalse(
                evaluate_manual_edge_gate(operation,"0",role="accountant").allowed)
            self.assertTrue(
                evaluate_manual_edge_gate(operation,"0",role="admin").allowed)

    def test_one_flow_explicitly_stage_only_not_egress_ready(self):
        self.assertIn("Stage",new_edge_prompt(integrated=True))
        self.assertIn("F4 READY",new_edge_prompt(integrated=True))
        self.assertIn("Legacy",new_edge_prompt(integrated=False))
        for invalid in (None,1,"true"):
            with self.subTest(invalid=invalid),self.assertRaises(EgressConsoleHold):
                new_edge_prompt(integrated=invalid)

    def test_staged_result_requires_correct_identity_and_state(self):
        result = {
            "edge_wg_ip":"10.77.0.7",
            "egress_v1":{"edge_id":"e7","egress_state":"STAGED_NOT_READY",
                         "ingress_ipv4":"10.77.0.7"},
        }
        body, eid = staged_edge_result("172.86.105.67",result)
        self.assertEqual(eid,"e7")
        self.assertIn("HOLD",body)
        self.assertIn("۲/۳",body)
        self.assertNotIn("کلید خصوصی",body)
        for broken in (
            {},
            {"egress_v1":{"edge_id":"e7","egress_state":"READY",
                          "ingress_ipv4":"10.77.0.7"},"edge_wg_ip":"10.77.0.7"},
            {"egress_v1":{"edge_id":"e7","egress_state":"STAGED_NOT_READY",
                          "ingress_ipv4":"10.77.0.9"},"edge_wg_ip":"10.77.0.7"},
            {"egress_v1":{"edge_id":"../","egress_state":"STAGED_NOT_READY",
                          "ingress_ipv4":"10.77.0.7"},"edge_wg_ip":"10.77.0.7"},
        ):
            with self.subTest(broken=broken),self.assertRaises(
                (EgressConsoleHold, ValueError, TypeError)
            ):
                staged_edge_result("172.86.105.67",broken)
        with self.assertRaises(EgressConsoleHold):
            staged_edge_result("127.0.0.1",result)


@unittest.skipIf(sys.version_info < (3,12), "NVL bot requires Python 3.12")
class WizardCallbackRoutingTests(unittest.TestCase):
    def test_one_shared_wizard_callback_and_session_only_opt_in(self):
        from test_edge_egress_bot_integration import source_tree
        source = (source_tree().body)
        fnames = [n.name for n in source if hasattr(n,"name")]
        self.assertEqual(fnames.count("callback_handler"),1)
        self.assertEqual(fnames.count("text_handler"),1)
        from pathlib import Path
        body=(Path(__file__).resolve().parents[1]
              / "bot_final_v49-2.py").read_text(encoding="utf-8")
        self.assertIn('elif d in ("hp_addedge", "hpeg_wizard"):',body)
        self.assertIn("integrated = (d == \"hpeg_wizard\")",body)
        self.assertIn("context.user_data['egress_new_edge_requested'] = integrated",body)
        self.assertIn("context.user_data.get('egress_new_edge_requested') is True",body)
        self.assertIn("egress_stage_requested=stage_for_this_edge",body)
        self.assertIn('callback_data="hpeg_wizard"',body)
        self.assertIn('callback_data="hp_addedge"',body)
        self.assertNotIn("_db_update_setting, 'edge_egress_v1_onboard_enabled'",body)
        self.assertNotIn("_db_set_all_accounts_host",body[body.index(
            'elif d in ("hp_addedge", "hpeg_wizard"):'):body.index(
            'elif d.startswith("hpdef_migrate_")')])

@unittest.skipIf(sys.version_info < (3,12), "NVL bot requires Python 3.12")
class IntegratedWizardFunctionTests(unittest.TestCase):
    def execute(self, *, opt_in, global_toggle="0", protected="0",
                stage_error=None, stage_payload=None):
        events=[]
        bot=types.SimpleNamespace(send_message=AsyncMock())
        app=types.SimpleNamespace(bot=bot)
        outcome={
            "edge_wg_ip":"10.77.0.7",
            "edge_pubkey":"PUBONLY",
            "tunnel_ok":True,
            "_edge_ssh_host_key":"PINNED_KEY",
            "_edge_ssh_port":22,
        }
        def read_setting(key, default=""):
            if key=="edge_egress_protected_mode":
                return protected
            if key=="edge_egress_v1_onboard_enabled":
                return global_toggle
            if key=="hosts":
                return ""
            return default
        def stage(**kwargs):
            events.append(("stage",kwargs["edge_ip"],kwargs["ingress_ip"]))
            if stage_error:
                raise ValueError("SIMULATED_STAGE_HOLD")
            return stage_payload if stage_payload is not None else {
                "edge_id":"e7",
                "egress_state":"STAGED_NOT_READY",
                "ingress_ipv4":"10.77.0.7",
            }
        def fake_sync(*args):
            events.append(("ingress",args[0]))
            return True, "", outcome.copy()
        fake_module=types.SimpleNamespace(onboard_after_ingress=stage)
        fn=get_function("_provision_new_edge",{
            "_db_get_setting":read_setting,
            "_provision_new_edge_sync":fake_sync,
            "_db_add_host_pool":lambda host:events.append(("pool",host)),
            "_db_update_setting":lambda *args:events.append(("setting_write",args)),
            "_db_set_host_active":lambda *args:events.append(("pool_active",args)),
            "_db_set_host_provider_meta":lambda *args:None,
            "_get_core_public_ip_cached":lambda:"209.200.246.198",
            "record_ingress_candidate":lambda *args:events.append(("candidate",)),
            "egress_staged_edge_result":staged_edge_result,
            "db_conn":lambda:None,
            "InlineKeyboardButton":lambda label,callback_data:(label,callback_data),
            "InlineKeyboardMarkup":lambda rows:rows,
            "esc":lambda s:s,
            "log":types.SimpleNamespace(exception=lambda *a,**kw:None),
        })
        with patch.dict(sys.modules,{"edge_egress_v1_onboarding":fake_module}):
            result=asyncio.run(fn(
                "172.86.105.67","DO_NOT_LOG",2252,
                "edge-172-86-105-67",5000,app,
                egress_stage_requested=opt_in,
            ))
        return result,events,bot.send_message.await_args_list

    def test_new_wizard_stages_even_when_global_flag_off(self):
        result,events,messages=self.execute(opt_in=True,global_toggle="0")
        self.assertTrue(result[0])
        self.assertEqual(events[0],("ingress","172.86.105.67"))
        self.assertIn(("stage","172.86.105.67","10.77.0.7"),events)
        self.assertIn(("pool","172.86.105.67"),events)
        self.assertIn("HOLD",messages[-1].args[1])
        self.assertNotIn("DO_NOT_LOG",messages[-1].args[1])
        rows=messages[-1].kwargs["reply_markup"]
        self.assertIn("hpeg_stage_e7",str(rows))
        self.assertIn("hpeg_review_edge_e7",str(rows))
        self.assertNotIn("hpdef_",str(rows))
        self.assertFalse(any(event[0]=="setting_write" and
                             event[1][0]=="edge_egress_v1_onboard_enabled"
                             for event in events))

    def test_legacy_flow_default_off_remains_ingress_only(self):
        result,events,messages=self.execute(opt_in=False,global_toggle="0")
        self.assertTrue(result[0])
        self.assertFalse(any(x[0]=="stage" for x in events))
        self.assertIn("hpdef_",str(messages[-1].kwargs["reply_markup"]))

    def test_staging_failure_after_ingress_holds_without_pool_or_default(self):
        result,events,messages=self.execute(opt_in=True,stage_error=True)
        self.assertFalse(result[0])
        self.assertEqual(result[1],"172.86.105.67")
        self.assertIn(("ingress","172.86.105.67"),events)
        self.assertFalse(any(x[0]=="pool" for x in events))
        self.assertIn("HOLD",messages[-1].args[1])
        self.assertNotIn("hpdef_",str(messages[-1].kwargs.get("reply_markup")))

    def test_forged_stage_identity_does_not_register_edge(self):
        result,events,messages=self.execute(
            opt_in=True,
            stage_payload={"edge_id":"e7","egress_state":"STAGED_NOT_READY",
                           "ingress_ipv4":"10.77.0.99"},
        )
        self.assertFalse(result[0])
        self.assertFalse(any(x[0]=="pool" for x in events))
        self.assertIn("HOLD",messages[-1].args[1])

    def test_protected_mode_rejects_integrated_wizard_before_remote(self):
        result,events,messages=self.execute(opt_in=True,protected="1")
        self.assertEqual(result,(False,None,None))
        self.assertFalse(events)
        self.assertIn("محافظت‌شده",messages[-1].args[1])

    def test_invalid_opt_in_is_denied_before_installation(self):
        with self.assertRaisesRegex(ValueError,"INVALID_EGRESS_STAGE_WIZARD_OPT_IN"):
            self.execute(opt_in="1")


if __name__ == "__main__":
    unittest.main()
