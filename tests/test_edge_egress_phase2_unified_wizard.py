"""K2 Phase 2 final unified Wizard: real installer opt-in, no parallel wizard.

All bot functions are AST-extracted with fake I/O. No VPS, Core or network.
"""
import asyncio
import sqlite3
import sys
import types
import unittest
from unittest.mock import AsyncMock, patch

from edge_egress_phase2_wizard import new_edge_prompt, staged_edge_result
from edge_egress_entrypoints import (
    classify_edge_callback, EdgeOperation, evaluate_manual_edge_gate,
)
from edge_egress_v1_console import EgressConsoleHold
from edge_egress_k2_phase1_wizard import normalize_k2_customer_port

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
        # Narrow mode-1 exemption: only admin's existing integrated wizard,
        # never legacy registration, relay switch, user transfer or Failover.
        self.assertIn('d == "hpeg_wizard" and role == \'admin\'',body)
        self.assertIn("k2_isolated_wizard_input",body)
        self.assertIn("state in ('EDGE_NEW_IP', 'EDGE_NEW_ROOTPASS', 'EDGE_NEW_PORT')",body)
        self.assertIn("role == 'admin'",body)
        self.assertIn("and not k2_isolated_wizard_input",body)
        self.assertNotIn("_db_set_all_accounts_host",body[body.index(
            'elif d in ("hp_addedge", "hpeg_wizard"):'):body.index(
            'elif d.startswith(("hpdef_migrate_", "hpdefmig_yes_", "hpdef_"))')])

@unittest.skipIf(sys.version_info < (3,12), "NVL bot requires Python 3.12")
class IntegratedWizardFunctionTests(unittest.TestCase):
    def execute(self, *, opt_in, global_toggle="0", protected="0",
                stage_error=None, stage_payload=None, customer_port=2252,
                native=False,transport_error=False):
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
            events.append(("stage_port",kwargs.get("customer_port")))
            if stage_error:
                raise ValueError("SIMULATED_STAGE_HOLD")
            return stage_payload if stage_payload is not None else {
                "edge_id":"e7",
                "egress_state":"STAGED_NOT_READY",
                "ingress_ipv4":"10.77.0.7",
            }
        def fake_sync(*args, **kwargs):
            events.append(("ingress",args[0]))
            events.append(("sync_port",args[2]))
            return True, "", outcome.copy()
        fake_module=types.SimpleNamespace(onboard_after_ingress=stage)
        async def prepare_edge(*args,**kwargs):
            events.append(('automatic_transport',args[1]))
            if transport_error:
                raise ValueError('synthetic transport failure')
            return {'observed_ipv4':'172.86.105.67','customer_ready':False}
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
            "_k2_ui_markup":lambda rows:rows,
            "db_conn":lambda:None,
            "assert_isolated_new_edge_candidate":lambda *args:events.append(('isolated_check',)),
            "normalize_k2_customer_port":normalize_k2_customer_port,
            "k2_native_operations_registered":lambda:native,
            "k2_native_prepare_edge":prepare_edge,
            "sqlite3":sqlite3,
            "K2WizardHold":__import__("edge_egress_k2_phase1_wizard",fromlist=["K2WizardHold"]).K2WizardHold,
            "InlineKeyboardButton":lambda label,callback_data:(label,callback_data),
            "InlineKeyboardMarkup":lambda rows:rows,
            "esc":lambda s:s,
            "log":types.SimpleNamespace(exception=lambda *a,**kw:None,warning=lambda *a,**kw:None),
        })
        with patch.dict(sys.modules,{"edge_egress_v1_onboarding":fake_module}):
            result=asyncio.run(fn(
                "172.86.105.67","DO_NOT_LOG",customer_port,
                "edge-172-86-105-67",5000,app,
                egress_stage_requested=opt_in,
            ))
        return result,events,bot.send_message.await_args_list

    def test_new_wizard_stages_even_when_global_flag_off(self):
        result,events,messages=self.execute(opt_in=True,global_toggle="0")
        self.assertTrue(result[0])
        self.assertIn(("ingress","172.86.105.67"),events)
        self.assertIn(("stage","172.86.105.67","10.77.0.7"),events)
        self.assertFalse(any(event[0] in ("pool","setting_write","pool_active")
                             for event in events))
        self.assertIn("آماده",messages[-1].args[1])
        self.assertNotIn("DO_NOT_LOG",messages[-1].args[1])
        rows=messages[-1].kwargs["reply_markup"]
        self.assertIn("hpeg_edge_e7",str(rows))
        self.assertIn("hpeg_m4_home_e7",str(rows))
        self.assertNotIn("hpdef_",str(rows))
        self.assertFalse(any(event[0]=="setting_write" and
                             event[1][0]=="edge_egress_v1_onboard_enabled"
                             for event in events))

    def test_string_telegram_port_passes_k2_and_pins_customer_port(self):
        result, events, _ = self.execute(opt_in=True, customer_port="2252")
        self.assertTrue(result[0])
        self.assertIn(("sync_port", "2252"), events)
        self.assertIn(("stage_port", 2252), events)

    def test_native_wizard_activates_only_after_final_isolated_candidate_check(self):
        result,events,messages=self.execute(opt_in=True,native=True)
        self.assertTrue(result[0])
        self.assertEqual(events[-1],('automatic_transport','e7'))
        self.assertEqual(sum(e[0]=='isolated_check' for e in events),2)
        self.assertFalse(result[2]['automatic_transport']['customer_ready'])
        self.assertIn('آماده بررسی انتقال',messages[-1].args[1])

    def test_native_transport_failure_does_not_repeat_install_or_admit_customer(self):
        result,events,messages=self.execute(opt_in=True,native=True,transport_error=True)
        self.assertFalse(result[0])
        self.assertEqual(sum(e[0]=='ingress' for e in events),1)
        self.assertFalse(any(e[0] in ('pool','setting_write') for e in events))
        self.assertIn('نصب را تکرار نکنید',messages[-1].args[1])

    def test_string_port_does_not_change_legacy_installer_contract(self):
        result, events, _ = self.execute(opt_in=False, customer_port="2252")
        self.assertTrue(result[0])
        self.assertIn(("sync_port", "2252"), events)
        self.assertNotIn(("stage_port", 2252), events)

    def test_invalid_k2_port_holds_before_remote_install(self):
        result, events, messages = self.execute(opt_in=True, customer_port="65536")
        self.assertFalse(result[0])
        self.assertFalse(any(x[0] in ("ingress", "stage") for x in events))
        self.assertIn("قابل آماده", messages[-1].args[1])

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
        self.assertIn("آماده",messages[-1].args[1])
        self.assertNotIn("hpdef_",str(messages[-1].kwargs.get("reply_markup")))

    def test_forged_stage_identity_does_not_register_edge(self):
        result,events,messages=self.execute(
            opt_in=True,
            stage_payload={"edge_id":"e7","egress_state":"STAGED_NOT_READY",
                           "ingress_ipv4":"10.77.0.99"},
        )
        self.assertFalse(result[0])
        self.assertFalse(any(x[0]=="pool" for x in events))
        self.assertIn("آماده",messages[-1].args[1])

    def test_protected_mode_can_stage_new_edge_without_moving_customers(self):
        result,events,messages=self.execute(opt_in=True,protected="1")
        self.assertTrue(result[0])
        self.assertIn(("stage","172.86.105.67","10.77.0.7"),events)
        self.assertFalse(any(event[0] in ("pool","setting_write","pool_active")
                             for event in events))
        self.assertIn("آماده",messages[-1].args[1])

    def test_invalid_opt_in_is_denied_before_installation(self):
        with self.assertRaisesRegex(ValueError,"INVALID_EGRESS_STAGE_WIZARD_OPT_IN"):
            self.execute(opt_in="1")


if __name__ == "__main__":
    unittest.main()
