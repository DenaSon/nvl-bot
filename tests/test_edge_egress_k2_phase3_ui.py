"""Real presentation/task helpers with Telegram I/O fakes; no live host claims."""
import ast
import asyncio
import contextlib
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from edge_egress_k2_operator_ui import (
    DisplayStore, Screen, accounts_page, parse_page, reason_text, error_html,
    running_html, running_buttons, detail_button,
)
from edge_egress_k2_migration_inventory import select_migration
from edge_egress_k2_m43_workflow import result_html, confirmation_html
from tests.test_edge_egress_k2_m43_workflow import make
from tests.test_edge_egress_p3_telegram import edge
from edge_egress_p3_telegram import dashboard_buttons,detail_buttons,maintenance_buttons,steps_html

BOT=Path(__file__).resolve().parents[1]/'bot_final_v49-2.py'


class Phase3PresentationTests(unittest.TestCase):
    def test_pages_cover_every_skipped_user_with_reasons_and_bounded_text(self):
        skipped=tuple((f'nvl{i:05d}', 'ACTIVE_SESSIONS_PRESENT' if i%2 else
                       'TARGET_ALREADY_PROTECTED') for i in range(10000))
        screen=Screen(1,20,'e9',kind='skipped',skipped=skipped)
        found=[]
        for page in range(667):
            html,buttons=accounts_page(screen,page)
            self.assertLess(len(html),3900)
            self.assertTrue(all(len(row)<=2 for row in buttons))
            self.assertTrue(all(len(cb.encode())<=64 for row in buttons for _,cb in row))
            found.extend(name for name,_ in skipped[page*15:(page+1)*15] if name in html)
        self.assertEqual(tuple(found),tuple(n for n,_ in skipped))
        with self.assertRaises(ValueError): accounts_page(screen,667)
        self.assertNotIn('ACTIVE_SESSIONS_PRESENT',html)

    def test_page_store_actor_chat_message_edge_and_navigation_boundaries(self):
        store=DisplayStore();first=store.begin(11,22,33,'e9')
        for scope in ((12,22,33,'e9'),(11,23,33,'e9'),(11,22,34,'e9'),(11,22,33,'e8')):
            with self.assertRaises(ValueError):store.get(*scope)
        self.assertIs(store.get(11,22,33,'e9'),first)
        store.navigate(12,22)
        self.assertTrue(store.current(11,22,first))
        store.navigate(11,22)
        self.assertFalse(store.current(11,22,first))
        other=store.begin(11,22,33,'e9')
        self.assertGreater(other.generation,first.generation)
        for i in range(40):store.begin(i,22,33,'e9')
        with self.assertRaises(ValueError):store.get(0,22,33,'e9')

    def test_page_input_and_untrusted_codes_never_become_markup(self):
        self.assertEqual(parse_page('hpeg_list_666_e9'),(666,'e9'))
        for raw in ('hpeg_list_-1_e9','hpeg_list_1000_e9','hpeg_list_1_../e9'):
            with self.assertRaises(ValueError):parse_page(raw)
        self.assertNotIn('<script>',reason_text('<script>'))
        self.assertNotIn('secret',error_html(ValueError('secret root password')))
        self.assertIn('بررسی فنی',error_html(ValueError('RECOVERY_UID_NOT_SETTLED')))
        self.assertNotIn('تغییری',error_html(ValueError('timeout'),executing=True))

    def test_result_partial_deferred_and_unknown_are_distinct(self):
        selection=select_migration('BATCH',('nvl01','nvl02','nvl03'),'e9')
        result={'state':'HOLD','accounts':[{'username':n,'state':state} for n,state in
                zip(selection.usernames,('VERIFIED','HOLD','DEFERRED'))]}
        html=result_html(result,selection=selection)
        self.assertIn('تأییدشده: 1',html)
        self.assertIn('انجام‌نشده: 1',html)
        self.assertIn('نیازمند بررسی: 1',html)
        self.assertIn('انجام نشد',html)
        result['state']='COMPLETED'
        with self.assertRaises(ValueError):result_html(result,selection=selection)
        result['state']='HOLD';result['accounts'][-1]['state']='anything'
        with self.assertRaises(ValueError):result_html(result,selection=selection)

    def test_active_egress_confirmation_is_explicit_not_an_ordinary_transfer(self):
        pending=replace(make(),activate_relay=True)
        html=confirmation_html(pending)
        self.assertIn('تأیید خروجی فعال',html)
        self.assertIn('همهٔ حساب',html)
        self.assertIn('۹۰',html)
        self.assertNotIn(pending.request_id,html)

    def test_new_isolated_edge_uses_existing_pinned_probe_without_joining_legacy_pool(self):
        candidate=edge(pool_active=False)
        self.assertFalse(candidate.can_probe)
        callbacks=[cb for row in detail_buttons(candidate) for _,cb in row]
        self.assertIn('hpeg_p1_probe_fra1',callbacks)
        self.assertNotIn('hpeg_probe_fra1',callbacks)
        self.assertNotIn('hpeg_health_fra1',callbacks)
        unknown=replace(candidate,stage_pin=None)
        self.assertNotIn('hpeg_p1_probe_fra1',[cb for row in detail_buttons(unknown) for _,cb in row])

    def test_primary_actions_are_short_and_maintenance_remains_reachable(self):
        buttons=detail_buttons(edge())
        self.assertEqual([cb for _,cb in buttons[0]],['hpeg_m4_home_fra1','hpeg_relay_fra1'])
        self.assertIn(('⚙️ جزئیات و نگهداری','hpeg_more_fra1'),sum(buttons,[]))
        self.assertIn('hpeg_retire_open_fra1',[cb for row in maintenance_buttons(edge()) for _,cb in row])
        for word in ('F4','PAM','6G','Stage','Phase','UID','JSON','SHA256'):
            self.assertNotIn(word,steps_html())
        source=BOT.read_text()
        hub=source[source.index('def _build_admin_programs_kb'):source.index('_MIGRATION_INPUT_STATES')]
        # CZ-02 deliberately moves the Programs shortcut away from unreleased K2.
        self.assertIn('callback_data="apps_cz_home"', hub)
        self.assertNotIn('callback_data="hpeg_status"', hub)
        self.assertIn('elif d == "hpeg_status"', source)
        pool=source[source.index('async def _show_host_pool'):source.index('async def _show_host_pool')+18000] if 'async def _show_host_pool' in source else ''
        self.assertNotIn('مدیریت Egress',pool)


@unittest.skipIf(sys.version_info < (3,12), "NVL bot requires Python 3.12")
class Phase3BackgroundTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        source=ast.parse(BOT.read_text())
        nodes=[n for n in source.body if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef))
               and n.name in ('_k2_ui_background','_k2_ui_markup')]
        self.tasks=[];self.store=DisplayStore()
        self.ns={'k2_ui_views':self.store,'contextlib':contextlib,
                 'k2_ui_running':running_html,'k2_ui_running_buttons':running_buttons,
                 'k2_ui_error':error_html,'k2_m4_preview_buttons':lambda eid:[],
                 'InlineKeyboardButton':lambda label,callback_data:(label,callback_data),
                 'InlineKeyboardMarkup':lambda rows:rows,
                 'log':SimpleNamespace(warning=lambda *a:None),
                 'spawn_bg_task':lambda coro:self.tasks.append(asyncio.create_task(coro))}
        exec(compile(ast.Module(body=nodes,type_ignores=[]),str(BOT),'exec'),self.ns)
        self.query=SimpleNamespace(from_user=SimpleNamespace(id=11),
            message=SimpleNamespace(chat_id=22,message_id=33),edit_message_text=AsyncMock())
        self.context=SimpleNamespace(user_data={})

    async def test_callback_returns_and_navigation_cannot_be_overwritten_by_late_result(self):
        started=asyncio.Event();finish=asyncio.Event()
        async def worker(screen):
            started.set();await finish.wait();return 'done',[]
        await self.ns['_k2_ui_background'](self.context,self.query,'e9',worker)
        await started.wait()
        self.assertFalse(self.tasks[0].done())
        self.store.navigate(11,22)
        finish.set();await self.tasks[0]
        self.assertEqual(self.query.edit_message_text.await_count,1)
        self.assertEqual(self.context.user_data,{})

    async def test_current_view_gets_final_result_and_preserves_skips_for_same_selection(self):
        selection=make().selection
        previous=self.store.begin(11,22,33,'e9',selection=selection,
            skipped=(('other','ACTIVE_SESSIONS_PRESENT'),))
        async def worker(screen):
            self.assertEqual(screen.skipped,previous.skipped)
            return 'done',[]
        await self.ns['_k2_ui_background'](self.context,self.query,'e9',worker,selection=selection)
        await self.tasks[0]
        self.assertEqual(self.query.edit_message_text.call_args.args[0],'done')

    async def test_uncertain_execution_never_claims_no_change_or_replays(self):
        calls=[]
        async def worker(screen):calls.append('once');raise TimeoutError('root secret')
        await self.ns['_k2_ui_background'](self.context,self.query,'e9',worker,reviewing=False)
        await self.tasks[0]
        html=self.query.edit_message_text.call_args.args[0]
        self.assertIn('تکرار نکنید',html)
        self.assertNotIn('root secret',html)
        self.assertEqual(calls,['once'])



@unittest.skipIf(sys.version_info < (3,12), "NVL bot requires Python 3.12")
class Phase3CallbackRecoveryTests(unittest.IsolatedAsyncioTestCase):
    """Execute the real M4 callback branch, with only Telegram/root I/O replaced."""
    def setUp(self):
        from copy import deepcopy
        from edge_egress_k2_m43_workflow import EphemeralApprovalStore
        from edge_egress_k2_m4_telegram import parse_callback,preview_buttons,M4UIHold
        from edge_egress_k2_m4_status import root_checkpoint_status_html
        tree=ast.parse(BOT.read_text())
        branch=next(n for n in ast.walk(tree) if isinstance(n,ast.If)
            and ast.unparse(n.test)=='d.startswith(\'hpeg_m4_\')')
        branch=deepcopy(branch);branch.orelse=[]
        wrapper=ast.parse('async def callback(update,context):\n query=update.callback_query\n d=query.data\n role=context.user_data.get("role")\n').body[0]
        wrapper.body.append(branch);ast.fix_missing_locations(wrapper)
        self.store=DisplayStore();self.approvals=EphemeralApprovalStore()
        self.selection=make().selection
        reply={'state':'STATUS','edge_id':'e9','wave_state':'UNKNOWN_INFLIGHT',
            'busy':True,'unresolved':True,'users':[{'username':'nvl0555','state':'UNKNOWN'}]}
        self.request=AsyncMock(return_value=reply)
        self.ns={'k2_ui_views':self.store,'k2_m43_approvals':self.approvals,
            'k2_m4_parse_callback':parse_callback,'k2_selected_scope':select_migration,
            'k2_root_direct_flags':SimpleNamespace(K2_ROOT_DIRECT_ENABLED=True),
            'k2_root_direct_client':lambda app:SimpleNamespace(request=self.request),
            'k2_m44_root_status_html':root_checkpoint_status_html,
            'k2_m4_preview_buttons':preview_buttons,'k2_ui_detail_button':detail_button,
            'k2_ui_error':error_html,'M4UIHold':M4UIHold,
            '_k2_ui_markup':lambda rows:rows,'InlineKeyboardMarkup':lambda rows:rows,
            'InlineKeyboardButton':lambda label,callback_data:(label,callback_data),
            'log':SimpleNamespace(warning=lambda *a:None)}
        exec(compile(ast.Module(body=[wrapper],type_ignores=[]),str(BOT),'exec'),self.ns)
        query=SimpleNamespace(data='hpeg_m4_status_e9',message=SimpleNamespace(
            message_id=33,reply_text=AsyncMock()),edit_message_text=AsyncMock())
        self.update=SimpleNamespace(callback_query=query,
            effective_user=SimpleNamespace(id=11),effective_chat=SimpleNamespace(id=22))
        self.context=SimpleNamespace(application=object(),user_data={'role':'admin',
            'k2_m4_last_selection':('SINGLE',('nvl0555',),'e9')})

    async def test_status_after_navigation_uses_original_selection_and_root_readback(self):
        await self.ns['callback'](self.update,self.context)
        self.request.assert_awaited_once_with('STATUS',actor_id=11,chat_id=22,selection=self.selection)
        self.assertIn('نتیجهٔ نهایی ندارد',self.update.callback_query.edit_message_text.call_args.args[0])
        self.assertEqual(self.store.get(11,22,33,'e9').selection,self.selection)

    async def test_non_admin_cannot_read_snapshot_or_root_status(self):
        self.context.user_data['role']='accountant'
        await self.ns['callback'](self.update,self.context)
        self.request.assert_not_awaited()
        self.update.callback_query.edit_message_text.assert_not_awaited()

    async def test_restart_without_selection_reports_expiration_without_a_root_request(self):
        self.context.user_data.pop('k2_m4_last_selection')
        await self.ns['callback'](self.update,self.context)
        self.request.assert_not_awaited()
        self.assertIn('در دسترس نیست',self.update.callback_query.message.reply_text.call_args.args[0])


if __name__=='__main__':unittest.main()
