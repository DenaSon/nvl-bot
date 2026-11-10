"""Offline Telegram markup regression tests for the NVL agent menu.

Extract only the pure/read-only UI handlers from the bot; no live bot import,
Telegram API calls, DB access, SSH, or service changes are performed.
"""
import ast
import asyncio
from pathlib import Path
from types import SimpleNamespace
import unittest


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"


class Button:
    def __init__(self, text, *, callback_data):
        self.text = text
        self.callback_data = callback_data


class Markup:
    def __init__(self, rows):
        self.inline_keyboard = rows


class Target:
    def __init__(self):
        self.text = None
        self.markup = None

    async def edit_message_text(self, text, *, reply_markup=None, parse_mode=None):
        self.text = text
        self.markup = reply_markup

    async def reply_text(self, text, *, reply_markup=None, parse_mode=None):
        await self.edit_message_text(text, reply_markup=reply_markup,
                                     parse_mode=parse_mode)


def compile_handlers():
    tree = ast.parse(BOT.read_text(encoding="utf-8"))
    handlers = {
        "_show_users_hub", "_show_agent_v2ray_types", "_show_users_panel"
    }
    wanted = [n for n in tree.body
              if isinstance(n, ast.AsyncFunctionDef) and n.name in handlers]
    assert {n.name for n in wanted} == handlers
    globals_ = {
        "InlineKeyboardButton": Button,
        "InlineKeyboardMarkup": Markup,
        "is_auth": lambda ctx: ctx.user_data.get("logged_in"),
        "_agent_lifecycle_access": lambda aid: False,
        "asyncio": asyncio,
        "_db_count_users_by_type": lambda typ, owner: 1,
        "_db_get_users_with_agents_by_type":
            lambda typ, owner, limit, offset: [("owned", 8, "create", "Customer")],
    }
    exec(compile(ast.Module(body=wanted, type_ignores=[]), str(BOT), "exec"),
         globals_)
    return globals_


def callbacks(target):
    return [[button.callback_data for button in row]
            for row in target.markup.inline_keyboard]


class ResellerMenuTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.handlers = compile_handlers()
        self.agent = SimpleNamespace(user_data={
            "logged_in": True, "role": "agent", "agent_id": 8,
        })

    async def test_agent_hub_has_three_buttons_on_one_row(self):
        target = Target()
        await self.handlers["_show_users_hub"](target, self.agent)
        self.assertEqual(callbacks(target)[0],
                         ["umanage_ssh", "ag_v2ray_types", "ag_users_search"])
        self.assertNotIn("umanage_v2ray", callbacks(target)[0])
        self.assertNotIn("umanage_v2ray_vol", callbacks(target)[0])

    async def test_nested_v2ray_types_and_return(self):
        target = Target()
        await self.handlers["_show_agent_v2ray_types"](target, self.agent)
        self.assertEqual(callbacks(target)[0],
                         ["umanage_v2ray", "umanage_v2ray_vol"])
        self.assertEqual(callbacks(target)[1], ["users_hub"])

    async def test_nested_menu_denied_to_non_reseller(self):
        self.agent.user_data["role"] = "accountant"
        target = Target()
        await self.handlers["_show_agent_v2ray_types"](target, self.agent)
        self.assertIn("مجاز نیست", target.text)
        self.assertIsNone(target.markup)

    async def test_legacy_admin_hub_keeps_direct_services(self):
        self.agent.user_data["role"] = "admin"
        target = Target()
        await self.handlers["_show_users_hub"](target, self.agent)
        self.assertEqual(callbacks(target)[0], ["umanage_ssh"])
        self.assertEqual(callbacks(target)[1], ["umanage_v2ray"])
        self.assertEqual(callbacks(target)[2], ["umanage_v2ray_vol"])

    async def test_v2ray_list_returns_to_v2ray_submenu(self):
        target = Target()
        update = SimpleNamespace(callback_query=target)
        for typ, back in (("ssh", "users_hub"),
                          ("v2ray", "ag_v2ray_types"),
                          ("v2ray_vol", "ag_v2ray_types")):
            with self.subTest(service_type=typ):
                self.agent.user_data["manage_type"] = typ
                await self.handlers["_show_users_panel"](update, self.agent)
                self.assertIn([back], callbacks(target))


if __name__ == "__main__":
    unittest.main()
