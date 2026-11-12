"""Regression: /daily_business_report never replies in Telegram groups.

Extract only the handler AST, avoiding import side effects from the monolithic
bot and allowing us to verify the real coroutine with controlled fakes.
"""
import ast
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import unittest


class Message:
    def __init__(self):
        self.replies = []

    async def reply_text(self, text, **kwargs):
        self.replies.append((text, kwargs))


class DailyReportGroupSilenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
        module = ast.parse(source.read_text(encoding="utf-8"))
        node, = (x for x in module.body if isinstance(x, ast.AsyncFunctionDef)
                 and x.name == "cmd_daily_business_report")
        cls.handler_code = compile(
            ast.Module(body=[node], type_ignores=[]), str(source), "exec",
        )

    def make_handler(self, *, auth_called=None):
        if auth_called is None:
            auth_called = []

        def get_superadmins(_db_path):
            auth_called.append(True)
            return [42]

        @contextmanager
        def db_conn():
            yield object()

        finance = SimpleNamespace(
            summarize=lambda conn, day, now=None: {"day": day},
            render_report=lambda report, **kwargs: "✅ REPORT",
        )
        ns = {
            "Update": object,
            "ContextTypes": SimpleNamespace(DEFAULT_TYPE=object),
            "asyncio": asyncio,
            "active_superadmin_ids": get_superadmins,
            "DB_PATH": ":memory:",
            "IRAN_TZ": timezone.utc,
            "datetime": datetime,
            "timedelta": timedelta,
            "timezone": timezone,
            "db_conn": db_conn,
            "nvl_daily_business": finance,
            "fmt_jalali_date_only": lambda day: day.isoformat(),
        }
        exec(self.handler_code, ns)
        return ns["cmd_daily_business_report"]

    def invoke(self, chat_type, user_id, args=None):
        calls = []
        handler = self.make_handler(auth_called=calls)
        msg = Message()
        update = SimpleNamespace(
            effective_chat=SimpleNamespace(type=chat_type),
            effective_user=SimpleNamespace(id=user_id),
            effective_message=msg,
        )
        asyncio.run(handler(update, SimpleNamespace(args=args or [])))
        return msg.replies, calls

    def test_group_nonadmin_is_silent_and_skips_database_check(self):
        replies, checks = self.invoke("supergroup", 1000)
        self.assertEqual(replies, [])
        self.assertEqual(checks, [])

    def test_group_superadmin_is_silent(self):
        replies, checks = self.invoke("group", 42)
        self.assertEqual(replies, [])
        self.assertEqual(checks, [])

    def test_channel_is_silent(self):
        replies, checks = self.invoke("channel", 1000)
        self.assertEqual(replies, [])
        self.assertEqual(checks, [])

    def test_private_nonadmin_retains_denial(self):
        replies, checks = self.invoke("private", 1000)
        self.assertEqual(len(replies), 1)
        self.assertIn("فقط سوپراَدمین مجاز است", replies[0][0])
        self.assertEqual(len(checks), 1)

    def test_private_superadmin_still_gets_report(self):
        replies, checks = self.invoke("private", 42, ["today"])
        self.assertEqual(replies[0][0], "✅ REPORT")
        self.assertEqual(len(replies), 1)
        self.assertEqual(len(checks), 1)


if __name__ == "__main__":
    unittest.main()
