"""Rich daily business renderer/transport contract tests.

No production token, Telegram network call, or database writes.
"""
import ast
import asyncio
from contextlib import contextmanager
from datetime import datetime, timedelta
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
import unittest

import nvl_daily_business as business
from cloudzy_rich_transport import RichBotAPI


def sample(*, partial=False, purchase=3100000):
    return {
        "day": "2026-11-12", "partial": partial,
        "buyers": 9, "topuppers": 4,
        "counts": {
            "AGENT_CREATED": 2, "BANK_TOPUP": 3, "MANUAL_TOPUP": 1,
            "PURCHASE": 27, "PURCHASE_REFUND": 1,
        },
        "totals": {
            "AGENT_CREATED": Decimal(0),
            "BANK_TOPUP": Decimal(5400000),
            "MANUAL_TOPUP": Decimal(600000),
            "PURCHASE": Decimal(purchase + 100000),
            "PURCHASE_REFUND": Decimal(100000),
        },
        "wallet_topups": Decimal(6000000),
        "net_purchases": Decimal(purchase),
        "central_bank": Decimal(4200000),
        "partner_bank": Decimal(1200000),
    }


def text_content(block):
    if isinstance(block, str):
        return block
    if isinstance(block, list):
        return "".join(text_content(item) for item in block)
    if not isinstance(block, dict):
        return ""
    return (
        text_content(block.get("text", "")) +
        text_content(block.get("summary", "")) +
        "".join(text_content(row) for row in block.get("cells", []) for cell in row) +
        text_content(block.get("blocks", []))
    )


class RichRendererTests(unittest.TestCase):
    def test_compact_table_and_collapsed_details(self):
        report = business.render_rich_report(sample(), label="۲۱ آبان ۱۴۰۵")
        self.assertEqual(set(report), {"blocks", "is_rtl", "skip_entity_detection"})
        self.assertTrue(report["is_rtl"])
        self.assertTrue(report["skip_entity_detection"])
        blocks = report["blocks"]
        self.assertEqual([b["type"] for b in blocks],
                         ["heading", "paragraph", "table", "details", "footer"])
        overview = blocks[2]
        self.assertTrue(overview["is_compact"])
        self.assertEqual(len(overview["cells"]), 6)
        self.assertTrue(all(len(row) == 2 for row in overview["cells"]))
        self.assertEqual(overview["cells"][0][0]["text"], "👥 نماینده خریدار")
        self.assertEqual(overview["cells"][0][1]["text"]["text"], "9 نفر")
        self.assertEqual(overview["cells"][-1][1]["text"]["text"], "4,200,000 تومان")
        details = blocks[3]
        self.assertEqual(details["type"], "details")
        self.assertNotIn("is_open", details)
        self.assertTrue(details["blocks"][0]["is_compact"])
        self.assertEqual(len(details["blocks"][0]["cells"]), 6)
        self.assertIn("1,200,000 تومان", text_content(details))
        self.assertIn("شارژ دستی الزاماً دریافت وجه", text_content(details))
        self.assertIn("۲۱ آبان ۱۴۰۵", text_content(report["blocks"]))

    def test_partial_warning_visible_and_no_comparison(self):
        report = business.render_rich_report(
            sample(partial=True), previous=sample(purchase=2800000)
        )
        self.assertEqual(report["blocks"][2]["type"], "paragraph")
        self.assertIn("داده‌های ناقص", report["blocks"][2]["text"])
        self.assertNotIn("📈 خالص خرید نسبت به دیروز",
                         text_content(report["blocks"]))
        self.assertEqual(report["blocks"][3]["type"], "table")

    def test_comparison_only_for_closed_complete_days(self):
        r = business.render_rich_report(
            sample(), previous=sample(purchase=3000000)
        )
        self.assertIn("⬆️ 3.3٪", text_content(r["blocks"]))
        preview = business.render_rich_report(
            sample(), previous=sample(purchase=3000000), preview=True
        )
        self.assertNotIn("⬆️", text_content(preview["blocks"]))
        old_partial = business.render_rich_report(
            sample(), previous=sample(partial=True)
        )
        self.assertNotIn("⬆️", text_content(old_partial["blocks"]))

    def test_is_pure_and_does_not_change_financial_values(self):
        source = sample()
        before = (source["net_purchases"], source["central_bank"],
                  source["wallet_topups"], source["totals"].copy(),
                  source["counts"].copy())
        business.render_rich_report(source, preview=True)
        self.assertEqual(before, (source["net_purchases"], source["central_bank"],
                                  source["wallet_topups"], source["totals"],
                                  source["counts"]))

    def test_existing_rich_transport_send_method_exact_payload(self):
        calls = []

        def transport(method, payload):
            calls.append((method, payload))
            return {"message_id": 418}

        rich = business.render_rich_report(sample())
        sent = asyncio.run(
            RichBotAPI("fake:token", transport=transport).send(
                chat_id=-1004495255355, rich_message=rich
            )
        )
        self.assertEqual(sent, 418)
        self.assertEqual(calls, [("sendRichMessage", {
            "chat_id": -1004495255355, "rich_message": rich,
            "protect_content": True,
        })])


class ScheduledRichSendTests(unittest.TestCase):
    def test_scheduler_uses_rich_transport_and_acknowledges_message_id(self):
        source = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        fn, = (node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)
               and node.name == "_daily_business_report_loop")
        module = compile(ast.Module(body=[fn], type_ignores=[]), str(source), "exec")
        claims, confirmations, posts = [], [], []
        report = business.render_rich_report(sample())
        finance = SimpleNamespace(
            claim_due_day=lambda conn, send_time: claims.append(send_time) or "2026-11-12",
            summarize=lambda conn, day: sample(),
            render_rich_report=lambda *args, **kwargs: report,
            finish_delivery=lambda conn, day, **kwargs: confirmations.append((day, kwargs)),
        )

        @contextmanager
        def db_conn():
            yield object()

        class FakeRichAPI:
            def __init__(self, token):
                assert token == "fake-bot-token"

            async def send(self, *, chat_id, rich_message):
                posts.append((chat_id, rich_message))
                return 54

        async def cancel_after_one_cycle(_seconds):
            raise asyncio.CancelledError()

        log = SimpleNamespace(
            info=lambda *args, **kwargs: None,
            exception=lambda *args, **kwargs: None,
        )
        ns = {
            "asyncio": SimpleNamespace(
                to_thread=asyncio.to_thread, sleep=cancel_after_one_cycle,
                CancelledError=asyncio.CancelledError
            ),
            "os": SimpleNamespace(environ={
                "NVL_DAILY_FINANCE_REPORT_CHAT_ID": "-1004495255355",
                "NVL_DAILY_FINANCE_REPORT_TIME": "00:05",
                "NVL_DAILY_FINANCE_REPORT_TZ": "Asia/Tehran",
            }),
            "db_conn": db_conn, "nvl_daily_business": finance,
            "NVLDailyRichBotAPI": FakeRichAPI,
            "datetime": datetime, "timedelta": timedelta,
            "fmt_jalali_date_only": lambda day: "۲۱ آبان",
            "log": log,
        }
        exec(module, ns)
        app = SimpleNamespace(bot=SimpleNamespace(token="fake-bot-token"))

        async def run_one_round():
            try:
                await ns["_daily_business_report_loop"](app)
            except asyncio.CancelledError:
                return
            self.fail("scheduler did not stop after single cycle")

        asyncio.run(run_one_round())
        self.assertEqual(claims, ["00:05"])
        self.assertEqual(posts, [(-1004495255355, report)])
        self.assertEqual(confirmations, [("2026-11-12", {"message_id": 54})])


if __name__ == "__main__":
    unittest.main()
