"""Read-only SQL regression tests for NVL's existing reseller user list.

Extract the exact DB functions from the production source without importing the
live Telegram bot (which initializes infrastructure and runtime dependencies).
"""
import ast
from contextlib import contextmanager
from pathlib import Path
import sqlite3
import unittest


BOT = Path(__file__).resolve().parents[1] / "bot_final_v49-2.py"
FUNCTIONS = {
    "_db_get_users_with_agents_by_type",
    "_db_count_users_by_type",
    "_db_search_users",
}


class AgentListSqlTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.execute(
            "CREATE TABLE ssh_accounts (username TEXT PRIMARY KEY, agent_id INTEGER, "
            "status TEXT, service_type TEXT, creation_date TEXT, customer_name TEXT)"
        )
        self.conn.execute(
            "CREATE TABLE activity_log (username TEXT, action TEXT, created_at TEXT)"
        )
        for i, owner in enumerate([4, 5, 4, 4, 5, 4, 4, 4, 4, 4, 4, 4, 4]):
            self.conn.execute(
                "INSERT INTO ssh_accounts VALUES (?, ?, ?, 'ssh', ?, ?)",
                (f"u{i:02d}", owner, "🟢 فعال", f"2026-11-{i+1:02d}", f"Customer {i}"),
            )
        self.conn.execute(
            "INSERT INTO ssh_accounts VALUES ('pending', 4, '⏳ درحال ساخت', 'ssh', '2026-11-11', 'No')"
        )
        self.conn.execute(
            "INSERT INTO ssh_accounts VALUES ('vol', 4, '🟢 فعال', 'v2ray_vol', '2026-11-11', 'Vol')"
        )
        self.conn.execute(
            "INSERT INTO activity_log VALUES ('u00', 'extend', '2026-11-20 00:00:00')"
        )

        @contextmanager
        def local_db_conn():
            yield self.conn

        tree = ast.parse(BOT.read_text(encoding="utf-8"))
        targets = [node for node in tree.body
                   if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
        self.assertEqual({n.name for n in targets}, FUNCTIONS)
        ns = {"db_conn": local_db_conn}
        exec(compile(ast.Module(body=targets, type_ignores=[]), str(BOT), "exec"), ns)
        self.func = ns

    def tearDown(self):
        self.conn.close()

    def test_reseller_query_scopes_before_pagination(self):
        count = self.func["_db_count_users_by_type"]("ssh", 4)
        self.assertEqual(count, 11)
        first = self.func["_db_get_users_with_agents_by_type"]("ssh", 4, 10, 0)
        second = self.func["_db_get_users_with_agents_by_type"]("ssh", 4, 10, 10)
        self.assertEqual([len(first), len(second)], [10, 1])
        self.assertTrue(all(owner == 4 for _, owner, _, _ in first + second))
        self.assertEqual(first[0][0], "u00")  # latest extension first
        self.assertTrue(set(x[0] for x in first).isdisjoint(x[0] for x in second))

    def test_unfiltered_admin_list_and_reseller_search(self):
        self.assertEqual(self.func["_db_count_users_by_type"]("ssh"), 13)
        self.assertEqual(len(self.func["_db_get_users_with_agents_by_type"]("ssh", None, 10, 0)), 10)
        self.assertEqual(len(self.func["_db_search_users"]("u", 4)), 11)
        self.assertEqual(len(self.func["_db_search_users"]("u", 5)), 2)
        self.assertEqual(len(self.func["_db_search_users"]("u", None)), 13)
        self.assertNotIn(("pending",), self.func["_db_search_users"]("pending", 4))

    def test_username_search_is_literal_bounded_and_owner_scoped(self):
        self.conn.execute(
            "INSERT INTO ssh_accounts VALUES ('agent_00', 4, '🟢 فعال', "
            "'v2ray_vol', '2026-11-20', 'Sample')"
        )
        self.conn.execute(
            "INSERT INTO ssh_accounts VALUES ('agent_01', 5, '🟢 فعال', "
            "'v2ray', '2026-11-20', 'Not Mine')"
        )
        search = self.func["_db_search_users"]
        self.assertEqual(search("_", 4), [("agent_00",)])
        self.assertEqual(search("%", 4), [])  # '%' is no longer a wildcard
        self.assertEqual(search("AGENT_", 4), [("agent_00",)])
        self.assertEqual(search("agent_", 5), [("agent_01",)])
        self.assertEqual(len(search("u", 4, 3)), 3)
        self.assertTrue(all(name != "agent_01" for name, in search("agent", 4, 30)))
        with self.assertRaises(ValueError):
            search("u", 4, 0)

    def test_invalid_page_rejected(self):
        with self.assertRaises(ValueError):
            self.func["_db_get_users_with_agents_by_type"]("ssh", 4, 10, -10)


if __name__ == "__main__":
    unittest.main()
