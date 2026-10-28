"""Phase 3: no-network purchase classification and exact provider reconciliation."""
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import sqlite3
import unittest

from cloudzy_cz05_catalog import CatalogHold
from cloudzy_purchase_guard import (
    PurchaseHold, classify_preflight, classify_create,
    exact_existing_server, require_base_hourly_ceiling,
    inspect_receipt, main,
)
from cloudzy_service import CloudzyAPIError, CloudzyError, CloudzyUncertainError


class PurchaseGuardTests(unittest.TestCase):
    def test_catalog_codes_are_precise_and_do_not_repeat_post(self):
        for code in ("AVAILABILITY_STALE", "PLAN_STOCK_OR_HOURLY_PRICE_CHANGED",
                     "AVAILABILITY_REGION_MISMATCH", "AVAILABILITY_DUPLICATE_PLAN"):
            with self.subTest(code=code):
                issue = classify_preflight(CatalogHold(code))
                self.assertEqual(issue.code, code)
                self.assertEqual(issue.retry_class, "NEW_PREFLIGHT_ONLY")
                self.assertIn("خریدی ارسال نشده", issue.next_action_fa)

    def test_provider_get_http_categories_are_not_stock_failures(self):
        for status, fragment in ((401, "دسترسی"), (403, "دسترسی"),
                                 (429, "محدود"), (500, "در دسترس")):
            with self.subTest(status=status):
                issue = classify_preflight(CloudzyAPIError(status, "provider PRIVATE"))
                self.assertEqual(issue.code, f"CLOUDZY_PREFLIGHT_HTTP_{status}")
                self.assertNotIn("PRIVATE", str(issue))
                self.assertIn(fragment, issue.title_fa)

    def test_generic_get_failures_remain_retryable_without_charge(self):
        issue = classify_preflight(CloudzyError("password=123"))
        self.assertEqual(issue.code, "CLOUDZY_PREFLIGHT_READ_FAILED")
        self.assertNotIn("password", str(issue))
        self.assertEqual(issue.retry_class, "READ_RETRY")

    def test_uncertain_post_distinguished_from_definite_fourxx(self):
        uncertain = classify_create(
            CloudzyUncertainError("POST /services", idempotency_key="secret"))
        self.assertEqual(uncertain.retry_class, "RECONCILE_FIRST")
        self.assertEqual(uncertain.code, "CREATE_RESULT_UNCERTAIN")
        self.assertNotIn("secret", str(uncertain))
        for status in (401, 402, 403, 422):
            issue = classify_create(CloudzyAPIError(status, "private secret"))
            self.assertEqual(issue.retry_class, "DEFINITE_REJECTION")
            self.assertEqual(issue.code, f"CLOUDZY_CREATE_HTTP_{status}")

    def test_ceiling_only_approved_base_price_and_is_strict(self):
        require_base_hourly_ceiling(11, None)
        require_base_hourly_ceiling(11, "")
        require_base_hourly_ceiling(11, "11")
        for price, ceiling, expected in (
            (12, "11", "BASE_HOURLY_CEILING_EXCEEDED"),
            (1, "0", "BASE_HOURLY_CEILING_EXCEEDED"),
            (1, "bad", "BASE_HOURLY_CEILING_CONFIG_INVALID"),
            (1, "-2", "BASE_HOURLY_CEILING_CONFIG_INVALID"),
            (0, "11", "INVALID_APPROVED_BASE_PRICE"),
        ):
            with self.subTest(price=price, ceiling=ceiling):
                with self.assertRaisesRegex(PurchaseHold, expected):
                    require_base_hourly_ceiling(price, ceiling)

    def test_exact_hostname_and_provider_id_must_match(self):
        valid = [{"hostname": "nvl-edge-deadbeefcafe", "id": "server-1"}]
        self.assertEqual(exact_existing_server(
            valid, hostname="nvl-edge-deadbeefcafe"), "server-1")
        self.assertEqual(exact_existing_server(
            [{"data": {"service": valid[0]}}], hostname="nvl-edge-deadbeefcafe",
            provider_id="server-1"), "server-1")
        with self.assertRaisesRegex(PurchaseHold, "PROVIDER_CREATION_UNPROVEN"):
            exact_existing_server([], hostname="nvl-edge-deadbeefcafe")
        with self.assertRaisesRegex(PurchaseHold, "PROVIDER_HOSTNAME_AMBIGUOUS"):
            exact_existing_server(valid * 2, hostname="nvl-edge-deadbeefcafe")
        with self.assertRaisesRegex(PurchaseHold, "PROVIDER_ID_CHANGED"):
            exact_existing_server(valid, hostname="nvl-edge-deadbeefcafe",
                                  provider_id="different-vps")
        with self.assertRaisesRegex(PurchaseHold, "PROVIDER_ID_UNVERIFIED"):
            exact_existing_server([{"hostname": "nvl-edge-deadbeefcafe"}],
                                  hostname="nvl-edge-deadbeefcafe")
        with self.assertRaisesRegex(PurchaseHold, "PROVIDER_INVENTORY_UNVERIFIED"):
            exact_existing_server(None, hostname="nvl-edge-deadbeefcafe")
        with self.assertRaisesRegex(PurchaseHold, "INVALID_OPERATION_HOSTNAME"):
            exact_existing_server(valid, hostname="different-ops-host")

    def test_unknown_ipv4_never_counts_as_server_identity(self):
        with self.assertRaisesRegex(PurchaseHold, "PROVIDER_ID_UNVERIFIED"):
            exact_existing_server(
                [{"hostname": "nvl-edge-deadbeefcafe", "primaryIpv4": "203.0.113.99"}],
                hostname="nvl-edge-deadbeefcafe")

    def test_cli_db_readonly_no_provider_calls_no_journal_writes(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "fixture.sqlite"
            with sqlite3.connect(path) as db:
                db.execute("""CREATE TABLE cloudzy_edge_operations(
                    id TEXT,status TEXT,hostname TEXT,provider_server_id TEXT,
                    region TEXT,plan_id TEXT,billing_cycle TEXT,
                    price_cents INTEGER,hold_reason TEXT,created_at INTEGER
                )""")
                db.execute(
                    "INSERT INTO cloudzy_edge_operations VALUES "
                    "('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','CREATE_UNCERTAIN',"
                    "'nvl-edge-deadbeefcafe',NULL,'DE-Frankfurt','p1',"
                    "'hourly',3,'CREATE_RESULT_UNCERTAIN',1000)")
            before = path.read_bytes()
            buf = StringIO()
            with patch("cloudzy_service.CloudzyService") as fake, redirect_stdout(buf):
                rc = main(["--db", str(path)])
            self.assertEqual(rc, 0)
            self.assertNotIn("deadbeefcafe", buf.getvalue())
            self.assertIn("CLOUDZY_LIVE_READ=SKIPPED", buf.getvalue())
            fake.assert_not_called()
            self.assertEqual(before, path.read_bytes())

    def test_live_get_is_only_inventory_and_reports_ambiguous_absence(self):
        with TemporaryDirectory() as d:
            path = Path(d) / "fixture.sqlite"
            with sqlite3.connect(path) as db:
                db.execute("""CREATE TABLE cloudzy_edge_operations(
                    id TEXT,status TEXT,hostname TEXT,provider_server_id TEXT,
                    region TEXT,plan_id TEXT,billing_cycle TEXT,
                    price_cents INTEGER,hold_reason TEXT,created_at INTEGER
                )""")
                db.execute(
                    "INSERT INTO cloudzy_edge_operations VALUES "
                    "('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','CREATE_UNCERTAIN',"
                    "'nvl-edge-deadbeefcafe',NULL,'DE-Frankfurt','p1',"
                    "'hourly',3,'CREATE_RESULT_UNCERTAIN',1000)")
            with patch.dict("os.environ", {"CLOUDZY_TOKEN": "test"}, clear=False):
                with patch("cloudzy_service.CloudzyService") as fake:
                    fake.return_value.list_servers.return_value = []
                    with redirect_stdout(StringIO()):
                        rc = main(["--db", str(path), "--live-read"])
                    self.assertEqual(rc, 1)
                    fake.return_value.list_servers.assert_called_once_with()
                    fake.return_value.create_server.assert_not_called()
                    fake.return_value.delete_server.assert_not_called()
                    fake.return_value.get_server.assert_not_called()


if __name__ == "__main__":
    unittest.main()
