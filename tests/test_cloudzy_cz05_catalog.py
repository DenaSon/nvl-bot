"""CZ-05 hermetic stock-policy tests; no Cloudzy network or purchases."""
from datetime import datetime, timedelta, timezone
import unittest

from cloudzy_cz05_catalog import (
    CatalogHold, eligible_offers, preferred_regions,
)


class CatalogPolicyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.region = "DE-Frankfurt"
        def plan(pid, slug, kind, *, scope="regional_catalog_base",
                 price_region="DE-Frankfurt", amount=1, currency="USD"):
            return {
                "id": pid, "slug": slug, "name": slug, "instanceType": kind,
                "priceScope": scope,
                "price": {"billingCycle": "hourly", "regionId": price_region,
                          "amount": amount, "monthlyEquivCents": 9995,
                          "currency": currency}
            }
        self.catalog = {
            "region": self.region, "billingCycle": "hourly",
            "plans": [
                plan("p1", "vps-1gb", "default", amount=1),
                plan("p2", "vps-2gb", "default", amount=2),
                plan("p3", "hf-1gb", "cpu-optimized"),
                plan("p4", "gpu-a100", "gpu-provided"),
                plan("p5", "vps-custom", "default"),
                plan("p6", "vps-4gb", "default", scope="general_catalog_base"),
                plan("p7", "vps-8gb", "default", price_region=""),
                plan("p8", "vps-12gb", "default", amount=0),
                plan("p9", "vps-16gb", "default", currency="EUR"),
            ]
        }
        self.availability = {
            "region": self.region, "checkedAt": self.now.isoformat(),
            "plans": [{"planId": f"p{i}", "available": True, "fitsOnNodes": 2,
                       "source": "live"} for i in range(1, 10)]
        }

    def eligible(self):
        return eligible_offers(self.catalog, self.availability,
                               region=self.region, now=self.now.timestamp())

    def test_only_live_regular_standard_regional_hourly_amount(self):
        self.assertEqual([x[:3] for x in self.eligible()],
                         [("p1", "vps-1gb", 1), ("p2", "vps-2gb", 2)])
        self.assertNotEqual(self.eligible()[0][2], 9995)

    def test_missing_stale_or_estimated_stock_fails_closed(self):
        self.availability["plans"][0]["available"] = False
        self.availability["plans"][1]["fitsOnNodes"] = 0
        self.assertEqual(self.eligible(), [])
        self.availability["plans"][0]["available"] = True
        self.availability["plans"][0]["source"] = "estimate"
        self.assertEqual(self.eligible(), [])
        self.availability["checkedAt"] = (self.now - timedelta(minutes=3)).isoformat()
        with self.assertRaises(CatalogHold):
            self.eligible()

    def test_invalid_region_cycle_duplicate_malformed_and_future_timestamp(self):
        self.availability["region"] = "NL-Amsterdam-DC2"
        with self.assertRaises(CatalogHold):
            self.eligible()
        self.availability["region"] = self.region
        self.catalog["billingCycle"] = "monthly"
        with self.assertRaises(CatalogHold):
            self.eligible()
        self.catalog["billingCycle"] = "hourly"
        self.availability["plans"].append(dict(self.availability["plans"][0]))
        with self.assertRaises(CatalogHold):
            self.eligible()
        self.availability["plans"].pop()
        self.availability["checkedAt"] = "invalid"
        with self.assertRaises(CatalogHold):
            self.eligible()
        self.availability["checkedAt"] = (self.now + timedelta(minutes=5)).isoformat()
        with self.assertRaises(CatalogHold):
            self.eligible()

    def test_exact_preference_and_region_state(self):
        regions = [
            {"id": "SG-Singapore-DC2", "name": "Singapore", "isActive": True},
            {"id": "DTX", "name": "Dallas", "isActive": True},
            {"id": "NL-Amsterdam-DC2", "name": "Amsterdam", "isActive": True},
            {"id": "DE-Frankfurt", "name": "Frankfurt", "isActive": True},
            {"id": "CH-Switzerland", "name": "Bern", "isActive": True, "isOutOfStock": True},
            {"id": "UK-London", "name": "London", "isActive": True},
            {"id": "US-Utah", "name": "Utah", "isActive": True, "isHidden": True},
            {"id": "UAE-Dubai", "name": "Dubai", "isActive": True},
        ]
        self.assertEqual([x[0] for x in preferred_regions(regions)], [
            "DE-Frankfurt", "NL-Amsterdam-DC2", "UK-London",
            "DTX", "SG-Singapore-DC2"
        ])


if __name__ == "__main__":
    unittest.main()
