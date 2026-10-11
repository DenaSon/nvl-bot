"""F1: strict table parsing refuses paths that could egress via Core."""
import unittest

from edge_egress_uid_route_state import ProtectedRouteError, inspect_owned_routes

KW = dict(next_hop="10.78.101.2", device="vnh-fra1", source="10.78.101.1")
BH = "blackhole default metric 4096\n"
EDGE = "default via 10.78.101.2 dev vnh-fra1 src 10.78.101.1 metric 100\n"


class OwnedRouteTests(unittest.TestCase):
    def test_deny_only_and_owned_active(self):
        frozen = inspect_owned_routes(BH, **KW)
        self.assertTrue(frozen.terminal_blackhole)
        self.assertFalse(frozen.edge_attached)
        active = inspect_owned_routes(EDGE + BH, **KW)
        self.assertTrue(active.terminal_blackhole)
        self.assertTrue(active.edge_attached)
        self.assertTrue(inspect_owned_routes(BH + EDGE, **KW).edge_attached)

    def test_first_install_can_observe_empty_table_but_not_call_it_guarded(self):
        empty = inspect_owned_routes("", allow_empty=True, **KW)
        self.assertFalse(empty.terminal_blackhole)
        with self.assertRaises(ProtectedRouteError):
            inspect_owned_routes("", **KW)

    def test_reject_foreign_next_hop_core_route_or_missing_terminal(self):
        for table in (
            EDGE,  # no terminal blackhole
            "default via 209.200.246.198 dev eth0\n" + BH,
            "default via 10.78.101.2 dev eth0 src 10.78.101.1 metric 100\n" + BH,
            "default via 10.78.101.2 dev vnh-fra1 src 209.200.246.198 metric 100\n" + BH,
            EDGE + BH + BH,
            EDGE + EDGE + BH,
            "unreachable default metric 4096\n" + EDGE,
            BH + "10.0.0.0/8 via 209.200.246.198 dev eth0\n",
        ):
            with self.subTest(table=table), self.assertRaises(ProtectedRouteError):
                inspect_owned_routes(table, **KW)

    def test_known_iproute2_cosmetic_variants(self):
        table = ("default via 10.78.101.2 dev vnh-fra1 proto static "
                 "src 10.78.101.1 metric 100 linkdown\n"
                 "blackhole default proto static metric 4096\n")
        self.assertTrue(inspect_owned_routes(table, **KW).edge_attached)


if __name__ == "__main__":
    unittest.main()
