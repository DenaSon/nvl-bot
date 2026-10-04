import asyncio
import pathlib
import unittest

from regional_probe_coordinator import (
    PROBE_PRIORITY_CONFIRMATION,
    PROBE_PRIORITY_DEFAULT,
    PROBE_PRIORITY_MARZBAN,
    PROBE_PRIORITY_STANDBY,
    RegionalProbeCoordinator,
)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BOT_PATH = ROOT / "bot_final_v49-2.py"


class RegionalProbeCoordinatorTests(unittest.IsolatedAsyncioTestCase):
    async def test_waiters_are_selected_by_priority(self):
        coordinator = RegionalProbeCoordinator()
        release_active = asyncio.Event()
        active_entered = asyncio.Event()
        order = []

        async def active_marzban():
            async with coordinator.slot(PROBE_PRIORITY_MARZBAN, "active-marzban"):
                active_entered.set()
                await release_active.wait()

        async def waiter(priority, label):
            async with coordinator.slot(priority, label):
                order.append(label)
                await asyncio.sleep(0)

        active = asyncio.create_task(active_marzban())
        await active_entered.wait()

        tasks = [
            asyncio.create_task(waiter(PROBE_PRIORITY_MARZBAN, "marzban")),
            asyncio.create_task(waiter(PROBE_PRIORITY_STANDBY, "standby")),
            asyncio.create_task(waiter(PROBE_PRIORITY_DEFAULT, "default")),
            asyncio.create_task(waiter(PROBE_PRIORITY_CONFIRMATION, "confirmation")),
        ]
        await asyncio.sleep(0)
        release_active.set()
        await active
        await asyncio.gather(*tasks)

        self.assertEqual(
            order,
            ["confirmation", "default", "standby", "marzban"],
        )

    async def test_fifo_is_preserved_within_same_priority(self):
        coordinator = RegionalProbeCoordinator()
        release_active = asyncio.Event()
        active_entered = asyncio.Event()
        order = []

        async def active():
            async with coordinator.slot(PROBE_PRIORITY_DEFAULT, "active"):
                active_entered.set()
                await release_active.wait()

        async def waiter(label):
            async with coordinator.slot(PROBE_PRIORITY_DEFAULT, label):
                order.append(label)

        first = asyncio.create_task(active())
        await active_entered.wait()
        a = asyncio.create_task(waiter("a"))
        await asyncio.sleep(0)
        b = asyncio.create_task(waiter("b"))
        await asyncio.sleep(0)
        c = asyncio.create_task(waiter("c"))
        await asyncio.sleep(0)

        release_active.set()
        await first
        await asyncio.gather(a, b, c)
        self.assertEqual(order, ["a", "b", "c"])

    async def test_slot_is_released_after_exception(self):
        coordinator = RegionalProbeCoordinator()

        with self.assertRaises(RuntimeError):
            async with coordinator.slot(PROBE_PRIORITY_DEFAULT, "boom"):
                raise RuntimeError("expected")

        async with coordinator.slot(PROBE_PRIORITY_DEFAULT, "next"):
            self.assertTrue(coordinator.active)
            self.assertEqual(coordinator.active_label, "next")


class V121DIntegrationShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = BOT_PATH.read_text(encoding="utf-8")

    def _region(self, start, end):
        a = self.source.index(start)
        b = self.source.index(end, a)
        return self.source[a:b]

    def test_shared_skip_lock_is_removed(self):
        self.assertNotIn("_regional_probe_lock", self.source)
        self.assertNotIn("PROBE_ALREADY_RUNNING", self.source)
        self.assertIn("RegionalProbeCoordinator", self.source)

    def test_default_work_uses_default_priority(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertIn("PROBE_PRIORITY_DEFAULT", region)
        self.assertIn("default-node-discovery", region)
        self.assertNotIn('return {"status": "BUSY"}', region)

    def test_differential_confirmation_has_highest_priority(self):
        region = self._region(
            "async def _regional_filter_tick(app):",
            "async def _regional_filter_probe_one_now",
        )
        self.assertGreaterEqual(
            region.count("PROBE_PRIORITY_CONFIRMATION"),
            2,
        )
        self.assertIn("confirm-source:", region)
        self.assertIn("confirm-control:", region)

    def test_standby_work_is_lower_priority(self):
        region = self._region(
            "async def _refresh_standby_regional_slow",
            "async def _standby_readiness_tick",
        )
        self.assertIn("PROBE_PRIORITY_STANDBY", region)
        self.assertNotIn("lock.locked()", region)

    def test_marzban_is_lowest_priority_and_yields_between_targets(self):
        region = self._region(
            "async def _marzban_regional_filter_tick",
            "async def _deliver_marzban_monitor_alerts",
        )
        self.assertIn("PROBE_PRIORITY_MARZBAN", region)
        self.assertIn("marzban-node-discovery", region)
        self.assertIn('f"marzban:{target.target_key}"', region)
        self.assertNotIn("async with lock", region)


if __name__ == "__main__":
    unittest.main()
