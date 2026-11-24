"""Lifecycle contract tests, no real Telegram calls."""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch
from telegram.request import HTTPXRequest
from nvl_cd_bot_lifecycle import PollingHealthRequest, drain_detached, mark_clean_shutdown


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_poll_evidence_only_for_successful_get_updates(self):
        request = PollingHealthRequest()
        self.addAsyncCleanup(request.shutdown)
        url = "https://api.telegram.org/botTEST/getUpdates"
        body = b'{"ok":true,"result":[]}'
        with patch.object(HTTPXRequest, "do_request", new=AsyncMock(return_value=(200, body))), \
                patch("builtins.print") as emit:
            self.assertEqual(await request.do_request(url, "POST"), (200, body))
            await request.do_request(url, "POST")
            await request.do_request(url.replace("getUpdates", "getMe"), "POST")
            emit.assert_called_once_with("NVL_CD_POLL_OK", flush=True)

    async def test_error_and_invalid_payload_never_emit_evidence(self):
        request = PollingHealthRequest()
        self.addAsyncCleanup(request.shutdown)
        for status, body in ((409, b'{"ok":false}'), (200, b'bad'), (200, b'{"ok":true}')):
            with patch.object(HTTPXRequest, "do_request", new=AsyncMock(return_value=(status, body))), \
                    patch("builtins.print") as emit:
                await request.do_request("https://example.test/getUpdates", "POST")
                emit.assert_not_called()

    async def test_drain_does_not_cancel_inflight_work(self):
        event = asyncio.Event()
        task = asyncio.create_task(event.wait())
        try:
            self.assertFalse(await drain_detached({task}, timeout=0.01))
            self.assertFalse(task.cancelled())
            event.set()
            self.assertTrue(await drain_detached({task}, timeout=1))
        finally:
            event.set()
            await task

    async def test_clean_marker_requires_no_pending_tasks(self):
        event = asyncio.Event()
        task = asyncio.create_task(event.wait())
        try:
            with patch("builtins.print") as emit:
                self.assertFalse(mark_clean_shutdown(True, {task}))
                self.assertFalse(mark_clean_shutdown(False, set()))
                emit.assert_not_called()
            event.set()
            await task
            with patch("builtins.print") as emit:
                self.assertTrue(mark_clean_shutdown(True, {task}))
                emit.assert_called_once_with("NVL_CD_SHUTDOWN_CLEAN", flush=True)
        finally:
            event.set()
            await task
