"""Core bot CD lifecycle evidence. No additional Telegram requests or secrets."""
import asyncio
import json
import time

from telegram.request import HTTPXRequest

POLL_OK = "NVL_CD_POLL_OK"
STOP_OK = "NVL_CD_SHUTDOWN_CLEAN"


class PollingHealthRequest(HTTPXRequest):
    """Observe the existing successful getUpdates response, never its contents in logs."""

    def __init__(self):
        # Match ApplicationBuilder's dedicated getUpdates connection pool.
        super().__init__(connection_pool_size=1)
        self._last_evidence = None

    async def do_request(self, url, method, request_data=None, **kwargs):
        status, raw = await super().do_request(
            url=url, method=method, request_data=request_data, **kwargs)
        if status == 200 and url.rsplit("/", 1)[-1] == "getUpdates":
            now = time.monotonic()
            if self._last_evidence is None or now - self._last_evidence >= 15:
                try:
                    result = json.loads(raw)
                    if (isinstance(result, dict) and result.get("ok") is True
                            and isinstance(result.get("result"), list)):
                        print(POLL_OK, flush=True)
                        self._last_evidence = now
                except (ValueError, TypeError, OSError):
                    # Health instrumentation must not alter the polling response.
                    pass
        return status, raw


async def drain_detached(tasks, timeout=45):
    """Await registered fire-and-forget work; never cancel it for deployment."""
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        pending = {task for task in tasks if not task.done()}
        if not pending:
            return True
        left = deadline - asyncio.get_running_loop().time()
        if left <= 0:
            return False
        _, remaining = await asyncio.wait(pending, timeout=left)
        if remaining:
            return False


def mark_clean_shutdown(drained, tracked):
    """Conservative evidence: registered work and remaining loop tasks are finished."""
    current = asyncio.current_task()
    if (drained and not any(not task.done() for task in tracked)
            and not any(task is not current and not task.done()
                        for task in asyncio.all_tasks())):
        print(STOP_OK, flush=True)
        return True
    return False
