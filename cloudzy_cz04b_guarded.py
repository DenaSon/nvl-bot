"""Opt-in P5 guarded implementation of the existing CZ04B route Saga.

Not wired into the live Telegram menu until combined P4/P5 staging approval.
Reuses the original CZ04B receipt, Cloudflare exact-record adapter, original 6G
lease, account fingerprint, provider/SSH/WG/NAT gates and DB CAS. No new DB.
"""
import asyncio

from cloudzy_cz04b import Cloudzy04B, CutoverHold, _digest
from cloudzy_route_reconcile import (
    require_customer_route_projection, classify_dns_records,
)


class GuardedCloudzy04B(Cloudzy04B):
    """Same existing public callbacks; only route execution policy changes."""

    def _projection(self, source, target):
        with self.db() as db:
            self.guard(db)
            return require_customer_route_projection(
                db, source=source, target=target)

    @staticmethod
    def _exact_dns(original, observed, desired):
        result = classify_dns_records(
            observed, source=original[0]["ip"], target=desired,
            expected=original)
        if result != "TARGET":
            raise CutoverHold("DNS_TARGET_IDENTITY_UNVERIFIED")
        return result

    def _mark_held(self, opid, lock, note):
        """Preserve the original 6G RUNNING lease; no automatic DNS replay."""
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT status,shared_6g_id FROM cloudzy_cz04b_operations "
                "WHERE id=? AND kind='route'", (opid,)
            ).fetchone()
            if not row or row[1] != lock:
                raise CutoverHold("ROUTE_HOLD_OWNER_CHANGED")
            if not db.execute(
                "SELECT 1 FROM failover_operations WHERE id=? AND status='RUNNING'",
                (lock,)
            ).fetchone():
                raise CutoverHold("SHARED_6G_LEASE_NOT_RUNNING")
            if row[0] not in (
                    "PREPARING", "DNS_WRITE_INTENT", "DNS_TARGET_CONFIRMED",
                    "DB_TARGET_COMMITTED", "READY", "HOLD"):
                raise CutoverHold("ROUTE_HOLD_STATE_CHANGED")
            if db.execute(
                "UPDATE cloudzy_cz04b_operations "
                "SET status='HOLD',note=?,updated_at=? WHERE id=? "
                "AND shared_6g_id=? AND status=?",
                (note, int(self.now()), opid, lock, row[0])
            ).rowcount != 1:
                raise CutoverHold("ROUTE_HOLD_CAS_FAILED")

    async def _run_route(self, actor, chat, target):
        """Protect a single DNS intent. Never auto-rollback after PUT intent."""
        if not self.enabled():
            raise CutoverHold("CZ04B_DISABLED")
        state = await asyncio.to_thread(self._state, target)
        await asyncio.to_thread(self._projection, state["source"], target)
        await self._fresh(state)
        initial = await asyncio.to_thread(self.dns.snapshot)
        self._expect_dns(initial, state["source"])
        fingerprint = _digest(state["users"])
        state["fingerprint"] = fingerprint
        lock, busy = await self._acquire(state["source"], target)
        if not lock:
            raise CutoverHold("SHARED_6G_BUSY")
        op_id = None
        dns_intent = False
        try:
            fresh = await asyncio.to_thread(self._state, target, locked=True)
            await asyncio.to_thread(self._projection, state["source"], target)
            if (_digest(fresh["users"]) != fingerprint
                    or fresh["hosts"] != state["hosts"]
                    or fresh["provider_id"] != state["provider_id"]):
                raise CutoverHold("ROUTE_PREVIEW_STALE")
            # A second current service probe under the protected lease.
            await self._fresh(fresh)
            current = await asyncio.to_thread(self.dns.snapshot)
            self._expect_dns(current, state["source"])
            if (len(current) != len(initial)
                    or {(r["name"], r["id"], r["ttl"]) for r in current}
                    != {(r["name"], r["id"], r["ttl"]) for r in initial}):
                raise CutoverHold("DNS_RECORD_IDENTITY_CHANGED")
            op_id = await asyncio.to_thread(
                self._reserve, "route", actor, chat, state,
                shared=lock, fingerprint=fingerprint)
            await asyncio.to_thread(
                self._transition, op_id, "DNS_WRITE_INTENT",
                "CLOUDFLARE_EXTERNAL_EFFECT_POSSIBLE")
            dns_intent = True
            # Exact existing adapter: one guarded PUT per configured record.
            # Any timeout/rejection/partial success is a HOLD, NOT auto-retry.
            await asyncio.to_thread(self.dns.set_all, current, target)
            actual = await asyncio.to_thread(self.dns.snapshot)
            self._exact_dns(initial, actual, target)
            await asyncio.to_thread(
                self._transition, op_id, "DNS_TARGET_CONFIRMED",
                "EXACT_CLOUDFLARE_RECORD_SET_VERIFIED")
            await asyncio.to_thread(self._commit_route, op_id, state)
            last = await asyncio.to_thread(self.dns.snapshot)
            self._exact_dns(initial, last, target)
            await asyncio.to_thread(self._route_db_postcheck, target)
            await asyncio.to_thread(
                self._transition, op_id, "READY", "DNS_DEFAULT_READY_NO_USER_MOVE")
            await asyncio.to_thread(self._shared_finish, lock, completed=True)
            return "READY"
        except Exception:
            if dns_intent:
                if op_id:
                    try:
                        await asyncio.to_thread(
                            self._mark_held, op_id, lock,
                            "DNS_OR_DEFAULT_RECONCILIATION_REQUIRED")
                    except Exception:
                        pass
                # The shared 6G lease was already persisted as a protected
                # recovery hold by _acquire(). NEVER release or roll back DNS.
                raise CutoverHold("DNS_OR_DEFAULT_UNCERTAIN_LOCK_HELD") from None
            try:
                if op_id:
                    await asyncio.to_thread(
                        self._transition, op_id, "ABORTED",
                        "NO_EXTERNAL_DNS_INTENT")
                await asyncio.to_thread(
                    self._shared_finish, lock, completed=False)
            except Exception:
                # If local journals cannot be closed we leave a protected 6G.
                raise CutoverHold("PREFLIGHT_LEASE_RECONCILE_REQUIRED") from None
            raise CutoverHold("ROUTE_PRE_DNS_PREFLIGHT_ABORTED") from None
