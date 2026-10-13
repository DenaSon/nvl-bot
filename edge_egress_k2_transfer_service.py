"""Explicitly released Telegram -> P3-A -> P3-C/customer-host 6G integration.

No built-in root worker or automatic enablement. A separate, vetted root-only
factory must supply independently verified fresh evidence, exact account/UID
scope and an eligible guarded composite host port after disposable acceptance.
Never use the Phase2 read-only ACK ticket as an execution authorization.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Callable

from edge_egress_p3_executor import (
    ExecutionScope, ExecutionTicket, FreshEvidence, ExecutionReceipt,
    Existing6GGuardedExecutor, issue_execution_ticket,
)
from edge_egress_k2_customer_move import GuardedCustomerIngressBindingPort

K2_TELEGRAM_TRANSFER_ENABLED = False


class TransferRegistrationHold(ValueError):
    pass


@dataclass(frozen=True)
class PreparedCustomerTransfer:
    scope: ExecutionScope
    ticket: ExecutionTicket


class GuardedK2TelegramTransferService:
    """Per-user transfer; existing 6G only; root-only operator release."""

    def __init__(self, *, db_conn: Callable, acquire_fn: Callable,
                 journal_fn: Callable, resolve_scope: Callable,
                 independent_review: Callable, make_host_port: Callable,
                 release_enabled: bool = False,
                 geteuid: Callable[[], int] = os.geteuid):
        self.db_conn = db_conn
        self.acquire_fn = acquire_fn
        self.journal_fn = journal_fn
        self.resolve_scope = resolve_scope
        self.review = independent_review
        self.make_host_port = make_host_port
        self.release_enabled = release_enabled
        self.geteuid = geteuid

    def _released(self):
        if (self.release_enabled is not True or self.geteuid() != 0
                or not all(callable(x) for x in (
                    self.db_conn, self.acquire_fn, self.journal_fn,
                    self.resolve_scope, self.review, self.make_host_port
                ))):
            raise TransferRegistrationHold("ROOT_OPERATOR_RELEASE_NOT_ATTESTED")

    def prepare(self, *, username: str, edge_id: str,
                actor_id: int, chat_id: int) -> PreparedCustomerTransfer:
        self._released()
        scope = self.resolve_scope(username, edge_id)
        if (not isinstance(scope, ExecutionScope)
                or scope.action != "UID_ATTACH"
                or scope.username != username or scope.edge_id != edge_id):
            raise TransferRegistrationHold("SELECTED_UID_OR_EDGE_CHANGED")
        fresh = self.review(scope)
        if not isinstance(fresh, FreshEvidence):
            raise TransferRegistrationHold("INDEPENDENT_FRESH_EVIDENCE_MISSING")
        # P3-A validates complete gates/F4 and actor/chat/TTL before issuing.
        ticket = issue_execution_ticket(
            scope, fresh, actor_id=actor_id, chat_id=chat_id,
        )
        return PreparedCustomerTransfer(scope, ticket)

    async def execute(self, item: PreparedCustomerTransfer, *,
                      actor_id: int, chat_id: int) -> ExecutionReceipt:
        self._released()
        if (not isinstance(item, PreparedCustomerTransfer)
                or actor_id != item.ticket.actor_id or chat_id != item.ticket.chat_id):
            raise TransferRegistrationHold("ACTOR_OR_CHAT_CHANGED")
        port = self.make_host_port(item.scope, item.ticket)
        if (not isinstance(port, GuardedCustomerIngressBindingPort)
                or port.scope != item.scope
                or port.ticket != item.ticket
                or port.release_enabled is not True):
            raise TransferRegistrationHold("AUDITED_COMPOSITE_HOST_PORT_REQUIRED")
        # No extra lock, journal, or owner table: all transitions flow through
        # the already implemented P3-A transaction and its mandatory F4 gates.
        executor = Existing6GGuardedExecutor(
            db_conn=self.db_conn, acquire_fn=self.acquire_fn,
            journal_fn=self.journal_fn, review_fn=self.review,
            host_port=port, release_enabled=True, geteuid=self.geteuid,
        )
        return await executor.execute(
            item.scope, item.ticket, actor_id=actor_id, chat_id=chat_id,
        )
