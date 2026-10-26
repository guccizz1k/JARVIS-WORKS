"""Staging-only PostgreSQL payment adapter. NOT registered on FastAPI.

This is a low-privilege, opted-in prototype. The privileged ledger functions
are installed in jw_dev by the separate reviewed migration. They lock the
invoice row before evaluating balances and record an audit event atomically.
"""
from __future__ import annotations

from datetime import date, datetime

from .pg_stage_v82 import validated_pg_session


class FinanceInputError(ValueError):
    """Payment request failed validation before opening a database transaction."""


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        raise FinanceInputError(f"Invalid {label}")
    return value


def record_payment_stage(connection, *, token: str, actor_id: str, org_id: str,
                         invoice_id: str, amount: int, paid_at: date,
                         reference: str, note: str = "") -> str:
    """Atomic idempotent payment through the DB's locked RPC.

    Do not retry on unknown transaction outcomes without reconciling by
    invoice and reference. The database resolves identical request IDs.
    """
    _identifier(invoice_id, "invoice_id")
    if type(amount) is not int or not 1 <= amount <= 10**16:
        raise FinanceInputError("Invalid payment amount")
    if not isinstance(paid_at, date) or isinstance(paid_at, datetime):
        raise FinanceInputError("Invalid payment date")
    if not isinstance(reference, str) or not 8 <= len(reference) <= 100:
        raise FinanceInputError("Invalid payment reference")
    if not isinstance(note, str) or len(note) > 300:
        raise FinanceInputError("Invalid payment note")
    with validated_pg_session(connection, raw_session_token=token,
                              actor_id=actor_id, org_id=org_id) as cur:
        cur.execute("""SELECT jw_dev.record_payment_v83(%s,%s,%s,%s,%s)""",
                    (invoice_id, amount, paid_at, reference, note))
        row = cur.fetchone()
        if not row or not isinstance(row[0], str) or not row[0]:
            raise RuntimeError("PostgreSQL payment RPC returned no identifier")
        return row[0]


def reverse_payment_stage(connection, *, token: str, actor_id: str, org_id: str,
                          invoice_id: str, payment_id: str) -> None:
    """Ask the DB to reverse one payment; DB validates admin role."""
    _identifier(invoice_id, "invoice_id")
    _identifier(payment_id, "payment_id")
    with validated_pg_session(connection, raw_session_token=token,
                              actor_id=actor_id, org_id=org_id) as cur:
        cur.execute("SELECT jw_dev.reverse_payment_v83(%s,%s)",
                    (invoice_id, payment_id))
        row = cur.fetchone()
        if row != (True,):
            raise RuntimeError("PostgreSQL reversal RPC did not confirm")
