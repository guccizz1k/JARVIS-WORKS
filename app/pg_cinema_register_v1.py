"""Strict opt-in registration of the CINEMA PostgreSQL trade write API (review candidate).

OFF by default. The router is mounted only when ALL of these hold:
  * JW_PG_CINEMA_TRADE_V1 == ISOLATED_DEV_CINEMA_TRADE_ONLY (own gate, separate from every other gate), and
  * the V9.0 isolated messenger composition is enabled (which in turn requires the V8.4 reader and V8.5
    auth gates, a non-production environment and no insecure-local flag).

It re-uses the V9.0 per-request session validation (`_pg_validated_cursor`: unsafe login detection, forced
PG session lookup, identity from `jw_dev.stage_identity_v84()`) and CSRF comparison. On top of that, every
request additionally verifies that the LOGIN role is not a member of the table-owning role
`jw_cinema_owner`, then drops to `jw_cinema_writer` (SELECT + EXECUTE on the public API only).

This module never creates roles, grants, tables or data. If the login role is not a member of
`jw_cinema_writer` (an administrator decision that has NOT been made), every request fails closed (403/503).
"""
from __future__ import annotations

import os
from typing import Any

from fastapi import HTTPException, Request

from . import pg_v90_integrated_entry as _v90
from .pg_cinema_trade_v1 import WRITER_ROLE, VerifiedSession, create_router

GATE_ENV = "JW_PG_CINEMA_TRADE_V1"
GATE_VALUE = "ISOLATED_DEV_CINEMA_TRADE_ONLY"
OWNER_ROLE = "jw_cinema_owner"


def cinema_trade_enabled() -> bool:
    return os.environ.get(GATE_ENV) == GATE_VALUE and _v90.v90_enabled()


def _authorize(request: Request) -> VerifiedSession:
    """Session cookie + CSRF are validated by the already-reviewed V9.0 code, not re-implemented here."""
    verified = _v90._authorize(request)
    return VerifiedSession(session_hash=verified.session_hash, csrf_verified=bool(verified.csrf_verified))


class ValidatedWriterGateway:
    """One PG transaction per call: V9.0 validated cursor -> owner-membership check -> SET LOCAL ROLE writer."""

    def query(self, session_hash: str, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with _v90._pg_validated_cursor(session_hash) as (cur, _identity):
            cur.execute("SELECT pg_catalog.pg_has_role(session_user, %s, 'MEMBER')", (OWNER_ROLE,))
            if cur.fetchone() != (False,):
                raise HTTPException(503, "Trade login role is not separated from the owner role")
            # S4: do not open a second transaction ledger for a tenant that
            # already has any historical v92 quote-to-cash rows. Check through
            # the validated tenant session BEFORE changing into the CINEMA role.
            # A separate deployed v92 writer could still race this check;
            # full global exclusivity requires a DB-level migration policy.
            org = _identity[2]
            cur.execute(
                "SELECT EXISTS(SELECT 1 FROM jw_dev.quotes WHERE org_id=%s) "
                "OR EXISTS(SELECT 1 FROM jw_dev.orders WHERE org_id=%s) "
                "OR EXISTS(SELECT 1 FROM jw_dev.invoices WHERE org_id=%s) "
                "OR EXISTS(SELECT 1 FROM jw_dev.payments WHERE org_id=%s)",
                (org, org, org, org),
            )
            legacy = cur.fetchone()
            if legacy != (False,):
                raise HTTPException(409, "Existing legacy trades require verified reconciliation")
            cur.execute(f"SET LOCAL ROLE {WRITER_ROLE}")  # fails closed (42501) until membership is granted
            cur.execute(sql, params)
            columns = [col.name for col in cur.description] if cur.description else []
            return [dict(zip(columns, row)) for row in cur.fetchall()] if columns else []


def register_cinema_trade_v1(app) -> bool:
    """Mount the trade router only after the explicit, separate opt-in. Returns whether it was mounted."""
    if not cinema_trade_enabled():
        return False
    app.include_router(create_router(ValidatedWriterGateway(), _authorize))
    return True
