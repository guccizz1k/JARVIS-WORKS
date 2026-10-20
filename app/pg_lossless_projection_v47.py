"""V4.7 ephemeral PG17 operational-column projection rehearsal.

Never a customer migration. In a disposable PostgreSQL 17 DB, rehearse ONLY
additive, nullable legacy fields in a transaction that must be rolled back.
The operational cutover decision is always DENIED irrespective of field parity.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from app.pg_cutover_readiness_v46 import (
    AuditBlocked, ESSENTIAL_FIELDS, SEMANTIC_BLOCKERS, TABLES,
    audit_cutover_gap, postgres_inventory,
)
from app.pg_migration_compat_v37 import COLUMNS

# Explicit, independently reviewable additive plan; never inferred from
# untrusted PostgreSQL catalog metadata or a user-provided identifier.
PROJECTION_TYPES = {
    'messenger_companies': {'verification_kind': 'text'},
    'messenger_connections': {'accepted_at': 'text', 'connection_seq': 'bigint'},
    'messenger_messages': {
        'order_id': 'text', 'immutable_order_snapshot': 'text',
        'actor_name': 'text', 'version': 'integer', 'edited_at': 'text',
    },
    'messenger_edits': {'edited_at': 'text'},
    'messenger_attachments': {'mime': 'text', 'size_bytes': 'integer'},
    'messenger_read_positions': {'last_read_rowid': 'bigint'},
    'messenger_receipts': {'actor_name': 'text'},
}


class ProjectionRefused(AuditBlocked):
    """Incorrect baseline/column/type/RLS must fail closed."""


def validate_plan() -> int:
    if tuple(PROJECTION_TYPES) != tuple(TABLES):
        raise ProjectionRefused('Plan must name all seven canonical tables')
    for table in TABLES:
        planned = PROJECTION_TYPES[table]
        if set(planned) != set(ESSENTIAL_FIELDS[table]):
            raise ProjectionRefused('Planned fields differ from V4.6 gap audit')
        if not set(planned).issubset(COLUMNS[table]):
            raise ProjectionRefused('Unknown historical legacy field')
        if any(t not in ('text', 'bigint', 'integer') for t in planned.values()):
            raise ProjectionRefused('Unsafe projected SQL type')
    return sum(map(len, PROJECTION_TYPES.values()))


def expected_missing() -> dict[str, list[str]]:
    validate_plan()
    return {table: sorted(values) for table, values in PROJECTION_TYPES.items()}


def create_plan(baseline: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    """No DDL on unexpected, drifted or partially patched operating schemas."""
    if set(baseline) != set(TABLES):
        raise ProjectionRefused('Incomplete baseline inventory')
    expected = expected_missing()
    statements = []
    for table in TABLES:
        existing = tuple(baseline[table])
        if len(set(existing)) != len(existing):
            raise ProjectionRefused('Duplicate catalog columns')
        if sorted(set(COLUMNS[table]) - set(existing)) != expected[table]:
            raise ProjectionRefused('Baseline drift or already-patched field')
        for column, kind in PROJECTION_TYPES[table].items():
            statements.append(f'ALTER TABLE public."{table}" ADD COLUMN "{column}" {kind}')
    return tuple(statements)


def projected_types(cur) -> dict[tuple[str, str], tuple[str, bool, bool]]:
    """Read exact type and NULL/default metadata from real PG system catalog."""
    cur.execute('''SELECT c.relname, a.attname,
                          pg_catalog.format_type(a.atttypid, a.atttypmod),
                          a.attnotnull, a.atthasdef
                     FROM pg_catalog.pg_class AS c
                     JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                     JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
                    WHERE n.nspname = 'public' AND c.relkind = 'r'
                      AND c.relname LIKE 'messenger_%'
                      AND a.attnum > 0 AND NOT a.attisdropped''')
    results = {}
    for table, field, kind, notnull, hasdef in cur.fetchall():
        if table in PROJECTION_TYPES and field in PROJECTION_TYPES[table]:
            key = (table, field)
            if key in results:
                raise ProjectionRefused('Duplicate catalog attribute')
            results[key] = (kind, bool(notnull), bool(hasdef))
    return results


@dataclass(frozen=True)
class RehearsalResult:
    projected_columns: int
    rollback_verified: bool
    force_rls_preserved: bool
    decision: str = 'BLOCKED'
    cutover_approved: bool = False


def rehearse_additive_columns(pg, source) -> RehearsalResult:
    """PG connection MUST be autocommit, disposable PG17 admin, no data transfer.

    All DDL is executed within one explicit transaction and ALWAYS rolled back.
    Schema state is checked after rollback even when the rehearsal raises.
    """
    count = validate_plan()
    if pg.autocommit is not True:
        raise ProjectionRefused('Autocommit connection required for isolated rollback boundary')
    with pg.cursor() as cur:
        baseline = postgres_inventory(cur)  # PG17, disposable db and admin guard
        if any(baseline.force_rls.get(t) is not True for t in TABLES):
            raise ProjectionRefused('Forced RLS required on every operating table')
        previous = audit_cutover_gap(source, baseline)
        if previous['missing_essential_fields'] != expected_missing():
            raise ProjectionRefused('Operational schema does not match approved gap baseline')
        sql = create_plan(baseline.columns)
        failure = None
        started = False
        try:
            cur.execute("BEGIN")
            started = True
            # Timeouts restrict waiting on schema locks even in an isolated DB.
            cur.execute("SET LOCAL lock_timeout = '2000ms'")
            cur.execute("SET LOCAL statement_timeout = '5000ms'")
            for statement in sql:
                cur.execute(statement)
            after = postgres_inventory(cur)
            if any(after.force_rls.get(t) is not True for t in TABLES):
                raise ProjectionRefused('Projected schema loses FORCE RLS')
            report = audit_cutover_gap(source, after)
            if report['missing_legacy_columns'] or report['missing_essential_fields']:
                raise ProjectionRefused('Projected schema retains a legacy field gap')
            if report['decision'] != 'BLOCKED' or report['cutover_approved'] is not False:
                raise ProjectionRefused('Rehearsal cannot authorize production cutover')
            if tuple(report['reason_codes']) != tuple(SEMANTIC_BLOCKERS):
                raise ProjectionRefused('Unsupported semantic blockers were dropped')
            observed = projected_types(cur)
            for table, mapping in PROJECTION_TYPES.items():
                for column, kind in mapping.items():
                    if observed.get((table, column)) != (kind, False, False):
                        raise ProjectionRefused('Projected SQL type/nullable/default drift')
            if len(observed) != count:
                raise ProjectionRefused('Incomplete projected attribute verification')
        except Exception as exc:
            failure = exc
        finally:
            if started:
                # Explicit unconditional ROLLBACK. Failure is an error, never PASS.
                try:
                    cur.execute('ROLLBACK')
                except Exception as exc:
                    raise ProjectionRefused('Isolated rollback failed') from exc
        restored = postgres_inventory(cur)
        if restored != baseline:
            raise ProjectionRefused('Post-rollback catalog differs from pristine baseline')
        if failure is not None:
            raise ProjectionRefused('Synthetic additive schema rehearsal failed') from failure
        return RehearsalResult(count, True, True)
