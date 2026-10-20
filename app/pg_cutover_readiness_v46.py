"""V4.6 synthetic-only PostgreSQL 17 operational schema gap audit.

Read PostgreSQL system catalogs and an in-memory SQLite test schema only.
Never migrate customer data, modify a table, create a route, or grant cutover.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
import sqlite3
from typing import Mapping

from app.pg_migration_compat_v37 import COLUMNS

LAB_DATABASE = re.compile(r"jw_v20_test_[0-9a-f]{12}\Z")
TABLES = tuple(COLUMNS)

# These are data-bearing legacy columns that an operating PostgreSQL schema
# must represent losslessly before it could replace the existing web storage.
# This list records field-level gaps; *independent* semantic blockers remain.
ESSENTIAL_FIELDS = {
    'messenger_companies': ('verification_kind',),
    'messenger_connections': ('accepted_at', 'connection_seq'),
    'messenger_messages': ('order_id', 'immutable_order_snapshot',
                           'actor_name', 'version', 'edited_at'),
    'messenger_edits': ('edited_at',),
    'messenger_attachments': ('mime', 'size_bytes'),
    'messenger_read_positions': ('last_read_rowid',),
    'messenger_receipts': ('actor_name',),
}

# A PostgreSQL column-name match alone is not sufficient for operational
# equivalence. Preserve these blockers until separately tested and reviewed.
SEMANTIC_BLOCKERS = (
    'ATTACHMENT_MESSAGE_KIND_DIFFERS',
    'LEGACY_TIMESTAMP_TEXT_VS_PG_TIMESTAMPTZ',
    'ORDER_SNAPSHOT_AND_RECEIPT_LIFECYCLE_NOT_VERIFIED',
    'LIVE_EMPLOYEE_IDENTITY_MAPPING_NOT_VERIFIED',
    'DUAL_WRITE_AND_ROLLBACK_NOT_VERIFIED',
    'PRODUCTION_CUTOVER_NOT_AUTHORIZED',
)

class AuditBlocked(RuntimeError):
    """An unsafe target or invalid schema cannot become an approval."""


@dataclass(frozen=True)
class SchemaInventory:
    columns: Mapping[str, tuple[str, ...]]
    force_rls: Mapping[str, bool]


def sqlite_contract(con: sqlite3.Connection) -> dict[str, tuple[str, ...]]:
    """Inspect the checked-in synthetic SQLite schema; reject any drift."""
    found = {}
    for table in TABLES:
        if not re.fullmatch(r'messenger_[a-z_]+', table):
            raise AuditBlocked('Unexpected legacy table name')
        table_meta = con.execute(
            "SELECT type FROM sqlite_master WHERE name=?", (table,)).fetchone()
        if table_meta != ('table',):
            raise AuditBlocked('Legacy synthetic table missing')
        # Identifiers come ONLY from the fixed, checked-in COLUMNS contract.
        columns = tuple(row[1] for row in con.execute(
            'PRAGMA table_info("' + table + '")'))
        if columns != tuple(COLUMNS[table]):
            raise AuditBlocked('Legacy synthetic columns changed')
        found[table] = columns
    return found


def postgres_inventory(cur) -> SchemaInventory:
    """Read-only catalog inspection; require the disposable PG17 admin role."""
    cur.execute('SELECT current_database(), current_user, '
                "current_setting('server_version_num')")
    database, role, version = cur.fetchone()
    if (not isinstance(database, str) or not LAB_DATABASE.fullmatch(database)
            or role != 'postgres' or int(version) // 10000 != 17):
        raise AuditBlocked('Refuse non-disposable PostgreSQL 17 administrator')

    cur.execute('''SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
                         a.attname
                    FROM pg_catalog.pg_class AS c
                    JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
                    JOIN pg_catalog.pg_attribute AS a ON a.attrelid=c.oid
                   WHERE n.nspname='public' AND c.relkind IN ('r','p')
                     AND a.attnum>0 AND NOT a.attisdropped
                     AND c.relname LIKE 'messenger_%'
                   ORDER BY c.relname, a.attnum''')
    cols = {table: [] for table in TABLES}
    forced = {}
    for table, enabled, force, column in cur.fetchall():
        if table not in cols:
            continue
        if not isinstance(column, str) or column in cols[table]:
            raise AuditBlocked('Invalid operating catalog field')
        cols[table].append(column)
        if table in forced and forced[table] != bool(enabled and force):
            raise AuditBlocked('Inconsistent PostgreSQL RLS catalog')
        forced[table] = bool(enabled and force)
    if any(not cols[t] for t in TABLES):
        raise AuditBlocked('Required operating messenger table missing')
    return SchemaInventory({k: tuple(v) for k, v in cols.items()}, forced)


def audit_cutover_gap(source: Mapping[str, tuple[str, ...]],
                      target: SchemaInventory) -> dict:
    """The only acceptable review decision is BLOCKED, even on schema match."""
    if set(source) != set(TABLES) or set(target.columns) != set(TABLES):
        raise AuditBlocked('Seven-table schema boundary incomplete')
    if set(target.force_rls) != set(TABLES):
        raise AuditBlocked('PostgreSQL table security metadata missing')
    if any(tuple(source[table]) != tuple(COLUMNS[table]) for table in TABLES):
        raise AuditBlocked('Unrecognized historical SQLite shape')
    missing = {}
    for table in TABLES:
        columns = target.columns[table]
        if not isinstance(columns, (list, tuple)) or len(columns) != len(set(columns)):
            raise AuditBlocked('Unrepresentable operating table columns')
        absent = sorted(set(COLUMNS[table]) - set(columns))
        if absent:
            missing[table] = absent
    not_forced = sorted(t for t in TABLES if target.force_rls[t] is not True)
    reasons = []
    if missing:
        reasons.append('OPERATIONAL_SCHEMA_MISSING_LEGACY_FIELDS')
    if not_forced:
        reasons.append('OPERATIONAL_RLS_NOT_FORCED')
    reasons.extend(SEMANTIC_BLOCKERS)
    return {
        'decision': 'BLOCKED',
        'cutover_approved': False,
        'seven_tables_checked': len(TABLES),
        'missing_legacy_columns': missing,
        'missing_essential_fields': {
            table: sorted(set(ESSENTIAL_FIELDS[table]) - set(target.columns[table]))
            for table in TABLES
            if set(ESSENTIAL_FIELDS[table]) - set(target.columns[table])
        },
        'rls_not_forced': not_forced,
        'reason_codes': reasons,
        'synthetic_only': True,
    }
