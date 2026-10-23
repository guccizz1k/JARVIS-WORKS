"""Review-only inventory for a future PostgreSQL migration.

DO NOT invoke this to write to a PostgreSQL server. It does not validate
PostgreSQL DDL compatibility, data movement, RLS, identity mapping, or cutover.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re

PG_TABLE_PATTERN = re.compile(
    r'\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?'
    r'(?:(?:"?[\w]+"?)\.)?(?:"?([a-z][a-z0-9_]*)"?)\s*\(',re.I)


def schema_inventory(connection, postgres_fixture_ddl: str):
    # Only read immutable table metadata: no customer rows or values.
    rows=connection.execute("SELECT name,sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    sqlite_tables={name for name,_ in rows}
    pg_tables={m.group(1).lower() for m in PG_TABLE_PATTERN.finditer(postgres_fixture_ddl)}
    missing=sorted(sqlite_tables-pg_tables)
    # Fingerprint schema DDL without exposing any live row contents.
    normalized=[(name,sql) for name,sql in rows]
    fingerprint=sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return {'source_engine':'SQLite','proposed_reference':'V2.0 PG RLS synthetic test fixture only',
            'sqlite_table_count':len(sqlite_tables),'pg_reference_table_count':len(pg_tables),
            'unrepresented_sqlite_tables':missing,
            'schema_ddl_sha256':fingerprint,
            'operational_cutover_permitted':False,
            'blockers':[
                'FULL_PG_TARGET_SCHEMA_MISSING' if missing else 'PRODUCTION_SCHEMA_MIGRATION_NOT_ATTESTED',
                'ROW_DATA_MIGRATION_AND_RELATIONSHIPS_NOT_ATTESTED',
                'LIVE_STORAGE_ADAPTER_STILL_SQLITE',
                'LIVE_POSTGRES_RLS_ATTACK_GATE_NOT_RUN',
                'PRODUCTION_CUTOVER_NOT_AUTHORIZED',
            ]}
