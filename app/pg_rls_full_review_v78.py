"""Generate a fail-closed, SELECT-only 35-table PostgreSQL RLS *lab review*.

NOT an application PG adapter, production migration, or RLS certification. This
script emits guarded SQL, never opens a network connection, and never writes DB.
Only execute in an isolated, synthetic PostgreSQL 17 throwaway lab after
independently migrating the entire schema and installing jw_guard.current_tenant.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3

from .pg_full_shadow_v76 import EXPECTED_TABLES

# Auth/administrator-only material cannot be exposed via SELECT * even when
# a row appears tenant-scoped (password hashes, MFA material, full audit notes).
PRIVATE = frozenset({
    'audit_logs','login_failures','mfa_credentials','mfa_recovery_codes',
    'security_events','sessions','staff_disabled','users',
})

# Tenant key is in-row, not inherited through a parent.
DIRECT = frozenset({
    'automation_document_drafts_v62','automation_statements_v60',
    'automation_task_times_v60','customers','evidence_lines_v66',
    'evidence_links_v65','evidence_previews_v64','evidence_records_v64',
    'import_previews','invoice_adjustment_decisions_v69',
    'invoice_adjustments_v69','invoices','messenger_companies',
    'messenger_read_positions','orders','payments',
    'quotes','reconciliation_reviews_v67',
})

# More restrictive than giving all connected parties blanket org-scoped
# access: child rows are checked against their owning document/connection.
DERIVED = {
    'quote_items': "EXISTS (SELECT 1 FROM public.quotes q WHERE q.id=quote_id AND q.org_id=jw_guard.current_tenant())",
    'order_items': "EXISTS (SELECT 1 FROM public.orders o WHERE o.id=order_id AND o.org_id=jw_guard.current_tenant())",
    'invoice_items': "EXISTS (SELECT 1 FROM public.invoices i WHERE i.id=invoice_id AND i.org_id=jw_guard.current_tenant())",
    'messenger_messages': "EXISTS (SELECT 1 FROM public.messenger_connections c WHERE c.id=connection_id AND (c.org_a=jw_guard.current_tenant() OR c.org_b=jw_guard.current_tenant()))",
    'messenger_attachments': "EXISTS (SELECT 1 FROM public.messenger_messages m JOIN public.messenger_connections c ON c.id=m.connection_id WHERE m.id=message_id AND (c.org_a=jw_guard.current_tenant() OR c.org_b=jw_guard.current_tenant()))",
    'messenger_edits': "EXISTS (SELECT 1 FROM public.messenger_messages m JOIN public.messenger_connections c ON c.id=m.connection_id WHERE m.id=message_id AND (c.org_a=jw_guard.current_tenant() OR c.org_b=jw_guard.current_tenant()))",
    'messenger_receipts': "EXISTS (SELECT 1 FROM public.messenger_messages m JOIN public.messenger_connections c ON c.id=m.connection_id WHERE m.id=message_id AND (c.org_a=jw_guard.current_tenant() OR c.org_b=jw_guard.current_tenant()))",
}
SPECIAL = {
    'organizations': 'id=jw_guard.current_tenant()',
    'messenger_connections': '(org_a=jw_guard.current_tenant() OR org_b=jw_guard.current_tenant())',
}

REVIEW_TABLES = PRIVATE | DIRECT | frozenset(DERIVED) | frozenset(SPECIAL)
IDENTIFIER = re.compile(r'^[a-z][a-z0-9_]*$')
EXPECTED_SCHEMA_HASH = 'd6bded1247a0962cc5e12c99f9aa96e0d95a2fb78fbdc04102b75563c845d9ca'
EXPECTED_OBJECT_HASH = '9fe81b16768b7f2a9bd904af2aedd577b6442dd0786d65115a8abf549f5d95dd'


class ReviewBlocked(RuntimeError):
    pass


def schema_contract(connection: sqlite3.Connection) -> dict:
    """Read-only complete-schema introspection, no customer row access."""
    if os.environ.get('JW_ENV','').lower() in ('prod','production'):
        raise ReviewBlocked('Production review generation prohibited')
    rows = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    tables = {r[0] for r in rows}
    if tables != EXPECTED_TABLES or REVIEW_TABLES != EXPECTED_TABLES:
        raise ReviewBlocked('Unreviewed or missing table; update explicit access classifications')
    columns = {}
    foreign_keys = {}
    for name in sorted(tables):
        cols={x[1] for x in connection.execute(f'PRAGMA table_info("{name}")').fetchall()}
        columns[name]=cols
        foreign_keys[name]=sorted([x[3],x[2],x[4]] for x in connection.execute(f'PRAGMA foreign_key_list("{name}")').fetchall())
        if name in DIRECT and 'org_id' not in cols:
            raise ReviewBlocked(f'Direct org_id key missing: {name}')
    required = {
        'organizations': {'id'},
        'messenger_connections': {'id','org_a','org_b'},
        'messenger_messages': {'id','connection_id'},
        'messenger_edits': {'message_id'},
        'messenger_attachments': {'message_id'},
        'messenger_receipts': {'message_id'},
        'quote_items': {'quote_id'},
        'order_items': {'order_id'},
        'invoice_items': {'invoice_id'},
    }
    for name, needed in required.items():
        if not needed <= columns[name]:
            raise ReviewBlocked(f'Policy relationship column missing: {name}')
    source_descriptor = {'columns': {key:sorted(value) for key,value in columns.items()}, 'foreign_keys':foreign_keys}
    actual_hash = hashlib.sha256(json.dumps(source_descriptor,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if actual_hash != EXPECTED_SCHEMA_HASH:
        raise ReviewBlocked('Source schema/relationship fingerprint changed; manual review required')
    objects=[list(row) for row in connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name").fetchall()]
    object_hash=hashlib.sha256(json.dumps(objects,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if object_hash != EXPECTED_OBJECT_HASH:
        raise ReviewBlocked('Source DDL/index/trigger changed; manual review required')
    policy_groups={
        'private':sorted(PRIVATE), 'direct':sorted(DIRECT),
        'derived':sorted(DERIVED), 'special':sorted(SPECIAL),
    }
    sha=hashlib.sha256(json.dumps(policy_groups,sort_keys=True).encode()).hexdigest()
    return {'tables':len(tables),'private':len(PRIVATE),'direct':len(DIRECT),
            'derived':len(DERIVED),'special':len(SPECIAL),'plan_sha256':sha,
            'source_schema_sha256':actual_hash, 'source_ddl_sha256':object_hash,
            'all_tables_accounted_for':True,
            'postgres_executed':False,'production_rls_approved':False}


def generate_lab_sql(connection: sqlite3.Connection) -> str:
    schema_contract(connection)
    columns = {}
    for table in sorted(REVIEW_TABLES):
        columns[table] = sorted(x[1] for x in connection.execute(f'PRAGMA table_info("{table}")').fetchall())
    sql = [
        '-- JARVIS WORKS V7.8: 35-table, SELECT-only PostgreSQL 17 RLS REVIEW.',
        '-- SYNTHETIC LAB ONLY. NO PRODUCTION USE. NO APP STORAGE CUTOVER.',
        '-- Requires existing jw_guard.current_tenant() signed-session function.',
        '-- This review is not a replacement for the write-side RLS and FK guards.',
        'BEGIN;',
        "DO $lab$ BEGIN",
        " IF current_database() !~ '^jw_v20_test_[0-9a-f]{12}$' OR current_user <> 'postgres'",
        "    OR current_setting('server_version_num')::integer / 10000 <> 17 THEN",
        "   RAISE EXCEPTION 'Disposable PostgreSQL 17 test administrator required';",
        ' END IF;',
        " IF to_regprocedure('jw_guard.current_tenant()') IS NULL THEN",
        "   RAISE EXCEPTION 'Signed tenant context required'; END IF;",
        " IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='jw_app' AND NOT rolsuper AND NOT rolbypassrls AND NOT rolcreaterole) THEN",
        "   RAISE EXCEPTION 'Unprivileged application review role required'; END IF;",
        " IF EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_roles r ON r.oid=c.relowner",
        "    WHERE n.nspname='public' AND c.relname=ANY(ARRAY[" + ','.join("'"+t+"'" for t in sorted(REVIEW_TABLES)) + "]) AND r.rolname='jw_app') THEN",
        "   RAISE EXCEPTION 'Application role owns a table; abort'; END IF;",
        " IF (SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename=ANY(ARRAY[" + ','.join("'"+t+"'" for t in sorted(REVIEW_TABLES)) + "])) <> 35 THEN",
        "   RAISE EXCEPTION 'Missing target tables'; END IF;",
        " IF EXISTS(SELECT 1 FROM pg_policies WHERE schemaname='public' AND tablename=ANY(ARRAY[" + ','.join("'"+t+"'" for t in sorted(REVIEW_TABLES)) + "])) THEN",
        "   RAISE EXCEPTION 'Existing policies require manual review; refusing additive permissive policies'; END IF;",
        "END; $lab$;",
        'DO $columns$ BEGIN',
    ]
    for table in sorted(REVIEW_TABLES):
        expected = 'ARRAY[' + ','.join("'"+col+"'" for col in columns[table]) + ']::text[]'
        sql.append(
            f" IF (SELECT array_agg(attname::text ORDER BY attname) FROM pg_attribute WHERE attrelid='public.\"{table}\"'::regclass AND attnum>0 AND NOT attisdropped) IS DISTINCT FROM {expected} THEN"
        )
        sql.append(f" RAISE EXCEPTION 'Column drift: {table}'; END IF;")
    sql.extend([
        'END; $columns$;',
        'REVOKE CREATE ON SCHEMA public FROM PUBLIC;',
        'GRANT USAGE ON SCHEMA public TO jw_app;',
    ])
    for table in sorted(REVIEW_TABLES):
        if not IDENTIFIER.fullmatch(table):
            raise ReviewBlocked('Invalid identifier')
        quoted='public."'+table+'"'
        sql.extend([
            f'REVOKE ALL ON TABLE {quoted} FROM PUBLIC, jw_app;',
            f'ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY;',
            f'ALTER TABLE {quoted} FORCE ROW LEVEL SECURITY;',
        ])
        if table in PRIVATE:
            # No SELECT privilege granted; no policy created, default-deny.
            continue
        if table in DIRECT:
            predicate='org_id=jw_guard.current_tenant()'
        elif table in DERIVED:
            predicate=DERIVED[table]
        else:
            predicate=SPECIAL[table]
        sql.extend([
            f'CREATE POLICY jw_v78_review_select ON {quoted} FOR SELECT TO jw_app USING ({predicate});',
            f'GRANT SELECT ON TABLE {quoted} TO jw_app;',
        ])
    sql.extend([
        '-- Require a separate attack test under jw_app before considering any release.',
        '-- This script only grants SELECT; application INSERT/UPDATE/DELETE are intentionally denied.',
        'COMMIT;',
    ])
    return '\n'.join(sql)+'\n'
