"""Read-only, bounded SQLite/Postgres comparison. Review-only; no migration writes.

All table names are code-whitelisted; generated report contains only counts and hashes,
not customer data. Not a replacement for an actual V8.9 migration/cutover rehearsal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable, Mapping

TABLES = frozenset('''audit_logs automation_document_drafts_v62 automation_statements_v60 automation_task_times_v60
customers evidence_lines_v66 evidence_links_v65 evidence_previews_v64 evidence_records_v64 import_previews
invoice_adjustment_decisions_v69 invoice_adjustments_v69 invoice_items invoices login_failures
messenger_attachments messenger_companies messenger_connections messenger_edits messenger_messages
messenger_read_positions messenger_receipts mfa_credentials mfa_recovery_codes order_items orders
organizations payments quote_items quotes reconciliation_reviews_v67 security_events sessions
staff_disabled users'''.split())
assert len(TABLES) == 35
LIMIT = 100_000


def normalize(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {'$binary_sha256': hashlib.sha256(bytes(value)).hexdigest(), '$bytes': len(value)}
    if isinstance(value, Decimal):
        return {'$decimal': str(value)}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [normalize(v) for v in value]
    if isinstance(value, dict):
        return {str(k): normalize(v) for k, v in sorted(value.items())}
    return str(value)


def fingerprint(rows: Iterable[Mapping[str, Any]], *, limit: int = LIMIT) -> dict[str, Any]:
    """Stable row-order-independent hash for small/medium staging snapshots.

    Fail instead of silently truncating. Digest includes duplicate rows.
    """
    if limit < 1:
        raise ValueError('limit must be positive')
    serialized = []
    for row in rows:
        if len(serialized) >= limit:
            raise ValueError('audit snapshot exceeded explicit row cap')
        serialized.append(json.dumps(normalize(dict(row)), sort_keys=True,
                                     ensure_ascii=False, separators=(',', ':')))
    serialized.sort()
    h = hashlib.sha256()
    for item in serialized:
        payload=item.encode('utf-8')
        h.update(len(payload).to_bytes(8, 'big'))
        h.update(payload)
    return {'count': len(serialized), 'sha256': h.hexdigest()}


def compare(source: Iterable[Mapping[str, Any]], target: Iterable[Mapping[str, Any]],
            *, limit: int = LIMIT) -> dict[str, Any]:
    left=fingerprint(source, limit=limit)
    right=fingerprint(target, limit=limit)
    return {'source': left, 'target': right, 'status': 'PASS' if left==right else 'FAIL'}


def audit(sqlite_path: str, pg_conn: Any, tables: Iterable[str]) -> dict[str, Any]:
    names=sorted(set(tables))
    if not names or any(name not in TABLES for name in names):
        raise ValueError('Requested table is not in reviewed schema whitelist')
    uri=Path(sqlite_path).resolve().as_uri()+'?mode=ro'
    details={}
    with sqlite3.connect(uri,uri=True) as source, pg_conn.cursor() as pg:
        source.row_factory=sqlite3.Row
        pg.execute('SET TRANSACTION READ ONLY')
        for table in names:
            # SQL names ONLY from the fixed TABLES whitelist, never request values.
            src=[dict(r) for r in source.execute('SELECT * FROM "'+table+'" LIMIT '+str(LIMIT+1))]
            pg.execute('SELECT * FROM jw_dev."'+table+'" LIMIT '+str(LIMIT+1))
            fields=[desc.name for desc in pg.description]
            dst=[dict(zip(fields,row)) for row in pg.fetchmany(LIMIT+1)]
            details[table]=compare(src,dst)
    return {'status':'PASS' if all(v['status']=='PASS' for v in details.values()) else 'FAIL',
            'tables':details, 'mode':'READ_ONLY_COMPARISON'}


def main():
    parser=argparse.ArgumentParser(description='Read-only V9 migration consistency audit')
    parser.add_argument('--sqlite',required=True)
    parser.add_argument('--tables',nargs='+',required=True)
    parser.add_argument('--dsn-env',default='JW_V90_AUDIT_DSN')
    args=parser.parse_args()
    if any(x not in TABLES for x in args.tables):
        parser.error('Table is not in allowlist')
    dsn=os.environ.get(args.dsn_env)
    if not dsn:
        parser.error('Approved read-only PostgreSQL DSN environment variable not set')
    try:
        import psycopg
    except ImportError:
        parser.error('psycopg is required for live comparison')
    # No migrations, deletes, upserts, or file disclosure in this utility.
    with psycopg.connect(dsn, connect_timeout=5, options='-c default_transaction_read_only=on') as conn:
        result=audit(args.sqlite,conn,args.tables)
    print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result['status']=='PASS' else 1

if __name__=='__main__':
    raise SystemExit(main())
