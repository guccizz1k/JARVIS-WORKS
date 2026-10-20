"""V4.6: read-only live PG17 catalog audit after all V4.5 tests pass."""
from __future__ import annotations
import os
import sys


def run() -> int:
    if (os.environ.get('JW_ENV', '').casefold() == 'production'
        or os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.environ.get('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'
        or any(os.environ.get(f'JW_PG_LAB_V{v}') != 'ONLY_DISPOSABLE_LAB'
               for v in range(35, 47))):
        print('NOT RUN: V4.6 synthetic PostgreSQL catalog gate not authorized')
        return 2
    try:
        from psycopg import connect
        from psycopg.conninfo import conninfo_to_dict
        from app.pg_cutover_readiness_v46 import (
            LAB_DATABASE, TABLES, AuditBlocked, sqlite_contract,
            postgres_inventory, audit_cutover_gap,
        )
        from scripts.v36_synthetic_fixture import fixture
        uri = os.environ['JW_PG_TEST_ADMIN_DSN']
        config = conninfo_to_dict(uri)
        if not (LAB_DATABASE.fullmatch(config.get('dbname', ''))
                and config.get('user') == 'postgres'
                and config.get('host') in ('localhost', '127.0.0.1', '::1')
                and config.get('password')):
            print('NOT RUN: V4.6 non-disposable PostgreSQL target')
            return 2
    except (ImportError, KeyError, ValueError, TypeError):
        print('NOT RUN: V4.6 database prerequisites unavailable')
        return 2
    phase = 'source-contract'
    try:
        source = fixture()
        try:
            columns = sqlite_contract(source)
        finally:
            source.close()
        phase = 'readonly-catalog'
        with connect(uri, connect_timeout=5) as db:
            with db.cursor() as cur:
                cur.execute('SET TRANSACTION READ ONLY')
                inventory = postgres_inventory(cur)
                phase = 'fail-closed-decision'
                report = audit_cutover_gap(columns, inventory)
        if report['decision'] != 'BLOCKED' or report['cutover_approved'] is not False:
            raise AuditBlocked('Cutover unexpectedly approved')
        if report['seven_tables_checked'] != len(TABLES):
            raise AuditBlocked('Not all seven tables inspected')
        if report['rls_not_forced']:
            raise AuditBlocked('Forced RLS lost')
        essential = report['missing_essential_fields']
        for table in ('messenger_messages','messenger_attachments',
                      'messenger_receipts','messenger_read_positions'):
            if table not in essential:
                raise AuditBlocked('Expected documented legacy gap disappeared; audit required')
        print('PASS: V4.6 read-only PG17 seven-table operational schema audit; '
              'forced-RLS verified; unsupported cutover DENIED')
        print('BLOCKED: V4.6 operational cutover: '+','.join(report['reason_codes']))
        return 0
    except Exception as exc:
        print('FAIL: V4.6 phase='+phase+' code='+type(exc).__name__+
              ' (database details suppressed)', file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(run())
