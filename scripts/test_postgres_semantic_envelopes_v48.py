"""V4.8 real disposable PG17 semantic envelope test, after V4.7 success."""
from __future__ import annotations
import os
import sys


def run() -> int:
    if (os.environ.get('JW_ENV', '').casefold() == 'production'
        or os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.environ.get('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'
        or any(os.environ.get(f'JW_PG_LAB_V{v}') != 'ONLY_DISPOSABLE_LAB'
               for v in range(35, 49))):
        print('NOT RUN: V4.8 disposable semantic gate not authorized')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from app.pg_cutover_readiness_v46 import LAB_DATABASE
        from app.pg_semantic_envelope_v48 import rehearse_semantic_envelopes
        from app.pg_migration_shadow_v36 import source_records
        from scripts.v36_synthetic_fixture import fixture
        dsn = os.environ['JW_PG_TEST_ADMIN_DSN']
        options = conninfo_to_dict(dsn)
        if not (set(options) <= {'dbname', 'user', 'host', 'port', 'password'}
                and LAB_DATABASE.fullmatch(options.get('dbname', ''))
                and options.get('user') == 'postgres'
                and options.get('host') in ('127.0.0.1','localhost','::1')
                and options.get('password')):
            print('NOT RUN: V4.8 target not an approved disposable database')
            return 2
    except (ImportError, KeyError, ValueError, TypeError):
        print('NOT RUN: V4.8 prerequisites unavailable')
        return 2
    stage = 'synthetic-source'
    try:
        source = fixture()
        try:
            records = source_records(source)
        finally:
            source.close()
        stage = 'ephemeral-semantic-transaction'
        with psycopg.connect(dsn, connect_timeout=5, autocommit=True) as pg:
            result = rehearse_semantic_envelopes(pg, records)
        if (result.decision != 'BLOCKED' or result.cutover_approved is not False
                or not result.rollback_verified or not result.force_rls_preserved
                or result.attachments_as_candidate_kind < 1 or result.rows < 7):
            raise RuntimeError('Semantic proof incomplete')
        print('PASS: V4.8 real PG17 synthetic semantic bytes, attachment-kind projection, '
              'order/receipt evidence and unconditional rollback')
        print('BLOCKED: V4.8 operational cutover DENIED; semantic sidecar is not '
              'a live message writer or an approved identity mapping')
        return 0
    except Exception as exc:
        print('FAIL: V4.8 stage=' + stage + ' code=' + type(exc).__name__ +
              ' (contents, credentials and DSN redacted)', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(run())
