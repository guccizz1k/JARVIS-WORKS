"""Real PG17 disposable catalog/rollback rehearsal after historical V4.6 gate."""
from __future__ import annotations

import os
import sys


def run() -> int:
    if (os.getenv('JW_ENV', '').casefold() == 'production'
        or os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
        or os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{v}') != 'ONLY_DISPOSABLE_LAB'
               for v in range(35, 48))):
        print('NOT RUN: V4.7 disposable rollback rehearsal not authorized')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from app.pg_cutover_readiness_v46 import LAB_DATABASE, sqlite_contract
        from app.pg_lossless_projection_v47 import rehearse_additive_columns
        from scripts.v36_synthetic_fixture import fixture
        uri = os.environ['JW_PG_TEST_ADMIN_DSN']
        settings = conninfo_to_dict(uri)
        if not (set(settings).issubset({'dbname', 'user', 'host', 'port', 'password'})
                and LAB_DATABASE.fullmatch(settings.get('dbname', ''))
                and settings.get('user') == 'postgres'
                and settings.get('host') in ('127.0.0.1', 'localhost', '::1')
                and settings.get('password') and not settings.get('options')):
            print('NOT RUN: V4.7 PG target is not approved disposable database')
            return 2
    except (ImportError, KeyError, ValueError, TypeError):
        print('NOT RUN: V4.7 live PG prerequisites unavailable')
        return 2
    phase = 'synthetic-source-contract'
    try:
        source = fixture()
        try:
            columns = sqlite_contract(source)
        finally:
            source.close()
        phase = 'rollback-only-column-rehearsal'
        with psycopg.connect(uri, connect_timeout=5, autocommit=True) as pg:
            result = rehearse_additive_columns(pg, columns)
        if (result.decision != 'BLOCKED' or result.cutover_approved is not False
                or not result.rollback_verified or not result.force_rls_preserved
                or result.projected_columns != 13):
            raise RuntimeError('Unverified field projection')
        print('PASS: V4.7 PG17 13-column additive rehearsal, exact SQL types, forced RLS and unconditional rollback')
        print('BLOCKED: V4.7 production cutover DENIED; semantics, identity, dual-write and rollback readiness unresolved')
        return 0
    except Exception as exc:
        print('FAIL: V4.7 phase=' + phase + ' code=' + type(exc).__name__ +
              ' (SQL, DSN, user data redacted)', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(run())
