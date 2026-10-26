"""Actual PG17 V3.6 disposable shadow/rollback gate (not operational cutover)."""
import os
import re
import sys

from app.pg_migration_shadow_v36 import (MigrationBlocked, source_records,
    stage_shadow, verify_shadow, drop_shadow, operational_cutover_blockers)
from scripts.v36_synthetic_fixture import fixture


def run():
    if (os.environ.get('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE'
        or os.environ.get('JW_PG_LAB_V36')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V3.6 disposable-only authorization missing')
        return 2
    admin_dsn=os.environ.get('JW_PG_TEST_ADMIN_DSN','')
    app_dsn=os.environ.get('JW_PG_TEST_APP_DSN','')
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
    except ImportError:
        print('NOT RUN: psycopg3 missing')
        return 2
    try:
        a=conninfo_to_dict(admin_dsn)
        b=conninfo_to_dict(app_dsn)
        if (not re.fullmatch(r'jw_v20_test_[a-f0-9]{12}', a.get('dbname',''))
            or a.get('user')!='postgres' or b.get('user')!='jw_app'
            or a.get('dbname')!=b.get('dbname')
            or a.get('host') not in ('127.0.0.1','localhost','::1')
            or b.get('host') not in ('127.0.0.1','localhost','::1')
            or not a.get('password') or not b.get('password')):
            print('NOT RUN: non-ephemeral PostgreSQL target refused')
            return 2
    except (ValueError,TypeError):
        print('NOT RUN: missing or invalid isolated PostgreSQL credentials')
        return 2
    db=fixture()
    try:
        records=source_records(db)
        blockers=operational_cutover_blockers(records)
        assert {'ORDER_SNAPSHOT_FIELDS_MISSING_IN_PG_SCHEMA',
          'LEGACY_ATTACHMENT_MESSAGE_KIND_INCOMPATIBLE',
          'RECEIPT_EVIDENCE_FIELDS_DIFFER'}.issubset(set(blockers))
        with psycopg.connect(admin_dsn,autocommit=True,connect_timeout=5) as pg:
            # Intentional mid-write failure must roll back even CREATE SCHEMA.
            try:
                stage_shadow(pg,records,inject_failure_after=2)
                raise AssertionError('Injected failure was not applied')
            except MigrationBlocked as exc:
                assert str(exc)=='Injected rollback test'
            with pg.cursor() as cur:
                cur.execute("SELECT to_regnamespace('jw_migration_v36')")
                assert cur.fetchone()==(None,), 'Rollback left a partially copied schema'
            stage_shadow(pg,records)
            verified=verify_shadow(pg,records)
            assert verified['rows']==len(records) and len(verified['tables'])==7
            with psycopg.connect(app_dsn) as user_db:
                try:
                    with user_db.cursor() as cur:
                        cur.execute('SELECT COUNT(*) FROM jw_migration_v36.records')
                    raise AssertionError('jw_app can read protected shadow evidence')
                except psycopg.Error as exc:
                    assert exc.sqlstate=='42501', 'Unexpected shadow privilege failure'
                    user_db.rollback()
            # Database check constraints reject tampering with copied bytes.
            try:
                with pg.transaction():
                    with pg.cursor() as cur:
                        cur.execute("UPDATE jw_migration_v36.records SET payload=%s WHERE entity=%s AND row_key=%s",
                                    (b'tampered','messenger_attachments',next(r.row_key for r in records if r.entity=='messenger_attachments')))
                raise AssertionError('Byte tampering was not rejected')
            except psycopg.Error as exc:
                assert exc.sqlstate=='23514', 'Unexpected content hash constraint error'
            verify_shadow(pg,records)
            drop_shadow(pg)
            with pg.cursor() as cur:
                cur.execute("SELECT to_regnamespace('jw_migration_v36')")
                assert cur.fetchone()==(None,), 'Shadow cleanup failed'
        print('PASS: V3.6 real PG17 synthetic SQLite shadow copy, exact SHA-256, cross-role denial, forced rollback and cleanup')
        print('BLOCKED: Production cutover incompatible legacy order/attachment/receipt semantics (no live migration)')
        return 0
    except Exception as exc:
        print('FAIL: V3.6 PG17 shadow gate: '+type(exc).__name__+' (details redacted)',file=sys.stderr)
        return 1
    finally:
        db.close()

if __name__=='__main__':
    raise SystemExit(run())
