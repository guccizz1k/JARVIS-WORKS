"""V4.2: disposable PostgreSQL 17 transactional logical-mirror restore drill.

No physical database backup, production data, server restart, network listener,
permanent database mutation, deployment, or live PostgreSQL cutover.
"""
from __future__ import annotations

import os
import re
import sys

from app.pg_restore_consistency_v42 import RestoreMismatch, compare_mirror, evidence
from scripts.test_postgres_writer_v40 import _verified_lab_uri

SCHEMA = 'jw_restore_v42'
SQL_MESSAGES = '''SELECT id,connection_id,sender_org,sender_user,kind,body,request_id,message_seq
                  FROM {}.messenger_messages WHERE connection_id='chat_ab'
                  ORDER BY message_seq,id'''
SQL_COUNTERS = '''SELECT connection_id,last_seq FROM {}.messenger_counters
                  WHERE connection_id='chat_ab' ORDER BY connection_id'''


class InjectedRollback(RuntimeError):
    pass


def _read(cursor, schema):
    # Schema names are FIXED literals, never taken from clients or inputs.
    if schema not in ('public', SCHEMA):
        raise RestoreMismatch('Unexpected restore schema')
    counter_schema = 'jw_guard' if schema == 'public' else SCHEMA
    cursor.execute(SQL_MESSAGES.format(schema))
    messages = cursor.fetchall()
    cursor.execute(SQL_COUNTERS.format(counter_schema))
    return messages, cursor.fetchall()


def _check(cur, dbname):
    cur.execute('SELECT current_database(),current_user,current_setting(%s)', ('server_version_num',))
    db, user, ver = cur.fetchone()
    if db != dbname or user != 'postgres' or int(ver)//10000 != 17:
        raise RestoreMismatch('Only isolated PG17 supervisor allowed')


def _create(cur):
    cur.execute('CREATE SCHEMA jw_restore_v42 AUTHORIZATION postgres')
    cur.execute('REVOKE ALL ON SCHEMA jw_restore_v42 FROM PUBLIC')
    cur.execute('''CREATE TABLE jw_restore_v42.messenger_messages
                   (LIKE public.messenger_messages INCLUDING ALL)''')
    cur.execute('''CREATE TABLE jw_restore_v42.messenger_counters
                   (LIKE jw_guard.messenger_counters INCLUDING ALL)''')


def _copy(cur):
    cur.execute('''INSERT INTO jw_restore_v42.messenger_messages
                   SELECT * FROM public.messenger_messages WHERE connection_id='chat_ab' ''')
    cur.execute('''INSERT INTO jw_restore_v42.messenger_counters
                   SELECT * FROM jw_guard.messenger_counters WHERE connection_id='chat_ab' ''')


def run() -> int:
    if (os.getenv('JW_PG_LAB_V42') != 'ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_LAB_V41') != 'ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'):
        print('NOT RUN: V4.2 disposable PostgreSQL mirror gate not authorized')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from app.pg_messenger_review import MessengerReviewAdapter
        admin = os.getenv('JW_PG_TEST_ADMIN_DSN', '')
        app = os.getenv('JW_PG_TEST_APP_DSN', '')
        a, b = conninfo_to_dict(admin), conninfo_to_dict(app)
        app_uri = _verified_lab_uri(a, b)
        MessengerReviewAdapter(app_uri)._check_dsn()
        dbname = a['dbname']
        if not re.fullmatch(r'jw_v20_test_[0-9a-f]{12}', dbname):
            raise ValueError('Unexpected database')
    except (ImportError, KeyError, RuntimeError, ValueError, TypeError):
        print('NOT RUN: V4.2 safe disposable PG17 or driver unavailable')
        return 2

    stage = 'preflight'
    created = False
    status = 1
    try:
        with psycopg.connect(admin, autocommit=True, connect_timeout=5) as pg:
            with pg.cursor() as cur:
                _check(cur, dbname)
                cur.execute('SELECT to_regnamespace(%s)', (SCHEMA,))
                if cur.fetchone()[0] is not None:
                    raise RestoreMismatch('Restore schema already exists: refuse overwrite')
                source = _read(cur, 'public')
                checkpoint = evidence(*source)
                if checkpoint['messages'] < 2:
                    raise RestoreMismatch('Required synthetic messenger source missing')

            stage = 'injected-restore-rollback'
            try:
                with pg.transaction():
                    with pg.cursor() as cur:
                        _create(cur)
                        _copy(cur)
                        raise InjectedRollback('synthetic failure after row copying')
            except InjectedRollback:
                pass
            with pg.cursor() as cur:
                cur.execute('SELECT to_regnamespace(%s)', (SCHEMA,))
                if cur.fetchone()[0] is not None:
                    raise RestoreMismatch('Failed transaction left a partial restore schema')
                if evidence(*_read(cur, 'public')) != checkpoint:
                    raise RestoreMismatch('Source changed after injected rollback')

            stage = 'independent-restore'
            with pg.transaction():
                with pg.cursor() as cur:
                    _create(cur)
                    _copy(cur)
            created = True
            with pg.cursor() as cur:
                compare_mirror(*source, *_read(cur, SCHEMA))

            stage = 'forbid-tenant-backup-access'
            with psycopg.connect(app_uri, connect_timeout=5) as tenant:
                with tenant.cursor() as cur:
                    try:
                        cur.execute('SELECT COUNT(*) FROM jw_restore_v42.messenger_messages')
                    except psycopg.Error as ex:
                        if ex.sqlstate != '42501':
                            raise RestoreMismatch('Unexpected mirror denial SQLSTATE') from None
                    else:
                        raise RestoreMismatch('Unprivileged tenant can read restore evidence')

            stage = 'detect-tamper-and-rollback'
            with pg.cursor() as cur:
                cur.execute('SELECT id FROM jw_restore_v42.messenger_messages LIMIT 1')
                target = cur.fetchone()[0]
            try:
                with pg.transaction():
                    with pg.cursor() as cur:
                        cur.execute('UPDATE jw_restore_v42.messenger_messages SET body=%s WHERE id=%s',
                                    ('injected mirror tamper', target))
                        compare_mirror(*source, *_read(cur, SCHEMA))
                raise RestoreMismatch('Modified mirror evidence was incorrectly accepted')
            except RestoreMismatch as ex:
                if str(ex) != 'Mirror evidence differed from sealed checkpoint':
                    raise
            with pg.cursor() as cur:
                compare_mirror(*source, *_read(cur, SCHEMA))
                if evidence(*_read(cur, 'public')) != checkpoint:
                    raise RestoreMismatch('Primary synthetic data changed in mirror trial')
        print('PASS: V4.2 real PG17 transactional logical mirror restore, exact SHA256, '
              'counter consistency, tamper rollback, tenant denial and source preservation')
        status = 0
    except Exception as ex:
        print('FAIL: V4.2 logical restore stage=' + stage + ' type=' + type(ex).__name__
              + ' (details redacted)', file=sys.stderr)
    finally:
        if created:
            try:
                with psycopg.connect(admin, autocommit=True, connect_timeout=5) as pg:
                    with pg.cursor() as cur:
                        _check(cur, dbname)
                        cur.execute('DROP SCHEMA IF EXISTS jw_restore_v42 CASCADE')
                        cur.execute('SELECT to_regnamespace(%s)', (SCHEMA,))
                        if cur.fetchone()[0] is not None:
                            raise RestoreMismatch('Failed to clean logical restore schema')
            except Exception as ex:
                status = 1
                print('FAIL: V4.2 isolated restore schema cleanup '+type(ex).__name__, file=sys.stderr)
    return status


if __name__ == '__main__':
    raise SystemExit(run())
