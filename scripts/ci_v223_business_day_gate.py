"""Transaction-local KST date/role restoration on disposable loopback PG17.

The validated-cursor context is injected here to isolate transaction semantics;
real authentication/RLS and payment assertions remain in the existing 74 HTTPS gate.
No source database or persistent role is changed by this supplementary test.
"""
import os
import secrets
from contextlib import contextmanager
from datetime import date

import psycopg
from psycopg import sql
from app import pg_cinema_legacy_api_v1 as legacy
from app import pg_cinema_register_v1 as reg


def main():
    if (os.getenv('JW_CINEMA_PG_DISPOSABLE') != '1'
            or os.getenv('PGHOST') not in ('localhost', '127.0.0.1')):
        raise SystemExit('BLOCKED: disposable loopback PG17 required')
    name = 'jw_day_' + secrets.token_hex(8)
    password = secrets.token_urlsafe(32)
    created_db = created_login = False
    original = reg._v90._pg_validated_cursor
    checks = 0
    with psycopg.connect(dbname='postgres', autocommit=True) as admin:
        assert int(admin.execute('SHOW server_version_num').fetchone()[0]) >= 170000
        # These roles belong to the preceding disposable engine setup. Never
        # create/drop/alter pre-existing engine or source roles in this gate.
        assert admin.execute('SELECT to_regrole(%s),to_regrole(%s)',
                             (legacy.WRITER_ROLE, reg.OWNER_ROLE)).fetchone() == (legacy.WRITER_ROLE, reg.OWNER_ROLE)
        try:
            admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
            created_db = True
            admin.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOBYPASSRLS PASSWORD {}').format(sql.Identifier(name), sql.Literal(password)))
            created_login = True
            admin.execute(sql.SQL('GRANT {} TO {} WITH INHERIT FALSE, SET TRUE').format(sql.Identifier(legacy.WRITER_ROLE), sql.Identifier(name)))
            with psycopg.connect(dbname=name, autocommit=True) as setup:
                setup.execute('CREATE SCHEMA jw_dev')
                for table in ('quotes','orders','invoices','payments'):
                    setup.execute(sql.SQL('CREATE TABLE jw_dev.{}(org_id text)').format(sql.Identifier(table)))
                setup.execute(sql.SQL('GRANT USAGE ON SCHEMA jw_dev TO {}').format(sql.Identifier(name)))
                setup.execute(sql.SQL('GRANT SELECT ON ALL TABLES IN SCHEMA jw_dev TO {}').format(sql.Identifier(name)))
            with psycopg.connect(dbname=name, user=name, password=password, autocommit=True,
                                 options='-c timezone=UTC') as conn:
                @contextmanager
                def connection():
                    yield conn

                @contextmanager
                def validated(_session_hash):
                    with conn.transaction(), conn.cursor() as cursor:
                        yield cursor, ('synthetic-actor','admin','synthetic-org')

                reg._v90._pg_validated_cursor = validated
                for gateway in (legacy.WriterTx(connection), legacy.ValidatedLegacyTx()):
                    for rollback in (False, True):
                        def work(cursor):
                            nonlocal checks
                            row = cursor.execute("SELECT current_setting('TimeZone'),current_user,current_date = (CURRENT_TIMESTAMP AT TIME ZONE 'Asia/Seoul')::date,('2026-11-16 16:00:00+00'::timestamptz)::date").fetchone()
                            assert row == ('Asia/Seoul',legacy.WRITER_ROLE,True,date(2026,11,17))
                            checks += 1
                            if rollback:
                                raise RuntimeError('SYNTHETIC_ROLLBACK')
                        try:
                            gateway.run('synthetic-session-hash', work)
                        except RuntimeError as error:
                            assert rollback and str(error) == 'SYNTHETIC_ROLLBACK'
                        assert conn.execute("SELECT current_setting('TimeZone'),current_user").fetchone() == ('UTC',name)
                        checks += 1
            assert checks == 8
        finally:
            reg._v90._pg_validated_cursor = original
            if created_db:
                admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
            if created_login:
                admin.execute(sql.SQL('DROP ROLE {}').format(sql.Identifier(name)))
    print('PASS_V223_KST_TRANSACTION_DAY checks=8 commit_and_rollback_restored=true synthetic_only=true')


if __name__ == '__main__':
    main()
