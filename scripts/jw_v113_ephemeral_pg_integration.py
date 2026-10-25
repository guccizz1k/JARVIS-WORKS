"""V11.3 manual-only disposable PG17 proof: NOTIFY and OCR concurrency.

Root access is permitted only on a fresh local PG17 cluster; all test data
is synthetic; all objects are dropped. Never run against Render or Supabase.
This runner is not executed by GitHub until explicitly approved.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _preflight(psycopg, parse, dsn):
    if os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE':
        raise RuntimeError('CI_DISPOSABLE_ACK_REQUIRED')
    try:
        info = parse(dsn)
        if (set(info) - {'host','port','dbname','user','password','connect_timeout'}
            or info.get('host') != '127.0.0.1'
            or info.get('port','5432') != '5432'
            or info.get('dbname') != 'postgres'
            or info.get('user') != 'postgres'
            or not 1 <= int(info.get('connect_timeout','5')) <= 5):
            raise RuntimeError('REFUSE_ANY_NONLOCAL_OR_NONROOT_DATABASE')
    except Exception as exc:
        raise RuntimeError('REFUSE_ANY_NONLOCAL_OR_NONROOT_DATABASE') from None
    with psycopg.connect(dsn,connect_timeout=5) as root:
        with root.cursor() as c:
            c.execute("SELECT current_setting('server_version_num')::integer/10000")
            if c.fetchone() != (17,): raise RuntimeError('PG17_REQUIRED')
            c.execute("""SELECT count(*) FROM pg_catalog.pg_database
                         WHERE NOT datistemplate AND datname<>'postgres'""")
            if c.fetchone() != (0,): raise RuntimeError('NONEMPTY_CLUSTER_DENIED')
            c.execute("""SELECT count(*) FROM pg_catalog.pg_roles
                         WHERE rolname<>'postgres' AND rolname !~ '^pg_'""")
            if c.fetchone() != (0,): raise RuntimeError('FOREIGN_ROLE_DENIED')


def _notification(conn, seconds=1.0):
    return list(conn.notifies(timeout=seconds,stop_after=1))


def _prove(psycopg, dsn):
    from app.pg_v112_ocr_queue import PgOcrQueue
    from app.pg_v112_wakeup import CHANNEL, digest_connection
    with psycopg.connect(dsn,autocommit=True) as first, \
         psycopg.connect(dsn,autocommit=True) as second:
        for listener in (first,second):
            with listener.cursor() as c:
                c.execute('LISTEN ' + CHANNEL)
        with psycopg.connect(dsn) as writer:
            with writer.cursor() as c:
                c.execute("""INSERT INTO jw_dev.messenger_connections
                  (id,org_a,org_b,requester_org,status,created_at)
                  VALUES ('ci-chat','ci-a','ci-b','ci-a','active',now()::text)""")
        with psycopg.connect(dsn) as writer:
            with writer.cursor() as c:
                c.execute("""INSERT INTO jw_dev.messenger_messages
                  (id,connection_id,sender_org,sender_user,kind,body,actor_name,
                   request_id,version,created_at,message_seq)
                  VALUES ('ci-rollback','ci-chat','ci-a','ci-ua','text','ROLLBACK',
                   'A','ci-rollback',1,now()::text,1)""")
            writer.rollback()
        assert not _notification(first,.2) and not _notification(second,.2)
        with psycopg.connect(dsn) as writer:
            with writer.cursor() as c:
                c.execute("""INSERT INTO jw_dev.messenger_messages
                  (id,connection_id,sender_org,sender_user,kind,body,actor_name,
                   request_id,version,created_at,message_seq)
                  VALUES ('ci-commit','ci-chat','ci-a','ci-ua','text','COMMIT',
                   'A','ci-commit',1,now()::text,1)""")
        for listener in (first,second):
            got=_notification(listener)
            assert len(got)==1 and got[0].channel==CHANNEL
            assert got[0].payload==digest_connection('ci-chat')
        with psycopg.connect(dsn) as writer:
            with writer.cursor() as c:
                c.execute("""INSERT INTO jw_dev.messenger_edits
                  (id,message_id,previous_body,new_body,actor_user,edited_at,version)
                  VALUES('ci-edit','ci-commit','old','new','ci-ua',now()::text,2)""")
        for listener in (first,second):
            got=_notification(listener)
            assert len(got)==1 and got[0].payload==digest_connection('ci-chat')
    q=PgOcrQueue(lambda:psycopg.connect(dsn,connect_timeout=5))
    obj='tenant/ci-a/'+'a'*32
    kwargs=dict(org_id='ci-a',actor_id='ci-ua',object_key=obj,
                filename='scan.pdf',sha256='b'*64,request_id='ci-request-123')
    job,created=q.submit(**kwargs)
    assert created and len(job)==32
    assert q.submit(**kwargs)==(job,False)
    try:
        q.submit(**{**kwargs,'actor_id':'ci-ub','request_id':'ci-request-124'})
    except psycopg.errors.CheckViolation:
        pass
    else:
        raise AssertionError('DB allowed other company actor')
    with ThreadPoolExecutor(max_workers=2) as pool:
        competing=list(pool.map(lambda _:q.claim(),range(2)))
    owned=[x for x in competing if x is not None]
    assert len(owned)==1 and owned[0].id==job
    old=owned[0]
    with psycopg.connect(dsn) as db:
        with db.cursor() as c:
            c.execute("""UPDATE jw_dev.ocr_jobs_v112
                 SET lease_until=clock_timestamp()-interval '1 second'
                 WHERE id=%s""",(job,))
    new=q.claim()
    assert new and new.id==job and new.lease_token!=old.lease_token
    stale=f'tenant/ci-a/ocr-result/{job}/{old.lease_token}'
    fresh=f'tenant/ci-a/ocr-result/{job}/{new.lease_token}'
    assert stale!=fresh and not q.complete(old,result_key=stale)
    assert q.complete(new,result_key=fresh)
    with psycopg.connect(dsn) as db:
        with db.cursor() as c:
            c.execute('SELECT state,result_key,attempts FROM jw_dev.ocr_jobs_v112 WHERE id=%s',(job,))
            assert c.fetchone()==('needs_review',fresh,2)
    return {'commit_two_listeners':'PASS','rollback_no_notify':'PASS',
            'edits_notify':'PASS','ocr_idempotency':'PASS',
            'actor_org_check':'PASS','concurrent_skip_locked':'PASS',
            'lease_result_fencing':'PASS','full_business_e2e':'NOT_RUN',
            '2_render_instances':'NOT_RUN'}


def main():
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import conninfo_to_dict, make_conninfo
    root=os.getenv('JW_PG_CI_ROOT_DSN','')
    _preflight(psycopg,conninfo_to_dict,root)
    name='jw_v112_ci_'+secrets.token_hex(6)
    created=False
    try:
        with psycopg.connect(root,autocommit=True) as c:
            with c.cursor() as cur:
                cur.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
                created=True
        dsn=make_conninfo(root,dbname=name)
        with psycopg.connect(dsn,autocommit=True) as db:
            with db.cursor() as cur:
                cur.execute('CREATE ROLE jw_app_dev NOLOGIN NOINHERIT NOBYPASSRLS')
                cur.execute((ROOT/'db/review/ci_v90_ephemeral_pg_schema.sql').read_text())
                cur.execute((ROOT/'db/review/v112_ephemeral_only_pg.sql').read_text())
        result=_prove(psycopg,dsn)
        print('JW_V113_PG17_EPHEMERAL_ONLY',result,flush=True)
        return 0
    finally:
        if created:
            with psycopg.connect(root,autocommit=True) as db:
                with db.cursor() as cur:
                    cur.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
                    cur.execute('DROP ROLE IF EXISTS jw_app_dev')


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception:
        print('BLOCKED: PG17 disposable integration failed (redacted)',file=sys.stderr)
        raise SystemExit(3)
