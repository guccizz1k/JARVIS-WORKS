"""Opt-in LIVE PostgreSQL 17 V2.7 messenger attack test (fictional data only).

Works ONLY in the random, ephemeral jw_v20_test_* database created by the
existing isolated runner. Missing DSNs/consent/driver is NOT RUN (exit 2),
never PASS. Does not migrate/enable the SQLite FastAPI business application.
"""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import os
import secrets
import sys

REQUIRED_TABLES = {
    'messenger_companies': {'jw_v27_company_directory'},
    'messenger_connections': {'jw_v27_thread_read', 'jw_v27_thread_create'},
    'messenger_messages': {'jw_v27_message_read', 'jw_v27_message_send'},
    'messenger_edits': {'jw_v27_edits_read'},
    'messenger_attachments': {'jw_v27_attach_read', 'jw_v27_attach_write'},
    'messenger_read_positions': {'jw_v27_read_pos_read', 'jw_v27_read_pos_insert', 'jw_v27_read_pos_update'},
    'messenger_receipts': {'jw_v27_receipt_read', 'jw_v27_receipt_write'},
}


def validate_catalog(connection):
    """Compare actual PostgreSQL catalog, not file text."""
    issues=[]
    with connection.cursor() as c:
        c.execute('''SELECT relname,relrowsecurity,relforcerowsecurity
          FROM pg_class r JOIN pg_namespace n ON n.oid=r.relnamespace
          WHERE n.nspname='public' AND relname=ANY(%s)''',
          (list(REQUIRED_TABLES),))
        flags={name:(enabled,forced) for name,enabled,forced in c.fetchall()}
        c.execute('''SELECT tablename,policyname,roles,cmd,qual,with_check
           FROM pg_policies WHERE schemaname='public' AND tablename=ANY(%s)''',
           (list(REQUIRED_TABLES),))
        policies={}
        for table,name,roles,cmd,qual,check in c.fetchall():
            policies.setdefault(table,[]).append((name,roles,cmd,qual,check))
        for table,names in REQUIRED_TABLES.items():
            if flags.get(table)!=(True,True):issues.append('RLS not forced: '+table)
            observed={p[0] for p in policies.get(table,[])}
            if observed!=names:issues.append('Unexpected policy list: '+table)
            if any('jw_app' not in p[1] for p in policies.get(table,[])):
                issues.append('Incorrect role: '+table)
            for p in policies.get(table,[]):
                if p[2]!='SELECT' and p[2]!='INSERT' and p[2]!='UPDATE':
                    issues.append('Unexpected operation: '+table)
                if 'jw_guard.current_tenant()' not in str(p[3])+str(p[4]) and table!='messenger_edits' and table!='messenger_attachments':
                    issues.append('No tenant isolation expression: '+table)
            c.execute("SELECT has_table_privilege('jw_app',%s,'TRUNCATE, REFERENCES, TRIGGER, DELETE')",('public.'+table,))
            if c.fetchone()[0]:issues.append('Forbidden table privilege: '+table)
            c.execute("SELECT has_table_privilege('jw_app',%s,'UPDATE')",('public.'+table,))
            if table!='messenger_read_positions' and c.fetchone()[0]:
                issues.append('Forbidden table update: '+table)
            elif table=='messenger_read_positions': c.fetchone()  # consume query result
        c.execute("SELECT has_table_privilege('jw_app','jw_guard.messenger_counters','SELECT, INSERT, UPDATE, DELETE, TRUNCATE')")
        if c.fetchone()[0]:issues.append('App can access private sequence counter')
        c.execute("SELECT has_column_privilege('jw_app','public.messenger_messages','message_seq','INSERT')")
        if c.fetchone()[0]:issues.append('App can choose persisted message sequence')
        c.execute("SELECT has_column_privilege('jw_app','public.messenger_companies','business_number','SELECT')")
        if c.fetchone()[0]:issues.append('Company business number exposed to directory role')
    return issues


def denied(fn, psycopg, states):
    if not states: raise AssertionError('Security denial needs explicit SQLSTATE')
    try: fn()
    except psycopg.Error as exc:
        if exc.sqlstate not in states:
            raise AssertionError('Unexpected SQLSTATE: '+str(exc.sqlstate)) from exc
        return
    raise AssertionError('Cross-tenant attack unexpectedly succeeded')


def run():
    admin_dsn=os.environ.get('JW_PG_TEST_ADMIN_DSN','')
    app_dsn=os.environ.get('JW_PG_TEST_APP_DSN','')
    if not admin_dsn or not app_dsn or os.environ.get('JW_PG_ALLOW_TEST_WRITES')!='ONLY_EPHEMERAL_DATABASE':
        print('NOT RUN: isolated PostgreSQL DSNs and explicit permission required')
        return 2
    try: import psycopg
    except ImportError:
        print('NOT RUN: psycopg[binary] not installed')
        return 2
    # The parent CI runner verified version, host, emptiness and fresh role.
    try:
        with psycopg.connect(admin_dsn) as admin:
            with admin.cursor() as c:
                c.execute('SELECT current_database(),current_user')
                db,user=c.fetchone()
                import re
                if not re.fullmatch(r'jw_v20_test_[0-9a-f]{12}',db) or user!='postgres':
                    raise AssertionError('Refuse non-ephemeral admin DB')
            issues=validate_catalog(admin)
            if issues: raise AssertionError('; '.join(issues))
            tokens={k:secrets.token_urlsafe(40) for k in ('tenant_a','tenant_b','tenant_c')}
            with admin.cursor() as c:
                c.execute("INSERT INTO public.organizations VALUES('tenant_c','Test C')")
                c.execute("INSERT INTO public.users VALUES('uc','tenant_c','fake')")
                for i,org in enumerate(tokens):
                    c.execute('INSERT INTO public.messenger_companies VALUES(%s,%s,%s,now())',
                              (org,'Synthetic '+org,str(3000000000+i)))
                    c.execute('''INSERT INTO jw_guard.authenticated_sessions
                    (token_digest,org_id,user_id,mfa_verified,expires_at)
                    VALUES (%s,%s,%s,true,%s)''',
                    (hashlib.sha256(tokens[org].encode()).digest(),org,{'tenant_a':'ua','tenant_b':'ub','tenant_c':'uc'}[org],
                     datetime.now(timezone.utc)+timedelta(minutes=30)))
            admin.commit()

            def execute(org, sql, args=(), returns=False):
                with psycopg.connect(app_dsn) as con:
                    with con.cursor() as c:
                        c.execute('SELECT jw_guard.bind_session(%s)',(tokens[org],))
                        c.execute(sql,args)
                        return c.fetchall() if returns else c.rowcount

            # Real RLS context is bound per transaction. The same message is
            # visible to BOTH participants but never to the third company.
            execute('tenant_a', '''INSERT INTO public.messenger_connections
                (id,org_a,org_b,requester_org,status)
                VALUES ('chat_ab','tenant_a','tenant_b','tenant_a','active')''')
            execute('tenant_c', '''INSERT INTO public.messenger_connections
                (id,org_a,org_b,requester_org,status)
                VALUES ('chat_bc','tenant_b','tenant_c','tenant_c','active')''')
            assert execute('tenant_a','SELECT id FROM public.messenger_connections ORDER BY id',returns=True)==[('chat_ab',)]
            assert execute('tenant_b','SELECT id FROM public.messenger_connections ORDER BY id',returns=True)==[('chat_ab',),('chat_bc',)]
            assert execute('tenant_c','SELECT id FROM public.messenger_connections ORDER BY id',returns=True)==[('chat_bc',)]
            assert len(execute('tenant_a','SELECT org_id,company_name FROM public.messenger_companies',returns=True))==3

            execute('tenant_a', '''INSERT INTO public.messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id)
                VALUES ('ab_one','chat_ab','tenant_a','ua','text','A hello','req_a_one')''')
            execute('tenant_b', '''INSERT INTO public.messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id)
                VALUES ('ab_two','chat_ab','tenant_b','ub','text','B hello','req_b_one')''')
            execute('tenant_b', '''INSERT INTO public.messenger_attachments
                (message_id,filename,data,content_hash) VALUES('ab_two','test.txt',%s,'sha256-demo')''',(b'test',))
            assert execute('tenant_a','SELECT id,message_seq FROM public.messenger_messages ORDER BY message_seq',returns=True)==[('ab_one',1),('ab_two',2)]
            assert execute('tenant_b','SELECT id FROM public.messenger_messages ORDER BY message_seq',returns=True)==[('ab_one',),('ab_two',)]
            assert execute('tenant_c','SELECT id FROM public.messenger_messages',returns=True)==[]
            assert execute('tenant_c','SELECT message_id FROM public.messenger_attachments',returns=True)==[]
            assert execute('tenant_a','SELECT message_id FROM public.messenger_attachments',returns=True)==[('ab_two',)]
            assert execute('tenant_c','SELECT COUNT(*) FROM public.messenger_connections WHERE id=%s',('chat_ab',),True)==[(0,)]
            assert execute('tenant_c','SELECT COUNT(*) FROM public.messenger_messages WHERE id=%s',('ab_one',),True)==[(0,)]
            # Raw SQL attacks are deliberately run with savepoints so their
            # expected denials do not disguise syntax/connection failures.
            with psycopg.connect(app_dsn) as con:
                with con.cursor() as c:
                    c.execute('SELECT jw_guard.bind_session(%s)',(tokens['tenant_c'],))
                    for query,args,states in (
                        ("INSERT INTO public.messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id) VALUES('attack1','chat_ab','tenant_c','uc','text','attack','req_attack_1')",(),{'P0001','42501'}),
                        ("INSERT INTO public.messenger_connections(id,org_a,org_b,requester_org,status) VALUES('attack2','tenant_a','tenant_b','tenant_a','active')",(),{'42501'}),
                        ("DELETE FROM public.messenger_messages WHERE id='ab_one'",(),{'42501'}),
                        ("UPDATE public.messenger_messages SET body='evil' WHERE id='ab_one'",(),{'42501'}),
                        ("SELECT last_seq FROM jw_guard.messenger_counters",(),{'42501'}),
                    ):
                        c.execute('SAVEPOINT blocked')
                        denied(lambda query=query,args=args: c.execute(query,args),psycopg,states)
                        c.execute('ROLLBACK TO SAVEPOINT blocked')
                    c.execute('SELECT COUNT(*) FROM public.messenger_messages')
                    assert c.fetchone()==(0,)
            with psycopg.connect(app_dsn) as con:
                with con.cursor() as c:
                    c.execute('SELECT jw_guard.bind_session(%s)',(tokens['tenant_a'],))
                    for query in (
                        "INSERT INTO public.messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id) VALUES('forged','chat_ab','tenant_b','ua','text','bad','req_for_1')",
                        "INSERT INTO public.messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id) VALUES('forged2','chat_ab','tenant_a','ub','text','bad','req_for_2')",
                        "INSERT INTO public.messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id,message_seq) VALUES('forged3','chat_ab','tenant_a','ua','text','bad','req_for_3',999)",
                        "UPDATE public.messenger_attachments SET data='x' WHERE message_id='ab_two'",
                    ):
                        c.execute('SAVEPOINT blocked')
                        denied(lambda query=query: c.execute(query),psycopg,{'42501','P0001'})
                        c.execute('ROLLBACK TO SAVEPOINT blocked')
            with psycopg.connect(app_dsn) as con:
                with con.cursor() as c:
                    c.execute('SELECT COUNT(*) FROM public.messenger_messages')
                    assert c.fetchone()==(0,), 'Unbound session read business evidence'
                    c.execute("SELECT set_config('jw.ctx_org','tenant_a',true)")
                    c.execute('SELECT COUNT(*) FROM public.messenger_messages')
                    assert c.fetchone()==(0,), 'Forged tenant GUC bypassed RLS'

            # Advance readable positions with strict monotonicity/bounds.
            execute('tenant_a', "INSERT INTO public.messenger_read_positions(connection_id,org_id,last_read_seq) VALUES ('chat_ab','tenant_a',1)")
            assert execute('tenant_a', "SELECT last_read_seq FROM public.messenger_read_positions",returns=True)==[(1,)]
            with psycopg.connect(app_dsn) as con:
                with con.cursor() as c:
                    c.execute('SELECT jw_guard.bind_session(%s)',(tokens['tenant_a'],))
                    for attack in (
                        "UPDATE public.messenger_read_positions SET last_read_seq=999 WHERE connection_id='chat_ab'",
                        "UPDATE public.messenger_read_positions SET last_read_seq=0 WHERE connection_id='chat_ab'",
                        "INSERT INTO public.messenger_read_positions(connection_id,org_id,last_read_seq) VALUES('chat_bc','tenant_a',0)",
                    ):
                        c.execute('SAVEPOINT blocked')
                        denied(lambda attack=attack:c.execute(attack),psycopg,{'42501','P0001'})
                        c.execute('ROLLBACK TO SAVEPOINT blocked')
            # Concurrent connection writers, protected by per-thread row locks.
            def write_many(i):
                for j in range(4):
                    execute('tenant_a', '''INSERT INTO public.messenger_messages
                        (id,connection_id,sender_org,sender_user,kind,body,request_id)
                        VALUES(%s,'chat_ab','tenant_a','ua','text','load',%s)''',
                        (f'parallel_{i}_{j}',secrets.token_hex(16)))
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(write_many,range(4)))
            rows=execute('tenant_a', '''SELECT message_seq FROM public.messenger_messages
                WHERE connection_id='chat_ab' ORDER BY message_seq''',returns=True)
            assert [r[0] for r in rows]==list(range(1,19)), 'Concurrent message order has gaps or duplicates'
            print('PASS: V2.7 PG17 live bidirectional thread isolation, actor forgery, immutable evidence, spoofing, parallel sequence')
            return 0
    except Exception as exc:
        # No tokens, connection strings or database user data in logs.
        print('FAIL: V2.7 PG live attack: '+type(exc).__name__+': '+str(exc)[:150],file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(run())
