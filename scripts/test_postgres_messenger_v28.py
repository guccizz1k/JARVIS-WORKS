"""Opt-in PostgreSQL 17 V2.8 LIVE integrity / second-employee isolation gate.

Runs only inside an ephemeral jw_v20_test_<12 hex> database provisioned by the
V2.8 runner. Missing test DSNs/driver/explicit consent = NOT RUN (exit 2).
No production or customer data is accessed. This file is NOT a PG emulator.
"""
from datetime import datetime, timedelta, timezone
import hashlib
import os
import re
import secrets
import sys


def denied(fn, psycopg, allowed_states):
    """Require a specific SQLSTATE, not arbitrary SQL failures or exceptions."""
    if not allowed_states:
        raise AssertionError('Explicit SQLSTATE required')
    try:
        fn()
    except psycopg.Error as exc:
        if exc.sqlstate not in allowed_states:
            raise AssertionError('Unexpected SQLSTATE: '+str(exc.sqlstate)) from exc
        return
    raise AssertionError('Unexpectedly permitted security-violating query')


def run():
    admin_dsn = os.environ.get('JW_PG_TEST_ADMIN_DSN', '')
    app_dsn = os.environ.get('JW_PG_TEST_APP_DSN', '')
    if (not admin_dsn or not app_dsn
            or os.environ.get('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'):
        print('NOT RUN: V2.8 requires disposable PostgreSQL DSNs and explicit consent')
        return 2
    try:
        import psycopg
    except ImportError:
        print('NOT RUN: psycopg unavailable')
        return 2
    try:
        with psycopg.connect(admin_dsn) as admin:
            with admin.cursor() as c:
                c.execute('SELECT current_database(),current_user')
                database, user = c.fetchone()
                if not re.fullmatch(r'jw_v20_test_[0-9a-f]{12}', database) or user != 'postgres':
                    raise AssertionError('Only ephemeral admin database is allowed')
                c.execute("SELECT convalidated, pg_get_constraintdef(oid) FROM pg_constraint "
                          "WHERE conrelid='public.messenger_attachments'::regclass "
                          "AND conname='jw_v28_attachment_sha256'")
                constraints = c.fetchall()
                if len(constraints) != 1 or not constraints[0][0] or 'digest' not in constraints[0][1]:
                    raise AssertionError('Missing validated attachment digest constraint')
                c.execute("SELECT tgenabled FROM pg_trigger WHERE tgrelid='public.messenger_attachments'::regclass "
                          "AND tgname='jw_v28_attachment_sender' AND NOT tgisinternal")
                if c.fetchall() != [('O',)]:
                    raise AssertionError('Missing enabled verified-sender trigger')
                c.execute("SELECT has_column_privilege('jw_app', 'public.messenger_read_positions', "
                          "'updated_at','UPDATE')")
                if c.fetchone() != (False,):
                    raise AssertionError('App role may forge read timestamps')
                c.execute("SELECT a.content_hash, encode(public.digest(a.data,'sha256'),'hex'),m.kind "
                          "FROM public.messenger_attachments a "
                          "JOIN public.messenger_messages m ON m.id=a.message_id")
                for claimed, actual, kind in c.fetchall():
                    if claimed != actual or kind != 'attachment':
                        raise AssertionError('Legacy evidence was not safely migrated')

                token_sender = secrets.token_urlsafe(40)
                token_other = secrets.token_urlsafe(40)
                c.execute("INSERT INTO public.users(id,org_id,password_hash) VALUES"
                          "('ub_v28','tenant_b','synthetic'),('ub_v28_other','tenant_b','synthetic')")
                for employee, token in [('ub_v28', token_sender), ('ub_v28_other', token_other)]:
                    c.execute('''INSERT INTO jw_guard.authenticated_sessions
                        (token_digest,org_id,user_id,mfa_verified,expires_at)
                        VALUES (%s,'tenant_b',%s,true,%s)''',
                        (hashlib.sha256(token.encode()).digest(),employee,
                         datetime.now(timezone.utc)+timedelta(minutes=30)))
            admin.commit()

            def execute(token, query, args=(), fetch=False):
                with psycopg.connect(app_dsn) as con:
                    with con.cursor() as c:
                        c.execute('SELECT jw_guard.bind_session(%s)',(token,))
                        c.execute(query,args)
                        return c.fetchall() if fetch else c.rowcount

            execute(token_sender, '''INSERT INTO public.messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id)
                VALUES ('v28_attached','chat_ab','tenant_b','ub_v28','attachment','file','v28_req_attachment')''')

            def denied_in_session(token, query, args, states):
                with psycopg.connect(app_dsn) as con:
                    with con.cursor() as c:
                        c.execute('SELECT jw_guard.bind_session(%s)',(token,))
                        c.execute('SAVEPOINT v28_denial')
                        denied(lambda: c.execute(query,args),psycopg,states)
                        c.execute('ROLLBACK TO SAVEPOINT v28_denial')

            # Same company, *different employee*: may create their own chat
            # messages, must not attach evidence to another employee's message.
            denied_in_session(token_other, '''INSERT INTO public.messenger_attachments
                (message_id,filename,data,content_hash) VALUES(%s,%s,%s,%s)''',
                ('v28_attached','stolen.pdf',b'example',hashlib.sha256(b'example').hexdigest()),
                {'P0001','42501'})
            denied_in_session(token_sender, '''INSERT INTO public.messenger_attachments
                (message_id,filename,data,content_hash) VALUES(%s,%s,%s,%s)''',
                ('v28_attached','file.txt',b'GOOD','0'*64),{'23514'})
            # An attachment to a plain-text message must fail even if its real
            # sender attempts it. V2.7 did not enforce the kind binding.
            execute(token_sender, '''INSERT INTO public.messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id)
                VALUES ('v28_text','chat_ab','tenant_b','ub_v28','text','plain','v28_req_text')''')
            denied_in_session(token_sender, '''INSERT INTO public.messenger_attachments
                (message_id,filename,data,content_hash) VALUES(%s,%s,%s,%s)''',
                ('v28_text','disguised.pdf',b'x',hashlib.sha256(b'x').hexdigest()),{'P0001'})

            binary = b'v28-generated-attachment-fixture'
            checksum = hashlib.sha256(binary).hexdigest()
            execute(token_sender, '''INSERT INTO public.messenger_attachments
                (message_id,filename,data,content_hash) VALUES(%s,%s,%s,%s)''',
                ('v28_attached','fixture.txt',binary,checksum))
            assert execute(token_other,
                "SELECT content_hash FROM public.messenger_attachments "
                "WHERE message_id='v28_attached'", fetch=True) == [(checksum,)]

            # Read marker last-read semantics preserved; read timestamp is
            # assigned by server and untrusted clients cannot overwrite it.
            denied_in_session(token_other,
                "INSERT INTO public.messenger_read_positions"
                "(connection_id,org_id,last_read_seq,updated_at) "
                "VALUES ('chat_ab','tenant_b',1,'2099-01-01')",(),{'42501'})
            execute(token_other,"INSERT INTO public.messenger_read_positions"
                "(connection_id,org_id,last_read_seq) VALUES ('chat_ab','tenant_b',1)")
            execute(token_other,"UPDATE public.messenger_read_positions SET last_read_seq=2 "
                "WHERE connection_id='chat_ab' AND org_id='tenant_b'")
            row=execute(token_other,"SELECT last_read_seq, updated_at FROM "
                "public.messenger_read_positions WHERE connection_id='chat_ab'",fetch=True)
            assert len(row)==1 and row[0][0]==2
            assert abs((datetime.now(timezone.utc)-row[0][1]).total_seconds())<120
            denied_in_session(token_other,
                "UPDATE public.messenger_read_positions SET updated_at='2099-01-01' "
                "WHERE connection_id='chat_ab'",(),{'42501'})
            denied_in_session(token_other,
                "UPDATE public.messenger_read_positions SET last_read_seq=0 "
                "WHERE connection_id='chat_ab'",(),{'P0001'})

            # No mutation of original documented ordering or third-party access.
            execute(token_other, '''INSERT INTO public.messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id)
                VALUES ('v28_other_text','chat_ab','tenant_b','ub_v28_other','text','own text','v28_req_other')''')
            rows=execute(token_other,"SELECT message_seq FROM public.messenger_messages "
                "WHERE connection_id='chat_ab' ORDER BY message_seq",fetch=True)
            seq=[r[0] for r in rows]
            assert seq==list(range(1,len(seq)+1)), 'V2.8 message sequence gap/reorder'
            print('PASS: V2.8 live checksum, sender binding, message kinds, server read-time, monotonic cursors')
            return 0
    except Exception as exc:
        print('FAIL: V2.8 live integrity gate: '+type(exc).__name__+' (credentials withheld)', file=sys.stderr)
        return 1


if __name__=='__main__':
    raise SystemExit(run())
