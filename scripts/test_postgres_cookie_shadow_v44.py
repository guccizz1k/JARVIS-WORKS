"""Real SQLite website-cookie -> PostgreSQL17 RLS shadow test; disposable only.

All identities, login credentials and messages here are synthetic. The real
B2B web main app, customer data, production configuration and public URLs
remain unmodified. This file runs inside the existing temporary PG17 gate.
"""
from __future__ import annotations

from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import Path
import os
import secrets
import sys
import tempfile


def run() -> int:
    if (os.getenv('JW_ENV','').casefold() == 'production' or
        os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE' or
        os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE' or
        any(os.getenv('JW_PG_LAB_V'+v) != 'ONLY_DISPOSABLE_LAB'
            for v in ('38','40','42','43','44'))):
        print('NOT RUN: V4.4 disposal and isolation guards absent')
        return 2
    try:
        import psycopg
        from psycopg.conninfo import conninfo_to_dict
        from fastapi.testclient import TestClient
        from app.pg_cookie_shadow_v44 import ReviewBinding, create_review_app
        from app.pg_messenger_review import MessengerReviewAdapter
        from app.pg_write_replay_v40 import LabWriterV40
        from scripts.test_postgres_writer_v40 import _verified_lab_uri
        import app.main as website
        admin_dsn=os.environ.get('JW_PG_TEST_ADMIN_DSN','')
        app_dsn=os.environ.get('JW_PG_TEST_APP_DSN','')
        dsn=_verified_lab_uri(conninfo_to_dict(admin_dsn),conninfo_to_dict(app_dsn))
        MessengerReviewAdapter(dsn)._check_dsn()
    except (ImportError,TypeError,ValueError,RuntimeError):
        print('NOT RUN: V4.4 reviewed dependencies or isolated PG17 DSN missing')
        return 2
    stage='setup'
    result=1
    token=secrets.token_urlsafe(40)
    digest=sha256(token.encode()).digest()
    original_path=website.DB_PATH
    original_demo=os.environ.get('DEMO_SEED')
    # DB references are restricted to the disposable V4.4 in-process web test.
    with tempfile.TemporaryDirectory(prefix='jw-v44-site-') as root:
        website.DB_PATH=Path(root)/'web-test.db'
        try:
            stage='seed-postgres-synthetic-organizations'
            with psycopg.connect(admin_dsn,connect_timeout=5) as pg:
                with pg.cursor() as c:
                    c.execute("INSERT INTO public.organizations(id,name) VALUES ('v44_pg_a','V44 A'),('v44_pg_b','V44 B')")
                    c.execute("INSERT INTO public.users(id,org_id,password_hash) VALUES ('v44_pg_ua','v44_pg_a','synthetic'),('v44_pg_ub','v44_pg_b','synthetic')")
                    c.execute('''INSERT INTO public.messenger_companies
                        (org_id,company_name,business_number,verified_at) VALUES
                        ('v44_pg_a','V44 A','8310000041',clock_timestamp()),
                        ('v44_pg_b','V44 B','8310000042',clock_timestamp())''')
                    c.execute("""INSERT INTO public.messenger_connections(id,org_a,org_b,requester_org,status)
                          VALUES ('v44_shadow_ab','v44_pg_a','v44_pg_b','v44_pg_a','active')""")
                    c.execute('''INSERT INTO jw_guard.authenticated_sessions
                        (token_digest,org_id,user_id,mfa_verified,expires_at)
                        VALUES (%s,'v44_pg_a','v44_pg_ua',true,%s)''',
                        (digest,datetime.now(timezone.utc)+timedelta(minutes=10)))
            stage='write-pg-via-verified-rls'
            message=LabWriterV40(dsn).send_text(token=token,thread='v44_shadow_ab',
                      content='V4.4 verified website shadow history',request_id=secrets.token_hex(16))
            assert message['id'] and not message['replayed']
            stage='create-actual-website-auth-and-sqlite-fixture'
            os.environ.pop('DEMO_SEED',None)  # synthetic fixture only; restored below
            website.init_db()
            web_thread=secrets.token_hex(16)
            with website.transaction() as c:
                for org,usr,email in (
                    ('v44_web_a','v44_web_ua','v44-a@synthetic.invalid'),
                    ('v44_web_b','v44_web_ub','v44-b@synthetic.invalid')):
                    c.execute('INSERT INTO organizations VALUES(?,?,?)',(org,org,website.now()))
                    c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                        (usr,org,email,website.hash_password('v44-test-password-only'),usr,'admin',website.now()))
                for org,bn in (('v44_web_a','8310000051'),('v44_web_b','8310000052')):
                    c.execute('''INSERT INTO messenger_companies
                           (org_id,business_number,verified_at,verification_kind)
                           VALUES(?,?,?,'demo')''',(org,bn,website.now()))
                c.execute('''INSERT INTO messenger_connections
                    (id,org_a,org_b,requester_org,status,created_at,accepted_at)
                    VALUES(?,?,?,?,'active',?,?)''',
                    (web_thread,'v44_web_a','v44_web_b','v44_web_a',website.now(),website.now()))
                c.execute('''INSERT INTO messenger_messages
                     (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
                     VALUES(?,?,?,?,'text',?,?,?)''',
                    (message['id'],web_thread,'v44_web_a','v44_web_ua',
                     'V4.4 verified website shadow history',secrets.token_hex(16),website.now()))
            stage='real-website-login-cookie'
            with TestClient(website.app,base_url='https://testserver') as website_client:
                login=website_client.post('/api/login',json={
                     'email':'v44-a@synthetic.invalid','password':'v44-test-password-only'})
                assert login.status_code==200
                cookie=website_client.cookies.get(website.SESSION_COOKIE)
                assert cookie and len(cookie)>=30
                stage='real-cookie-to-pg-rls-shadow'
                binding=ReviewBinding('v44_web_a','v44_web_ua','v44_pg_a','v44_pg_ua',
                    'v44_shadow_ab',token,
                    (('v44_pg_a','v44_web_a'),('v44_pg_b','v44_web_b')),
                    (('v44_pg_ua','v44_web_ua'),('v44_pg_ub','v44_web_ub')))
                def broker(org,user,thread):
                    assert (org,user,thread)==('v44_web_a','v44_web_ua',web_thread)
                    return binding
                isolated=create_review_app(dsn=dsn,adapter=MessengerReviewAdapter(dsn),
                    sqlite_conn=website.conn,trusted_broker=broker)
                with TestClient(isolated,base_url='https://testserver') as lab:
                    url='/lab44/threads/'+web_thread+'/shadow'
                    hdr={'Cookie':website.SESSION_COOKIE+'='+cookie}
                    assert lab.get(url).status_code==401
                    forged=lab.get(url,headers={'X-JW-Lab-Session':token})
                    assert forged.status_code==401
                    good=lab.get(url,headers=hdr)
                    assert good.status_code==200 and good.json()['status']=='MATCH',good.text
                    assert good.json()['text_row_parity'] is True and good.json()['cutover_approved'] is False
                    assert token not in good.text and 'V4.4 verified website' not in good.text
                    assert lab.post(url,headers=hdr).status_code==405
                    stage='detect-parity-corruption'
                    with website.conn() as c:
                        c.execute('UPDATE messenger_messages SET body=? WHERE id=?',
                                  ('changed evidence',message['id']))
                    mismatch=lab.get(url,headers=hdr)
                    assert mismatch.status_code==200
                    assert mismatch.json()['status']=='MISMATCH'
                    assert not mismatch.json()['text_row_parity']
                    stage='web-cookie-revocation'
                    with website.conn() as c:
                        c.execute('DELETE FROM sessions WHERE token_hash=?',
                                   (sha256(cookie.encode()).hexdigest(),))
                    assert lab.get(url,headers=hdr).status_code==401
                    stage='pg-authority-revocation'
                    with psycopg.connect(admin_dsn,connect_timeout=5) as pg:
                        with pg.cursor() as c:
                            c.execute('UPDATE jw_guard.authenticated_sessions SET revoked_at=clock_timestamp() WHERE token_digest=%s',(digest,))
                            assert c.rowcount==1
                    # Website session is recreated synthetically to isolate the PG check.
                    with website.conn() as c:
                        c.execute('INSERT INTO sessions(token_hash,user_id,expires_at,csrf_token,id,created_at) VALUES (?,?,?,?,?,?)',
                          (sha256(cookie.encode()).hexdigest(),'v44_web_ua',
                           (datetime.now(website.KST)+timedelta(minutes=5)).isoformat(),
                           secrets.token_urlsafe(32),website.ident(),website.now()))
                    blocked=lab.get(url,headers=hdr)
                    assert blocked.status_code in (403,503) and not blocked.json().get('text_row_parity')
                    assert 'postgresql://' not in blocked.text
            result=0
        except Exception as exc:
            print('FAIL: V4.4 cookie/PG17 stage='+stage+' type='+type(exc).__name__+' (details redacted)',file=sys.stderr)
        finally:
            website.DB_PATH=original_path
            if original_demo is None: os.environ.pop('DEMO_SEED',None)
            else: os.environ['DEMO_SEED']=original_demo
            # All PostgreSQL data is confined to the existing disposable DB,
            # which the parent supervisor will DROP regardless of exit status.
            # Report is PASS only if every above assertion succeeds.
    if result==0:
        print('PASS: V4.4 real website cookie -> PG17 RLS identity, read-only history parity, tamper denial, web/PG revocation')
    return result


if __name__=='__main__':
    raise SystemExit(run())
