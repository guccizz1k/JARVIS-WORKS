"""Disposable PG17 integration: exact V85 cutover, actual TLS, OTP and ERP installation inventory.
No managed DB credentials, production installation or deployment.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import psycopg
from psycopg.conninfo import make_conninfo
from fastapi.testclient import TestClient
from psycopg import sql

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('cutover',HERE/'naruv_v85_dual_cutover_review.py')
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
s=v.s;b=v.b;base=v.base;need=b.need
def tls(dsn,cert,**kw):
    return make_conninfo(dsn,sslmode='verify-full',sslrootcert=str(cert),gssencmode='disable',connect_timeout=4,**kw)
def deny_tls(dsn):
    try:
        with psycopg.connect(dsn):pass
    except psycopg.OperationalError:pass
    else:raise RuntimeError('TLS_BAD_CERT_ACCEPTED')
def assert_tls(dsn,role):
    with psycopg.connect(dsn) as c:
        row=c.execute("SELECT session_user,ssl,version FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
        need(row[0]==role and row[1] and row[2] in ('TLSv1.2','TLSv1.3'),'TLS_SESSION')
def inventory(fixture):
    # Required native inventory (39) and 3 HR profile tables, plus the
    # explicitly enumerated 19 jw_dev tables and 3 identity tables.
    expected=set(base.EXPECTED)
    expected|={('naruv_draft',t) for t in ('profile_envelopes','profile_revision_history','profile_retention')}
    expected|={('jw_dev',t) for t in 'organizations users sessions messenger_companies messenger_connections messenger_messages messenger_attachments messenger_edits messenger_read_positions customers quotes quote_items audit_logs naruv_review_sources staff_disabled mfa_credentials mfa_recovery_codes login_failures security_events'.split()}
    expected|={('naruv_hosted_identity_review',t) for t in ('organizations','users','sessions')}
    with psycopg.connect(fixture.root_dsn) as c:
        rows=c.execute("""SELECT n.nspname::text,t.relname::text,t.relrowsecurity,t.relforcerowsecurity
        FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
        WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p')""",(sorted({x[0] for x in expected}),)).fetchall()
        need({(a,b) for a,b,_,_ in rows}==expected,'INSTALL_INVENTORY_MISMATCH')
        need(all(r and f for _,_,r,f in rows),'INSTALL_FORCE_RLS')
        need(c.execute("""SELECT count(*) FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
        CROSS JOIN unnest(ARRAY['anon','authenticated','service_role']) r
        WHERE n.nspname=ANY(%s) AND t.relkind IN ('r','p') AND
        (has_table_privilege(r,t.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR
         has_any_column_privilege(r,t.oid,'SELECT,INSERT,UPDATE,REFERENCES'))""",(sorted({x[0] for x in expected}),)).fetchone()==(0,),'INSTALL_EXTERNAL_TABLE_GRANT')
    print('AUTH_TLS_INSTALL_INVENTORY_PASS tables='+str(len(expected))+' force_rls='+str(len(expected)),flush=True)

def main():
    base.preflight()
    b.pin(HERE/'naruv_v85_dual_cutover_review.py','565bf498c914c98cccbb905e2031b2a9bbd40081')
    from app import pg_auth_v85 as auth,pg_api_v84 as read,naruv_native_write_review as write,naruv_pg_auth_review as review
    from app.security_hardening import totp_code
    from scripts.naruv_native_write_review_ci import NativeWrite
    # Save actual connection functions before fixture replaces them.
    real_read=read._connect;real_ingest=write._ingest_connect
    fixture,ingest=base.setup()
    b.install(fixture);broker=s.install(fixture)
    dsn,pw,key,_,_=v.install(fixture)
    cert=Path(os.environ['NARUV_TLS_CA']).resolve(strict=True)
    bad=Path(os.environ['NARUV_TLS_BAD_CA']).resolve(strict=True)
    auth_dsn=tls(dsn,cert);trade_dsn=tls(fixture.TRADE_DSN,cert);ingest_dsn=tls(ingest,cert)
    for d,r in ((auth_dsn,'naruv_v85_cutover_ci'),(trade_dsn,'jw_ci_trade'),(ingest_dsn,'naruv_ci_ingest')):
        assert_tls(d,r)
        deny_tls(make_conninfo(d,sslrootcert=str(bad)))
        deny_tls(make_conninfo(d,host='not-the-server.invalid',hostaddr='127.0.0.1'))
    print('AUTH_TLS_INDEPENDENT_LOGIN_PASS logins=3 bad_ca_denials=3 hostname_denials=3',flush=True)
    # Additional profile tables are actual source DDL, not target-derived inventory.
    profile=b.pin(base.ROOT/'db/review/naruv_hr_profile_ci.sql','835b0d6b6210d0e6151d701848f9276f6f5a7be2')
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("SET LOCAL naruv.profile_ci='DISPOSABLE_ONLY'")
        c.execute(profile)
    inventory(fixture)
    read._connect=real_read;write._ingest_connect=real_ingest
    app=NativeWrite.app
    origin={'origin':'https://testserver'}
    env={review.FLAG:review.ACK,'JW_DATA_KEY':key.decode(),'JW_PG_AUTH_STAGE_DSN':auth_dsn,
         'JW_PG_STAGE_DSN':trade_dsn,'NARUV_NATIVE_STAGE_DSN':ingest_dsn}
    with patch.dict(os.environ,env):
        need(review.register(app),'TLS_AUTH_REGISTER')
        need(read.register_stage_api(app),'TLS_READ_REGISTER')
        login=review.PREFIX+'/login';logout=review.PREFIX+'/logout'
        def sign(client,who,expected=200,**extra):
            return v.check(client.post(login,json=dict(email=who+'@invalid.test',password=pw,**extra),headers=origin),expected)
        def token(client):
            return hashlib.sha256(client.cookies.get(auth.COOKIE).encode()).hexdigest()
        def out(client,csrf):
            v.check(client.post(logout,headers=dict(origin,**{'x-csrf-token':csrf})),200)
        # Lockout persists, and a correct password is blocked until window expiry.
        with TestClient(app,base_url='https://testserver') as a:
            for _ in range(5):
                v.check(a.post(login,json=dict(email='a@invalid.test',password='wrong'),headers=origin),401)
            sign(a,'a',429)
            with psycopg.connect(fixture.root_dsn) as c:
                need(c.execute("SELECT attempts FROM jw_dev.login_failures WHERE email='a@invalid.test'").fetchone()==(5,),'LOCKOUT_COUNT')
                c.execute("UPDATE jw_dev.login_failures SET first_failed_at=(clock_timestamp()-interval '16 minutes')::text WHERE email='a@invalid.test'")
            ac=sign(a,'a')['csrf_token'];ah=token(a)
            need(s.state(fixture,ah)==(1,1,0,1),'TLS_AUTH_PAIR')
            # Original V84 read API uses the same verified session, real connector.
            need(v.check(a.get('/api/pg-stage/v84/me'),200)['org_id']=='ci-a','TLS_READ_IDENTITY')
            # Original import API uses both real trade and ingest connect functions.
            raw=b'sku,item_name,unit\n009,TLS Item,EA\n'
            from app import naruv_native_file_preview as preview
            h=dict(origin,**{'x-csrf-token':ac,'content-type':preview.FORMATS['csv']})
            stem=preview.PREFIX+'/sources/source-a/item/csv'
            d=v.check(a.post(stem+'/preview',headers=h,content=raw),200)
            dig={'x-naruv-stage-digest':d['stage_sha256'],'x-naruv-canonical-digest':d['canonical_rows_sha256'],'x-naruv-target-digest':d['target_snapshot_sha256']}
            v.check(a.post(stem+'/stages/tls-stage',headers=dict(h,**dig),content=raw),200)
            h2=dict(origin,**{'x-csrf-token':ac},**dig)
            v.check(a.post(preview.PREFIX+'/stages/tls-stage/approve',headers=dict(h2,**{'x-naruv-confirm':'yes'})),200)
            v.check(a.post(preview.PREFIX+'/stages/tls-stage/commit/tls-import',headers=h2),200)
            with psycopg.connect(trade_dsn) as c:
                b.bind(c,ah)
                need(c.execute("SELECT current_user").fetchone()==('jw_app_dev',),'TLS_BUSINESS_ROLE')
                s.stock(c,ac,'tls-stock')
                need(b.rpc(c,'naruv_valuation.audit_ledger',ac)['status']=='RECONCILED','TLS_LEDGER')
            out(a,ac)
            need(s.state(fixture,ah)==(0,1,1,0),'TLS_LOGOUT_PAIR')
        print('AUTH_TLS_LOCKOUT_IMPORT_ERP_PASS attempts=5 three_original_connectors=true',flush=True)
        # Same OTP presented concurrently, exactly one succeeds.
        step=int(time.time()//30)
        otp=totp_code('JBSWY3DPEHPK3PXP',step)
        def attempt():
            with TestClient(app,base_url='https://testserver') as client:
                r=client.post(login,json=dict(email='b@invalid.test',password=pw,otp=otp),headers=origin)
                if r.status_code==200:
                    h=token(client)
                    need(s.state(fixture,h)==(1,1,0,1),'OTP_PAIR')
                    out(client,r.json()['csrf_token'])
                return r.status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes=list(pool.map(lambda _:attempt(),range(2)))
        need(sorted(codes)==[200,401],'OTP_CONCURRENT_REPLAY')
        with psycopg.connect(fixture.root_dsn) as c:
            need(c.execute("SELECT last_counter FROM jw_dev.mfa_credentials WHERE user_id='ci-ub'").fetchone()==(step,),'OTP_COUNTER')
        print('AUTH_TLS_OTP_RACE_PASS accepted=1 rejected=1',flush=True)
        # Actual management broker disables both stores and revokes active sessions.
        with TestClient(app,base_url='https://testserver') as a,psycopg.connect(broker,autocommit=True) as m:
            ac=sign(a,'a')['csrf_token'];ah=token(a)
            s.change(m,'ci-ua',False,'admin')
            need(s.state(fixture,ah)==(0,1,1,0),'DISABLE_PAIR')
            v.check(a.get('/api/pg-stage/v84/me'),401)
            a.cookies.clear()
            sign(a,'a',401)
            s.change(m,'ci-ua',True,'admin')
            ac=sign(a,'a')['csrf_token']
            need(token(a)!=ah,'REACTIVATED_TOKEN')
            out(a,ac)
        print('AUTH_TLS_DISABLE_REACTIVATE_PASS',flush=True)
    print('AUTH_TLS_PREFLIGHT_REVIEW_PASS production_authorized=false hosted_install=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
