"""Disposable original V85 password/MFA API cutover to dual-store identity.
The original V85 definer ownership is retained in this fixture only.
No production migration or real credentials. Same local DB transaction.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
import secrets
from unittest.mock import patch
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from psycopg.types.json import Jsonb

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('sync',HERE/'naruv_dual_auth_sync_review.py')
s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
b=s.b;base=s.base;need=b.need
H='naruv_hosted_identity_review.'
DDL="""
-- Revoke the review broker's unauthenticated issuance path. Keep actor
-- lifecycle for the separately trusted management service.
REVOKE EXECUTE ON FUNCTION naruv_sync_ci.issue(text,text,text,text,integer),
 naruv_sync_ci.revoke(text) FROM naruv_sync_broker_ci;
DELETE FROM jw_dev.sessions;
ALTER FUNCTION jw_dev.v85_auth_candidate(text) RENAME TO v85_candidate_native_ci;
ALTER FUNCTION jw_dev.v85_auth_issue_session(text,text,text,bigint,text) RENAME TO v85_issue_native_ci;
ALTER FUNCTION jw_dev.v85_auth_revoke_session(text) RENAME TO v85_revoke_native_ci;
REVOKE ALL ON FUNCTION jw_dev.v85_candidate_native_ci(text),jw_dev.v85_issue_native_ci(text,text,text,bigint,text),
 jw_dev.v85_revoke_native_ci(text) FROM PUBLIC,jw_auth_stage_v85,anon,authenticated,service_role,jw_app_dev;
CREATE FUNCTION jw_dev.v85_auth_candidate(p_email text)
RETURNS TABLE(user_id text,org_id text,password_hash text,mfa_ciphertext text,mfa_counter bigint,
 is_disabled boolean,failure_attempts bigint,failure_first_at text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE actor text;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'CUTOVER_ISOLATION' USING ERRCODE='25000'; END IF;
 SELECT u.id INTO actor FROM jw_dev.users u WHERE lower(u.email)=p_email;
 -- Hosted user before native user, same order as management change.
 IF FOUND THEN
  PERFORM 1 FROM naruv_hosted_identity_review.users h WHERE h.id=actor FOR UPDATE;
 END IF;
 RETURN QUERY SELECT c.user_id,c.org_id,c.password_hash,c.mfa_ciphertext,c.mfa_counter,
  c.is_disabled,c.failure_attempts,c.failure_first_at FROM jw_dev.v85_candidate_native_ci(p_email) c;
END $f$;
CREATE FUNCTION jw_dev.v85_auth_issue_session(p_user_id text,p_token_hash text,p_csrf text,
 p_mfa_counter bigint DEFAULT NULL,p_recovery_hash text DEFAULT NULL)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE h naruv_hosted_identity_review.users%ROWTYPE; l jw_dev.users%ROWTYPE; v_id text; expiry timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR p_token_hash IS NULL OR p_token_hash !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'CUTOVER_INPUT' USING ERRCODE='23514'; END IF;
 SELECT * INTO h FROM naruv_hosted_identity_review.users WHERE id=p_user_id FOR UPDATE;
 IF NOT FOUND OR NOT h.active THEN RAISE EXCEPTION 'CUTOVER_IDENTITY' USING ERRCODE='23514'; END IF;
 SELECT * INTO l FROM jw_dev.users WHERE id=p_user_id FOR UPDATE;
 IF NOT FOUND OR (h.id,h.org_id,h.actor_role) IS DISTINCT FROM (l.id,l.org_id,l.role) THEN RAISE EXCEPTION 'CUTOVER_IDENTITY' USING ERRCODE='23514'; END IF;
 -- Original MFA/recovery, native session, login failure reset and audit event.
 v_id:=jw_dev.v85_issue_native_ci(p_user_id,p_token_hash,p_csrf,p_mfa_counter,p_recovery_hash);
 SELECT expires_at::timestamptz INTO STRICT expiry FROM jw_dev.sessions WHERE id=v_id AND token_hash=p_token_hash;
 INSERT INTO naruv_hosted_identity_review.sessions(token_hash,actor_id,epoch,csrf_token,expires_at)
 VALUES(p_token_hash,h.id,h.epoch,p_csrf,expiry);
 RETURN v_id;
END $f$;
CREATE FUNCTION jw_dev.v85_auth_revoke_session(p_token_hash text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE actor text; n int;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'CUTOVER_ISOLATION' USING ERRCODE='25000'; END IF;
 SELECT actor_id INTO actor FROM naruv_hosted_identity_review.sessions WHERE token_hash=p_token_hash;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM naruv_hosted_identity_review.users WHERE id=actor FOR UPDATE;
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE token_hash=p_token_hash AND actor_id=actor AND NOT revoked;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RETURN false; END IF;
 IF NOT jw_dev.v85_revoke_native_ci(p_token_hash) THEN RAISE EXCEPTION 'CUTOVER_REVOKE_DRIFT' USING ERRCODE='42501'; END IF;
 RETURN true;
END $f$;
CREATE OR REPLACE FUNCTION jw_dev.v85_auth_check_csrf(p_token_hash text,p_csrf text)
RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
 SELECT EXISTS(SELECT 1 FROM jw_dev.sessions l JOIN jw_dev.users u ON u.id=l.user_id
 JOIN naruv_hosted_identity_review.sessions s ON s.token_hash=l.token_hash AND s.actor_id=l.user_id
 JOIN naruv_hosted_identity_review.users h ON h.id=s.actor_id
 LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
 WHERE l.token_hash=p_token_hash AND l.csrf_token=p_csrf AND s.csrf_token=p_csrf
 AND p_csrf<>'' AND l.expires_at::timestamptz=s.expires_at AND s.expires_at>clock_timestamp()
 AND NOT s.revoked AND h.active AND s.epoch=h.epoch AND h.org_id=u.org_id AND h.actor_role=u.role AND d.user_id IS NULL)
$f$;
-- Replace in place (same OID) so existing RLS policy dependencies remain.
CREATE OR REPLACE FUNCTION jw_dev.stage_identity_v84()
RETURNS TABLE(actor_id text,org_id text,actor_role text,csrf_token text,org_name text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
 SELECT u.id,u.org_id,u.role,l.csrf_token,o.name FROM jw_dev.sessions l
 JOIN jw_dev.users u ON u.id=l.user_id JOIN jw_dev.organizations o ON o.id=u.org_id
 JOIN naruv_hosted_identity_review.sessions s ON s.token_hash=l.token_hash AND s.actor_id=l.user_id
 JOIN naruv_hosted_identity_review.users h ON h.id=s.actor_id
 LEFT JOIN jw_dev.staff_disabled d ON d.user_id=u.id
 WHERE l.token_hash=nullif(current_setting('jw.session_hash',true),'')
 AND l.csrf_token=s.csrf_token AND l.csrf_token<>'' AND l.expires_at::timestamptz=s.expires_at
 AND s.expires_at>clock_timestamp() AND NOT s.revoked AND h.active AND s.epoch=h.epoch
 AND h.org_id=u.org_id AND h.actor_role=u.role AND d.user_id IS NULL
$f$;
CREATE OR REPLACE FUNCTION jw_dev.current_org_from_session() RETURNS text
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
 SELECT i.org_id FROM jw_dev.stage_identity_v84() i
$f$;
CREATE OR REPLACE FUNCTION jw_dev.current_actor_from_session_v82() RETURNS text
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
 SELECT i.actor_id FROM jw_dev.stage_identity_v84() i
$f$;
REVOKE ALL ON FUNCTION jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82() TO jw_app_dev;
REVOKE ALL ON FUNCTION jw_dev.v85_auth_candidate(text),jw_dev.v85_auth_issue_session(text,text,text,bigint,text),
 jw_dev.v85_auth_revoke_session(text) FROM PUBLIC,anon,authenticated,service_role,jw_app_dev;
GRANT EXECUTE ON FUNCTION jw_dev.v85_auth_candidate(text),jw_dev.v85_auth_issue_session(text,text,text,bigint,text),
 jw_dev.v85_auth_revoke_session(text) TO jw_auth_stage_v85;
"""
def install(fixture):
    from app.security_hardening import recovery_hash
    pw=secrets.token_urlsafe(32);password=secrets.token_urlsafe(24);salt=secrets.token_bytes(16)
    encoded='pbkdf2_sha256$260000$'+salt.hex()+'$'+hashlib.pbkdf2_hmac('sha256',password.encode(),salt,260000).hex()
    key=Fernet.generate_key();recovery=secrets.token_hex(16)
    recovery_digest=recovery_hash('ci-ub',recovery)
    cipher=Fernet(key).encrypt(b'JBSWY3DPEHPK3PXP').decode()
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute("CREATE TABLE jw_dev.mfa_credentials(user_id text PRIMARY KEY REFERENCES jw_dev.users(id),secret_encrypted text NOT NULL,last_counter bigint NOT NULL)")
        c.execute("CREATE TABLE jw_dev.mfa_recovery_codes(user_id text REFERENCES jw_dev.users(id),code_hash text,consumed_at text,PRIMARY KEY(user_id,code_hash))")
        c.execute("CREATE TABLE jw_dev.login_failures(email text PRIMARY KEY,attempts bigint NOT NULL,first_failed_at text NOT NULL)")
        c.execute("CREATE TABLE jw_dev.security_events(id text PRIMARY KEY,org_id text,actor_id text,event_type text,created_at text)")
        for name in ('mfa_credentials','mfa_recovery_codes','login_failures','security_events'):
            c.execute('ALTER TABLE jw_dev.'+name+' ENABLE ROW LEVEL SECURITY')
            c.execute('ALTER TABLE jw_dev.'+name+' FORCE ROW LEVEL SECURITY')
            c.execute('REVOKE ALL ON jw_dev.'+name+' FROM PUBLIC')
        c.execute("UPDATE jw_dev.users SET password_hash=%s WHERE id IN ('ci-ua','ci-ub')",(encoded,))
        c.execute("INSERT INTO jw_dev.mfa_credentials VALUES('ci-ub',%s,-1)",(cipher,))
        c.execute("INSERT INTO jw_dev.mfa_recovery_codes VALUES('ci-ub',%s,NULL)",(recovery_digest,))
    with psycopg.connect(fixture.root_dsn,autocommit=True) as c:
        c.execute(b.pin(base.ROOT/'migrations/v85_auth_stage.sql','ec473797d3cc4304e08e36f134b469d8512bb0cd'))
    with psycopg.connect(fixture.root_dsn) as c:
        old=c.execute("SELECT 'jw_dev.stage_identity_v84()'::regprocedure::oid").fetchone()
        c.execute(DDL)
        need(c.execute("SELECT 'jw_dev.stage_identity_v84()'::regprocedure::oid").fetchone()==old,'CUTOVER_RLS_OID')
        c.execute(sql.SQL('CREATE ROLE naruv_v85_cutover_ci LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB PASSWORD {}').format(sql.Literal(pw)))
        c.execute('GRANT jw_auth_stage_v85 TO naruv_v85_cutover_ci WITH INHERIT FALSE,SET TRUE')
    return make_conninfo(fixture.root_dsn,user='naruv_v85_cutover_ci',password=pw),password,key,recovery,recovery_digest
def check(r,status):
    need(r.status_code==status,'CUTOVER_HTTP_'+str(r.status_code)+'_EXPECTED_'+str(status))
    return r.json()
def main():
    base.preflight()
    b.pin(HERE/'naruv_dual_auth_sync_review.py','16052037b863788af47cd9841e208ed9cc42f2fa')
    fixture,_=base.setup()
    old_auth=b.install(fixture)
    broker=s.install(fixture)
    dsn,pw,key,recovery,digest=install(fixture)
    from app import pg_auth_v85 as auth,naruv_pg_auth_review as review
    from scripts.naruv_native_write_review_ci import NativeWrite
    app=NativeWrite.app
    origin={'origin':'https://testserver'}
    # No network TLS assertion: exact API auth cursor with actual local TCP login.
    with patch.dict(os.environ,{review.FLAG:review.ACK,'JW_DATA_KEY':key.decode()}),patch.object(auth,'_connect',lambda:psycopg.connect(dsn,connect_timeout=5)):
        need(review.register(app),'CUTOVER_REGISTER')
        login=review.PREFIX+'/login';logout=review.PREFIX+'/logout'
        # Force hosted insert failure AFTER original recovery consumption and native issuance.
        collision='7'*64
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("INSERT INTO naruv_hosted_identity_review.sessions(token_hash,actor_id,epoch,csrf_token,expires_at) VALUES(%s,'ci-ub',0,%s,clock_timestamp()+interval '1 hour')",(collision,'x'*32))
        with psycopg.connect(dsn,autocommit=True) as c:
            c.execute('SET ROLE jw_auth_stage_v85')
            s.expect(c,'23505','SELECT jw_dev.v85_auth_issue_session(%s,%s,%s,NULL,%s)',('ci-ub',collision,'x'*32,digest))
            for q in ("SELECT jw_dev.v85_issue_native_ci(NULL,NULL,NULL,NULL,NULL)","SELECT jw_dev.v85_revoke_native_ci(NULL)","SELECT jw_dev.v85_candidate_native_ci(NULL)"):
                s.expect(c,'42501',q)
        with psycopg.connect(fixture.root_dsn) as c:
            need(c.execute("SELECT consumed_at IS NULL FROM jw_dev.mfa_recovery_codes WHERE user_id='ci-ub'").fetchone()==(True,),'CUTOVER_MFA_ROLLBACK')
            need(c.execute("SELECT count(*) FROM jw_dev.sessions WHERE token_hash=%s",(collision,)).fetchone()==(0,),'CUTOVER_NATIVE_ROLLBACK')
            need(c.execute("SELECT count(*) FROM jw_dev.security_events").fetchone()==(0,),'CUTOVER_EVENT_ROLLBACK')
            c.execute("DELETE FROM naruv_hosted_identity_review.sessions WHERE token_hash=%s",(collision,))
        with psycopg.connect(broker,autocommit=True) as c:
            s.expect(c,'42501','SELECT naruv_sync_ci.issue(NULL,NULL,NULL,NULL,NULL)')
            s.expect(c,'42501','SELECT naruv_sync_ci.revoke(NULL)')
        print('V85_CUTOVER_MFA_ATOMIC_ROLLBACK_PASS direct_bypass_denials=5',flush=True)
        with TestClient(app,base_url='https://testserver') as a,TestClient(app,base_url='https://testserver') as z:
            check(a.post(login,json={'email':'a@invalid.test','password':'wrong'},headers=origin),401)
            check(z.post(login,json={'email':'b@invalid.test','password':pw},headers=origin),401)
            ar=a.post(login,json={'email':'a@invalid.test','password':pw},headers=origin)
            csrf=check(ar,200)['csrf_token'];raw=a.cookies.get(auth.COOKIE);h=hashlib.sha256(raw.encode()).hexdigest()
            need(s.state(fixture,h)==(1,1,0,1),'CUTOVER_A_PAIR')
            need(all(x in ar.headers['set-cookie'] for x in ('Secure','HttpOnly','SameSite=strict')),'CUTOVER_COOKIE')
            br=z.post(login,json={'email':'b@invalid.test','password':pw,'recovery_code':recovery},headers=origin)
            zcsrf=check(br,200)['csrf_token'];zh=hashlib.sha256(z.cookies.get(auth.COOKIE).encode()).hexdigest()
            need(s.state(fixture,zh)==(1,1,0,1),'CUTOVER_B_PAIR')
            with psycopg.connect(fixture.TRADE_DSN) as c:
                b.bind(c,h);s.stock(c,csrf,'v85-cutover-stock')
                need(b.rpc(c,'naruv_valuation.audit_ledger',csrf)['status']=='RECONCILED','CUTOVER_LEDGER')
            with psycopg.connect(fixture.TRADE_DSN) as c:
                b.bind(c,zh)
                need(b.rpc(c,'naruv_valuation.audit_ledger',zcsrf)['status']=='RECONCILED','CUTOVER_OTHER_LEDGER')
            check(a.post(logout,headers=dict(origin,**{'x-csrf-token':'wrong-csrf-token-0000'})),403)
            need(s.state(fixture,h)==(1,1,0,1),'CUTOVER_BAD_LOGOUT_MUTATION')
            check(a.post(logout,headers=dict(origin,**{'x-csrf-token':csrf})),200)
            need(s.state(fixture,h)==(0,1,1,0),'CUTOVER_LOGOUT_PAIR')
            need(s.state(fixture,zh)==(1,1,0,1),'CUTOVER_OTHER_TENANT')
            with psycopg.connect(fixture.TRADE_DSN) as c:
                b.bind(c,h);s.denied_stock(c,csrf,'v85-denied')
            check(z.post(logout,headers=dict(origin,**{'x-csrf-token':zcsrf})),200)
            check(z.post(login,json={'email':'b@invalid.test','password':pw,'recovery_code':recovery},headers=origin),401)
        print('V85_CUTOVER_HTTP_LOGIN_LOGOUT_PASS tenants=2 recovery_replay_denied=1',flush=True)
        # A synthetic legacy-only session cannot reach any of the identity helpers.
        oldhash=s.token('legacy-only')
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at) VALUES('legacy-only',%s,'ci-ua',(now()+interval '1 hour')::text,%s,now()::text)",(oldhash,'q'*32))
        with psycopg.connect(fixture.TRADE_DSN) as c:
            b.bind(c,oldhash)
            need(c.execute('SELECT count(*) FROM jw_dev.stage_identity_v84()').fetchone()==(0,),'CUTOVER_LEGACY_STAGE')
            need(c.execute('SELECT jw_dev.current_org_from_session(),jw_dev.current_actor_from_session_v82()').fetchone()==(None,None),'CUTOVER_LEGACY_HELPERS')
            s.denied_stock(c,'q'*32,'legacy-denied')
        print('V85_CUTOVER_LEGACY_ONLY_DENIAL_PASS helpers=3',flush=True)
    print('V85_DUAL_CUTOVER_REVIEW_PASS production_authorized=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
