"""Local-only dual identity atomic broker and native ERP concurrency rehearsal."""
import hashlib
import importlib.util
from pathlib import Path
import secrets
import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
from psycopg.types.json import Jsonb

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('bridge',HERE/'naruv_native_auth_bridge_review.py')
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
base=b.base
need=b.need
BROKER='naruv_sync_broker_ci'
OWNER='naruv_sync_owner_ci'
P='naruv_sync_ci.'
DDL="""
CREATE ROLE naruv_sync_owner_ci NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_sync_broker_ci NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE SCHEMA naruv_sync_ci AUTHORIZATION naruv_sync_owner_ci;
REVOKE ALL ON SCHEMA naruv_sync_ci FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON SCHEMA naruv_sync_ci TO naruv_sync_broker_ci;
GRANT USAGE ON SCHEMA jw_dev,naruv_hosted_identity_review TO naruv_sync_owner_ci;
GRANT SELECT(id,org_id,role),UPDATE(role) ON jw_dev.users TO naruv_sync_owner_ci;
GRANT SELECT(id,user_id,token_hash),INSERT(id,token_hash,user_id,expires_at,csrf_token,created_at),DELETE ON jw_dev.sessions TO naruv_sync_owner_ci;
GRANT SELECT,INSERT,DELETE ON jw_dev.staff_disabled TO naruv_sync_owner_ci;
ALTER TABLE jw_dev.staff_disabled ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.staff_disabled FORCE ROW LEVEL SECURITY;
CREATE POLICY sync_users ON jw_dev.users TO naruv_sync_owner_ci USING(true) WITH CHECK(true);
CREATE POLICY sync_sessions ON jw_dev.sessions TO naruv_sync_owner_ci USING(true) WITH CHECK(true);
CREATE POLICY sync_disabled ON jw_dev.staff_disabled TO naruv_sync_owner_ci USING(true) WITH CHECK(true);
SET LOCAL ROLE naruv_hid_owner;
GRANT SELECT(id,org_id,actor_role,active) ON naruv_hosted_identity_review.users TO naruv_sync_owner_ci;
GRANT SELECT(token_hash,actor_id,expires_at,revoked) ON naruv_hosted_identity_review.sessions TO naruv_sync_owner_ci;
CREATE POLICY sync_users_read ON naruv_hosted_identity_review.users FOR SELECT TO naruv_sync_owner_ci USING(true);
CREATE POLICY sync_sessions_read ON naruv_hosted_identity_review.sessions FOR SELECT TO naruv_sync_owner_ci USING(true);
RESET ROLE;
SET LOCAL ROLE naruv_hid_writer;
REVOKE EXECUTE ON FUNCTION naruv_hosted_identity_review.issue(text,text,text,integer),naruv_hosted_identity_review.revoke(text),naruv_hosted_identity_review.change_actor(text,boolean,text) FROM naruv_hid_auth;
GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.issue(text,text,text,integer),naruv_hosted_identity_review.revoke(text),naruv_hosted_identity_review.change_actor(text,boolean,text) TO naruv_sync_owner_ci;
RESET ROLE;
SET LOCAL ROLE naruv_sync_owner_ci;
CREATE FUNCTION naruv_sync_ci.issue(p_id text,p_actor text,p_hash text,p_csrf text,p_ttl integer)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE h record; l record; expiry timestamptz;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR p_id IS NULL OR p_id !~ '^[A-Za-z0-9-]{1,128}$' THEN RAISE EXCEPTION 'SYNC_INPUT' USING ERRCODE='23514'; END IF;
 -- Hosted issue locks user first; legacy trigger subsequently takes native fence.
 IF NOT naruv_hosted_identity_review.issue(p_actor,p_hash,p_csrf,p_ttl) THEN RAISE EXCEPTION 'SYNC_ISSUE'; END IF;
 SELECT id,org_id,actor_role,active INTO h FROM naruv_hosted_identity_review.users WHERE id=p_actor;
 SELECT id,org_id,role INTO l FROM jw_dev.users WHERE id=p_actor;
 IF NOT FOUND OR NOT h.active OR (h.id,h.org_id,h.actor_role) IS DISTINCT FROM (l.id,l.org_id,l.role)
 OR EXISTS(SELECT 1 FROM jw_dev.staff_disabled WHERE user_id=p_actor) THEN RAISE EXCEPTION 'SYNC_IDENTITY_DRIFT' USING ERRCODE='42501'; END IF;
 SELECT expires_at INTO STRICT expiry FROM naruv_hosted_identity_review.sessions WHERE token_hash=p_hash AND actor_id=p_actor AND NOT revoked;
 INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at)
 VALUES(p_id,p_hash,p_actor,expiry::text,p_csrf,clock_timestamp()::text);
 RETURN true;
END $f$;
CREATE FUNCTION naruv_sync_ci.revoke(p_hash text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE a text; n int;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'SYNC_INPUT' USING ERRCODE='23514'; END IF;
 SELECT actor_id INTO a FROM naruv_hosted_identity_review.sessions WHERE token_hash=p_hash;
 IF NOT FOUND THEN RAISE EXCEPTION 'SYNC_UNKNOWN' USING ERRCODE='42501'; END IF;
 IF NOT naruv_hosted_identity_review.revoke(p_hash) THEN
   IF EXISTS(SELECT 1 FROM jw_dev.sessions WHERE token_hash=p_hash) THEN RAISE EXCEPTION 'SYNC_DRIFT' USING ERRCODE='42501'; END IF;
   RETURN false;
 END IF;
 DELETE FROM jw_dev.sessions WHERE token_hash=p_hash AND user_id=a;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RAISE EXCEPTION 'SYNC_DRIFT' USING ERRCODE='42501'; END IF;
 RETURN true;
END $f$;
CREATE FUNCTION naruv_sync_ci.change_actor(p_actor text,p_active boolean,p_role text)
RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE h record; l record;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'SYNC_INPUT' USING ERRCODE='23514'; END IF;
 IF NOT naruv_hosted_identity_review.change_actor(p_actor,p_active,p_role) THEN RAISE EXCEPTION 'SYNC_CHANGE'; END IF;
 SELECT id,org_id INTO h FROM naruv_hosted_identity_review.users WHERE id=p_actor;
 SELECT id,org_id INTO l FROM jw_dev.users WHERE id=p_actor;
 IF NOT FOUND OR (h.id,h.org_id) IS DISTINCT FROM (l.id,l.org_id) THEN RAISE EXCEPTION 'SYNC_IDENTITY_DRIFT' USING ERRCODE='42501'; END IF;
 UPDATE jw_dev.users SET role=p_role WHERE id=p_actor;
 DELETE FROM jw_dev.sessions WHERE user_id=p_actor;
 IF p_active THEN DELETE FROM jw_dev.staff_disabled WHERE user_id=p_actor;
 ELSE INSERT INTO jw_dev.staff_disabled(user_id) VALUES(p_actor) ON CONFLICT DO NOTHING; END IF;
 RETURN true;
END $f$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_sync_ci FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_sync_ci.issue(text,text,text,text,integer),naruv_sync_ci.revoke(text),naruv_sync_ci.change_actor(text,boolean,text) TO naruv_sync_broker_ci;
RESET ROLE;
"""
def install(fixture):
    pw=secrets.token_urlsafe(32)
    with psycopg.connect(fixture.root_dsn) as c:
        c.execute(DDL)
        c.execute(sql.SQL('ALTER ROLE {} LOGIN PASSWORD {}').format(sql.Identifier(BROKER),sql.Literal(pw)))
    return make_conninfo(fixture.root_dsn,user=BROKER,password=pw)

def token(label):return hashlib.sha256(('dual-review-'+label).encode()).hexdigest()
def issue(a,label,actor,csrf,sid=None):
    h=token(label)
    need(a.execute('SELECT '+P+'issue(%s,%s,%s,%s,3600)',(sid or label,actor,h,csrf)).fetchone()==(True,),'SYNC_ISSUE')
    return h
def revoke(a,h):
    return a.execute('SELECT '+P+'revoke(%s)',(h,)).fetchone()[0]
def change(a,actor,active,role):
    need(a.execute('SELECT '+P+'change_actor(%s,%s,%s)',(actor,active,role)).fetchone()==(True,),'SYNC_CHANGE')
def expect(c,code,query,args=()):
    try:
        with c.transaction():c.execute(query,args)
    except psycopg.Error as e:need(e.sqlstate==code,'SYNC_EXPECTED_'+code+'_GOT_'+str(e.sqlstate))
    else:raise RuntimeError('SYNC_UNEXPECTED_ACCEPT_'+code)
def state(fixture,h):
    with psycopg.connect(fixture.root_dsn) as c:
        return c.execute("""SELECT
          (SELECT count(*) FROM jw_dev.sessions WHERE token_hash=%s),
          (SELECT count(*) FROM naruv_hosted_identity_review.sessions WHERE token_hash=%s),
          (SELECT count(*) FROM naruv_hosted_identity_review.sessions WHERE token_hash=%s AND revoked),
          (SELECT count(*) FROM jw_dev.sessions l JOIN naruv_hosted_identity_review.sessions r ON r.token_hash=l.token_hash
           WHERE l.token_hash=%s AND l.user_id=r.actor_id AND l.expires_at::timestamptz=r.expires_at AND l.csrf_token=r.csrf_token)""",(h,h,h,h)).fetchone()
def stock(c,csrf,rid):
    return b.rpc(c,'naruv_valuation.receive','001',rid,Jsonb(dict(source_id='source-a',warehouse_id='W1',quantity=1,unit_cost=105)),True,csrf)
def denied_stock(c,csrf,rid,code='42501'):
    b.denied(c,'naruv_valuation.receive',('001',rid,Jsonb(dict(source_id='source-a',warehouse_id='W1',quantity=1,unit_cost=105)),True,csrf),code)
def main():
    base.preflight()
    b.pin(HERE/'naruv_native_auth_bridge_review.py','af21613738e407bfe5bb17be1a9c164c90bac1c2')
    fixture,_=base.setup()
    old_auth=b.install(fixture)
    dsn=install(fixture)
    csrf=fixture.CSRF['A']
    with psycopg.connect(dsn,autocommit=True) as a:
        need(a.execute('SELECT session_user,current_user').fetchone()==(BROKER,BROKER),'SYNC_LOGIN')
        a.execute("SET lock_timeout='300ms'")
        a.execute("SET statement_timeout='8s'")
        h=issue(a,'sync-a','ci-ua',csrf)
        hb=issue(a,'sync-b','ci-ub',fixture.CSRF['B'])
        need(state(fixture,h)==state(fixture,hb)==(1,1,0,1),'SYNC_EXACT_PAIR')
        # Deliberately fail the second store after hosted issue succeeds.
        expect(a,'23505','SELECT '+P+'issue(%s,%s,%s,%s,3600)',('sync-a','ci-ua',token('duplicate-id'),csrf))
        need(state(fixture,token('duplicate-id'))==(0,0,0,0),'SYNC_ISSUE_ROLLBACK')
        print('DUAL_AUTH_ATOMIC_ISSUE_PASS',flush=True)
        with psycopg.connect(old_auth,autocommit=True) as old:
            expect(old,'42501','SELECT naruv_hosted_identity_review.issue(%s,%s,%s,3600)',('ci-ua',token('old-path'),csrf))
            expect(old,'42501','SELECT naruv_hosted_identity_review.change_actor(%s,false,%s)',('ci-ua','admin'))
        for query in ('SELECT * FROM jw_dev.sessions','DELETE FROM jw_dev.sessions','SELECT * FROM naruv_hosted_identity_review.sessions','SET ROLE naruv_sync_owner_ci'):
            expect(a,'42501',query)
        print('DUAL_AUTH_DIRECT_BYPASS_DENIAL_PASS cases=6',flush=True)
        # Native business transaction wins; broker cannot revoke while session lock held.
        with psycopg.connect(fixture.TRADE_DSN,autocommit=True) as c:
            c.execute("SET lock_timeout='300ms'");c.execute("SET statement_timeout='8s'")
            c.execute('BEGIN');b.bind(c,h);stock(c,csrf,'sync-business-first')
            expect(a,'55P03','SELECT '+P+'revoke(%s)',(h,))
            c.execute('COMMIT')
            need(revoke(a,h) and state(fixture,h)==(0,1,1,0),'SYNC_REVOKE_PAIR')
            need(revoke(a,h) is False,'SYNC_REVOKE_REPLAY')
            c.execute('BEGIN');b.bind(c,h);denied_stock(c,csrf,'sync-business-first');c.execute('ROLLBACK')
            print('DUAL_AUTH_BUSINESS_FIRST_PASS',flush=True)
            # Broker wins; both changes held until commit; no business write allowed.
            h=issue(a,'sync-revoke-first','ci-ua',csrf)
            a.execute('BEGIN');need(revoke(a,h),'SYNC_REVOKE')
            c.execute('BEGIN');b.bind(c,h);denied_stock(c,csrf,'sync-denied','55P03');c.execute('ROLLBACK')
            a.execute('COMMIT')
            c.execute('BEGIN');b.bind(c,h);denied_stock(c,csrf,'sync-denied');c.execute('ROLLBACK')
            need(state(fixture,h)==(0,1,1,0),'SYNC_REVOKE_COMMIT')
            print('DUAL_AUTH_REVOKE_FIRST_PASS',flush=True)
            # Failed broker transaction leaves both stores and native state unchanged.
            h=issue(a,'sync-change-rollback','ci-ua',csrf)
            a.execute('BEGIN');change(a,'ci-ua',False,'member');a.execute('ROLLBACK')
            need(state(fixture,h)==(1,1,0,1),'SYNC_CHANGE_ROLLBACK')
            c.execute('BEGIN');b.bind(c,h);stock(c,csrf,'sync-business-rollback');c.execute('ROLLBACK')
            before=b.snapshot(fixture)
            a.execute('BEGIN');change(a,'ci-ua',False,'member')
            c.execute('BEGIN');b.bind(c,h);denied_stock(c,csrf,'sync-denied-change','55P03');c.execute('ROLLBACK')
            a.execute('COMMIT')
            need(state(fixture,h)==(0,1,1,0),'SYNC_CHANGE_COMMIT')
            change(a,'ci-ua',True,'admin')
            c.execute('BEGIN');b.bind(c,h);denied_stock(c,csrf,'sync-no-revival');c.execute('ROLLBACK')
            need(b.snapshot(fixture)==before,'SYNC_DENIED_ERP_MUTATION')
            need(state(fixture,hb)==(1,1,0,1),'SYNC_OTHER_TENANT')
            fresh=issue(a,'sync-fresh','ci-ua',csrf)
            c.execute('BEGIN');b.bind(c,fresh)
            v=b.rpc(c,'naruv_valuation.inspect','source-a','001','W1',csrf)
            need(int(v['quantity'])==1,'SYNC_EXACT_STOCK')
            proof=b.rpc(c,'naruv_valuation.audit_ledger',csrf)
            need(proof['status']=='RECONCILED','SYNC_LEDGER')
            c.execute('COMMIT')
            print('DUAL_AUTH_CHANGE_ROLLBACK_AND_REACTIVATION_PASS',flush=True)
    print('DUAL_AUTH_SYNC_REVIEW_PASS cases=5 production_authorized=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
