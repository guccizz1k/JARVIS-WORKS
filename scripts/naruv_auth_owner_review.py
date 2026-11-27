"""Least-privilege owner conversion for exact V85/identity routines in disposable PG17.
No hosted migration; original auth and identity function bodies remain unchanged.
"""
import hashlib
import importlib.util
import os
from pathlib import Path
from unittest.mock import patch
import psycopg
from psycopg import sql
from fastapi.testclient import TestClient

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('tls',HERE/'naruv_auth_tls_preflight_review.py')
t=importlib.util.module_from_spec(spec);spec.loader.exec_module(t)
v=t.v;s=t.s;b=t.b;base=t.base;need=t.need
R='naruv_identity_reader_ci'
W='naruv_v85_writer_ci'
OWNERS={
 W:('v85_auth_candidate(text)','v85_auth_failed(text)','v85_auth_issue_session(text,text,text,bigint,text)',
    'v85_auth_revoke_session(text)','v85_candidate_native_ci(text)','v85_issue_native_ci(text,text,text,bigint,text)','v85_revoke_native_ci(text)'),
 R:('v85_auth_check_csrf(text,text)','stage_identity_v84()','current_org_from_session()','current_actor_from_session_v82()')}
# Exact grants for reviewed function bodies, not learned from the target ACL.
READ={
 'jw_dev.users':'id,org_id,role',
 'jw_dev.sessions':'token_hash,user_id,expires_at,csrf_token',
 'jw_dev.organizations':'id,name',
 'jw_dev.staff_disabled':'user_id',
 'naruv_hosted_identity_review.users':'id,org_id,actor_role,active,epoch',
 'naruv_hosted_identity_review.sessions':'token_hash,actor_id,epoch,csrf_token,expires_at,revoked',
}
WRITE={
 'jw_dev.users':['SELECT','UPDATE(id)'],
 'jw_dev.sessions':['SELECT','INSERT','DELETE','UPDATE(id)'],
 'jw_dev.staff_disabled':['SELECT(user_id)'],
 'jw_dev.mfa_credentials':['SELECT','UPDATE(last_counter)'],
 'jw_dev.mfa_recovery_codes':['SELECT(user_id,code_hash,consumed_at)','UPDATE(consumed_at)'],
 'jw_dev.login_failures':['SELECT','INSERT','UPDATE(attempts,first_failed_at)','DELETE'],
 'jw_dev.security_events':['INSERT'],
 'naruv_hosted_identity_review.users':['SELECT','UPDATE(id)'],
 'naruv_hosted_identity_review.sessions':['SELECT','INSERT','UPDATE(revoked)'],
}
def install(fixture):
    with psycopg.connect(fixture.root_dsn) as c:
        bodies={sig:c.execute('SELECT pg_get_functiondef(%s::regprocedure)',('jw_dev.'+sig,)).fetchone()[0] for fs in OWNERS.values() for sig in fs}
        for role in OWNERS:
            c.execute(sql.SQL('CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION').format(sql.Identifier(role)))
            c.execute(sql.SQL('GRANT USAGE ON SCHEMA jw_dev,naruv_hosted_identity_review TO {}').format(sql.Identifier(role)))
        for table,cols in READ.items():
            c.execute('GRANT SELECT('+cols+') ON '+table+' TO '+R)
            c.execute('CREATE POLICY cutover_reader ON '+table+' FOR SELECT TO '+R+' USING(true)')
        for table,perms in WRITE.items():
            c.execute('GRANT '+','.join(perms)+' ON '+table+' TO '+W)
            for op in ('SELECT','INSERT','UPDATE','DELETE'):
                if not any(p==op or p.startswith(op+'(') for p in perms):continue
                suffix={'SELECT':'USING(true)','INSERT':'WITH CHECK(true)','DELETE':'USING(true)',
                    'UPDATE':'USING(true) WITH CHECK('+('false' if 'UPDATE(id)' in perms else 'true')+')'}[op]
                c.execute('CREATE POLICY cutover_writer_'+op.lower()+' ON '+table+' FOR '+op+' TO '+W+' '+suffix)
        for role,funcs in OWNERS.items():
            for sig in funcs:
                c.execute('ALTER FUNCTION jw_dev.'+sig+' OWNER TO '+role)
                need(c.execute('SELECT pg_get_functiondef(%s::regprocedure)',('jw_dev.'+sig,)).fetchone()[0]==bodies[sig],'OWNER_BODY_CHANGED')
        # Existing ACLs remain effective, explicit owner roles are not reachable
        # by business, authentication, ingestion or management service logins.
        for role,funcs in OWNERS.items():
            need(c.execute("SELECT rolcanlogin,rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname=%s",(role,)).fetchone()==(False,)*7,'OWNER_FLAGS')
            for sig in funcs:
                need(c.execute("SELECT pg_get_userbyid(proowner),prosecdef,proconfig FROM pg_proc WHERE oid=%s::regprocedure",('jw_dev.'+sig,)).fetchone()==(role,True,['search_path=pg_catalog']),'OWNER_ROUTINE')
                need(c.execute("""SELECT count(*) FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
                    WHERE p.oid=%s::regprocedure AND (a.grantee=0 OR a.is_grantable AND a.grantee<>p.proowner)""",('jw_dev.'+sig,)).fetchone()==(0,),'OWNER_ROUTINE_PUBLIC_OR_GRANTABLE')
            need(c.execute("SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid WHERE r.rolname=%s",(role,)).fetchone()==(0,),'OWNER_ROLE_MEMBERSHIP')
            for schema in ('jw_dev','naruv_hosted_identity_review'):
                need(c.execute("SELECT has_schema_privilege(%s,%s,'CREATE')",(role,schema)).fetchone()==(False,),'OWNER_SCHEMA_CREATE')
        # Deny exposure of credential data to identity readers, including the
        # credential fields on a table otherwise readable by column.
        for table,col in [('jw_dev.users','password_hash'),('jw_dev.users','email'),('jw_dev.mfa_credentials','secret_encrypted'),
                          ('jw_dev.mfa_recovery_codes','code_hash')]:
            need(c.execute("SELECT has_column_privilege(%s,%s,%s,'SELECT')",(R,table,col)).fetchone()==(False,),'OWNER_READER_SECRET')
        c.execute('SET LOCAL ROLE '+R)
        for q in ('SELECT password_hash FROM jw_dev.users','SELECT secret_encrypted FROM jw_dev.mfa_credentials',
                  'SELECT code_hash FROM jw_dev.mfa_recovery_codes','UPDATE jw_dev.sessions SET csrf_token=csrf_token'):
            s.expect(c,'42501',q)
        c.execute('RESET ROLE; SET LOCAL ROLE '+W)
        for q in ("UPDATE jw_dev.users SET role='member' WHERE id='ci-ua'",
                  "UPDATE jw_dev.users SET id=id WHERE id='ci-ua'",
                  "UPDATE naruv_hosted_identity_review.users SET id=id WHERE id='ci-ua'",
                  'DELETE FROM jw_dev.security_events'):
            s.expect(c,'42501',q)
        c.execute('RESET ROLE')
    print('AUTH_OWNER_LEAST_PRIVILEGE_PASS routines=11 owner_roles=2 direct_denials=8 bodies_unchanged=11',flush=True)

def main():
    base.preflight()
    b.pin(HERE/'naruv_v85_dual_cutover_review.py','565bf498c914c98cccbb905e2031b2a9bbd40081')
    from app import pg_auth_v85 as auth,pg_api_v84 as read,naruv_pg_auth_review as review
    from scripts.naruv_native_write_review_ci import NativeWrite
    real_read=read._connect
    fixture,_=base.setup()
    b.install(fixture);broker=s.install(fixture)
    dsn,pw,key,recovery,digest=v.install(fixture)
    install(fixture)
    cert=Path(os.environ['NARUV_TLS_CA']).resolve(strict=True)
    auth_dsn=t.tls(dsn,cert);trade_dsn=t.tls(fixture.TRADE_DSN,cert)
    read._connect=real_read
    app=NativeWrite.app
    origin={'origin':'https://testserver'}
    env={review.FLAG:review.ACK,'JW_DATA_KEY':key.decode(),'JW_PG_AUTH_STAGE_DSN':auth_dsn,'JW_PG_STAGE_DSN':trade_dsn}
    with patch.dict(os.environ,env):
        need(review.register(app),'OWNER_AUTH_REGISTER')
        need(read.register_stage_api(app),'OWNER_READ_REGISTER')
        login=review.PREFIX+'/login';logout=review.PREFIX+'/logout'
        # Force an error after original recovery proof consumption; the new
        # restricted owners must still preserve the transaction's atomicity.
        collision='7'*64
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("INSERT INTO naruv_hosted_identity_review.sessions(token_hash,actor_id,epoch,csrf_token,expires_at) VALUES(%s,'ci-ub',0,%s,clock_timestamp()+interval '1 hour')",(collision,'x'*32))
        with psycopg.connect(auth_dsn,autocommit=True) as c:
            c.execute('SET ROLE jw_auth_stage_v85')
            s.expect(c,'23505','SELECT jw_dev.v85_auth_issue_session(%s,%s,%s,NULL,%s)',('ci-ub',collision,'x'*32,digest))
            for q in ('SET ROLE '+R,'SET ROLE '+W,'SELECT password_hash FROM jw_dev.users','SELECT jw_dev.v85_issue_native_ci(NULL,NULL,NULL,NULL,NULL)'):
                s.expect(c,'42501',q)
        with psycopg.connect(fixture.root_dsn) as c:
            need(c.execute("SELECT consumed_at IS NULL FROM jw_dev.mfa_recovery_codes WHERE user_id='ci-ub'").fetchone()==(True,),'OWNER_MFA_ROLLBACK')
            need(c.execute("SELECT count(*) FROM jw_dev.sessions WHERE token_hash=%s",(collision,)).fetchone()==(0,),'OWNER_SESSION_ROLLBACK')
            need(c.execute("SELECT count(*) FROM jw_dev.security_events").fetchone()==(0,),'OWNER_EVENT_ROLLBACK')
            c.execute("DELETE FROM naruv_hosted_identity_review.sessions WHERE token_hash=%s",(collision,))
        print('AUTH_OWNER_ATOMIC_MFA_ROLLBACK_PASS',flush=True)
        with TestClient(app,base_url='https://testserver') as a,TestClient(app,base_url='https://testserver') as z:
            v.check(a.post(login,json=dict(email='a@invalid.test',password='wrong'),headers=origin),401)
            ar=v.check(a.post(login,json=dict(email='a@invalid.test',password=pw),headers=origin),200)
            br=v.check(z.post(login,json=dict(email='b@invalid.test',password=pw,recovery_code=recovery),headers=origin),200)
            ah=hashlib.sha256(a.cookies.get(auth.COOKIE).encode()).hexdigest()
            zh=hashlib.sha256(z.cookies.get(auth.COOKIE).encode()).hexdigest()
            need(s.state(fixture,ah)==s.state(fixture,zh)==(1,1,0,1),'OWNER_SESSION_PAIR')
            need(v.check(a.get('/api/pg-stage/v84/me'),200)['org_id']=='ci-a','OWNER_READ_A')
            need(v.check(z.get('/api/pg-stage/v84/me'),200)['org_id']=='ci-b','OWNER_READ_B')
            with psycopg.connect(trade_dsn) as c:
                b.bind(c,ah);s.stock(c,ar['csrf_token'],'owner-stock')
                need(b.rpc(c,'naruv_valuation.audit_ledger',ar['csrf_token'])['status']=='RECONCILED','OWNER_LEDGER')
            v.check(a.post(logout,headers=dict(origin,**{'x-csrf-token':ar['csrf_token']})),200)
            need(s.state(fixture,ah)==(0,1,1,0),'OWNER_LOGOUT')
            with psycopg.connect(trade_dsn) as c:
                b.bind(c,ah);s.denied_stock(c,ar['csrf_token'],'owner-denied')
            need(s.state(fixture,zh)==(1,1,0,1),'OWNER_OTHER_TENANT')
            v.check(z.post(logout,headers=dict(origin,**{'x-csrf-token':br['csrf_token']})),200)
            v.check(z.post(login,json=dict(email='b@invalid.test',password=pw,recovery_code=recovery),headers=origin),401)
        print('AUTH_OWNER_HTTP_ERP_PASS tenants=2 runtime_denials=4 recovery_replay_denied=1',flush=True)
    print('AUTH_OWNER_REVIEW_PASS production_authorized=false hosted_install=false gate5=BLOCKED',flush=True)
if __name__=='__main__':main()
