"""Real PG17 TLS auth login/logout acceptance against disposable ERP only."""
import hashlib
import os
import secrets
from unittest.mock import patch
import psycopg
from psycopg.conninfo import make_conninfo,conninfo_to_dict
from fastapi import FastAPI
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet
from app import pg_auth_v85 as auth,pg_v90_integrated_entry as v90,naruv_integrated_review as integrated
from app import naruv_pg_auth_review as review
from app.security_hardening import recovery_hash
from scripts import ci_v90_postgres_browser as fixture
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def verify(cert,dsns):
    opts=conninfo_to_dict(fixture.root_dsn)
    assert os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE"
    assert (opts["host"],opts["port"],opts["dbname"],opts["user"])==("127.0.0.1","5432","postgres","postgres")
    names=("mfa_credentials","mfa_recovery_codes","login_failures","security_events")
    users=("ci-ua","ci-ub")
    password=secrets.token_urlsafe(24);salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,260000)
    encoded=f"pbkdf2_sha256$260000${salt.hex()}${digest.hex()}"
    key=Fernet.generate_key()
    recovery=secrets.token_hex(16)
    cipher=Fernet(key).encrypt(b"JBSWY3DPEHPK3PXP").decode()
    with psycopg.connect(fixture.root_dsn) as root:
        assert root.execute("SELECT count(*) FROM pg_tables WHERE schemaname='jw_dev' AND tablename=ANY(%s)",(list(names),)).fetchone()==(0,)
        assert root.execute("SELECT to_regprocedure('jw_dev.v85_auth_candidate(text)')").fetchone()==(None,)
        before=root.execute("SELECT id,password_hash FROM jw_dev.users WHERE id=ANY(%s) ORDER BY id",(list(users),)).fetchall()
        assert len(before)==2
        root.execute("CREATE TABLE jw_dev.mfa_credentials(user_id text PRIMARY KEY REFERENCES jw_dev.users(id),secret_encrypted text NOT NULL,last_counter bigint NOT NULL)")
        root.execute("CREATE TABLE jw_dev.mfa_recovery_codes(user_id text REFERENCES jw_dev.users(id),code_hash text,consumed_at text,PRIMARY KEY(user_id,code_hash))")
        root.execute("CREATE TABLE jw_dev.login_failures(email text PRIMARY KEY,attempts bigint NOT NULL,first_failed_at text NOT NULL)")
        root.execute("CREATE TABLE jw_dev.security_events(id text PRIMARY KEY,org_id text,actor_id text,event_type text,created_at text)")
        for name in names:
            # Fixed names above, no external inputs.
            root.execute("ALTER TABLE jw_dev."+name+" ENABLE ROW LEVEL SECURITY")
            root.execute("ALTER TABLE jw_dev."+name+" FORCE ROW LEVEL SECURITY")
            root.execute("REVOKE ALL ON jw_dev."+name+" FROM PUBLIC")
        root.execute("UPDATE jw_dev.users SET password_hash=%s WHERE id=ANY(%s)",(encoded,list(users)))
        root.execute("INSERT INTO jw_dev.mfa_credentials VALUES('ci-ub',%s,-1)",(cipher,))
        root.execute("INSERT INTO jw_dev.mfa_recovery_codes VALUES('ci-ub',%s,NULL)",(recovery_hash("ci-ub",recovery),))
    try:
        # Original V85 migration includes BEGIN/COMMIT. Run only on the
        # exact disposable service, not on any deployed DB.
        with psycopg.connect(fixture.root_dsn,autocommit=True) as root:
            root.execute((ROOT/"migrations/v85_auth_stage.sql").read_text())
        from app import naruv_hr_profile_review as profiles
        with psycopg.connect(fixture.root_dsn) as root:
            root.execute("SELECT set_config('naruv.profile_ci','DISPOSABLE_ONLY',true)")
            root.execute((ROOT/"db/review/naruv_hr_profile_ci.sql").read_text())
        tls={p:make_conninfo(d,sslmode="verify-full",sslrootcert=str(cert),gssencmode="disable",connect_timeout=3) for p,d in dsns.items()}
        env={review.FLAG:review.ACK,integrated.FLAG:integrated.ACK,integrated.drafts.FLAG:integrated.ACK,integrated.hr.FLAG:integrated.ACK,"JW_PG_AUTH_STAGE_DSN":tls["auth"],"JW_PG_STAGE_DSN":tls["business"],
            "JW_V90_ALLOWED_ORIGINS":"https://testserver","JW_DATA_KEY":key.decode(),"JW_ENV":"dev",profiles.FLAG:"DISPOSABLE_FIXTURE_ONLY",profiles.KEY:secrets.token_hex(32)}
        with patch.dict(os.environ,env),patch.object(v90.stage,"_connect",lambda:psycopg.connect(tls["business"])):
            app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
            assert integrated.register_integrated_review(app,include_drafts=True,include_hr=True)
            assert review.register(app)
            assert profiles.register(app)
            login=review.PREFIX+"/login";logout=review.PREFIX+"/logout"
            path=integrated.PREFIX+"/drafts/payroll/worker-1/2026-11"
            origin={"origin":"https://testserver"}
            def sign(c,email,code=200,**extra):
                r=c.post(login,json=dict(email=email,password=password,**extra),headers=origin)
                assert r.status_code==code,("LOGIN_STATUS",r.status_code,code)
                return r
            with TestClient(app,base_url="https://testserver") as a,TestClient(app,base_url="https://testserver") as b:
                assert a.post(login,json={"email":"a@invalid.test","password":password}).status_code==403
                assert a.post(login,json={"email":"a@invalid.test","password":"wrong"},headers=origin).status_code==401
                assert a.post(login,content=b'{"email":"a","email":"b","password":"x"}',headers=dict(origin,**{"content-type":"application/json"})).status_code==422
                assert a.post(login,content=b"x"*8193,headers=dict(origin,**{"content-type":"application/json"})).status_code==413
                ar=sign(a,"a@invalid.test")
                acsrf=ar.json()["csrf_token"];atoken=a.cookies.get(auth.COOKIE)
                assert all(v in ar.headers["set-cookie"] for v in ("Secure","HttpOnly","SameSite=strict"))
                assert ar.headers["cache-control"]=="no-store"
                ah=dict(origin,**{"x-csrf-token":acsrf})
                sign(a,"a@invalid.test",409)
                assert a.post(path,headers=ah).json()["gross_krw"]==114000
                sign(b,"b@invalid.test",401)
                br=sign(b,"b@invalid.test",recovery_code=recovery)
                bcsrf=br.json()["csrf_token"];bh=dict(origin,**{"x-csrf-token":bcsrf})
                assert b.post(path,headers=bh).json()["gross_krw"]==171000
                assert b.post(path,headers=ah).status_code==403
                profile=profiles.PREFIX+"/workers/worker-1"
                value={"revision":"r1","profile":{"display_name":"Synthetic Worker","work_email":"worker@example.invalid","employment_start":"2026-01-01"}}
                assert a.post(profile+"/create",json=value,headers=ah).status_code==422
                create=dict(ah,**{"x-naruv-confirm":"yes"})
                def profile_status(action,code,**kwargs):
                    r=a.post(profile+"/"+action,**kwargs)
                    # Never echo body, cookie, credential or personal data.
                    detail=r.json().get("detail") if r.headers.get("content-type","").startswith("application/json") else None
                    safe=detail if isinstance(detail,str) and detail.isascii() and detail.replace("_","").isalnum() and len(detail)<80 else "REDACTED"
                    assert r.status_code==code,("PROFILE_STATUS",action,r.status_code,code,safe)
                    return r
                raw_headers=dict(create,**{"content-type":"application/json"})
                profile_status("create",422,headers=raw_headers,content=b'{"revision":"r1","profile":{"display_name":"Synthetic Worker","display_name":"Synthetic Other","work_email":"worker@example.invalid","employment_start":"2026-01-01"}}')
                profile_status("create",422,headers=create,json={"revision":"r1","profile":True})
                profile_status("create",422,headers=create,json={"revision":"r1","profile":dict(value["profile"],employment_start=123)})
                profile_status("create",413,headers=raw_headers,content=b"x"*8193)
                profile_status("create",200,headers=create,json=value)
                profile_status("create",409,headers=create,json=value)
                assert profile_status("read",200,headers=ah).json()["profile"]==value["profile"]
                assert b.post(profile+"/read",headers=bh).status_code==404
                assert b.post(profile+"/read",headers=ah).status_code==403
                with psycopg.connect(fixture.root_dsn) as root:
                    encrypted=root.execute("SELECT envelope FROM naruv_draft.profile_envelopes").fetchone()[0]
                    assert "Synthetic Worker" not in str(encrypted) and "worker@example.invalid" not in str(encrypted)
                    assert root.execute("SELECT relrowsecurity AND relforcerowsecurity FROM pg_class WHERE oid='naruv_draft.profile_envelopes'::regclass").fetchone()==(True,)
                    assert root.execute("SELECT has_table_privilege('jw_app_dev','naruv_draft.profile_envelopes','SELECT')").fetchone()==(False,)
                print("NARUV_HR_PROFILE_PG_PASS authenticated encrypted storage, duplicate, tenant and CSRF denial",flush=True)
                assert a.post(logout,headers=dict(origin,**{"x-csrf-token":"x"*32})).status_code==403
                assert a.post(logout,headers=ah).status_code==200
                assert a.cookies.get(auth.COOKIE) is None
                a.cookies.set(auth.COOKIE,atoken)
                assert a.post(path,headers=ah).status_code==401
                a.cookies.clear()
                assert b.post(logout,headers=bh).status_code==200
                sign(b,"b@invalid.test",401,recovery_code=recovery)
                with psycopg.connect(fixture.root_dsn) as root:
                    assert root.execute("SELECT count(*) FROM jw_dev.sessions WHERE token_hash=%s",(hashlib.sha256(atoken.encode()).hexdigest(),)).fetchone()==(0,)
                    assert root.execute("SELECT count(*) FROM jw_dev.mfa_recovery_codes WHERE consumed_at IS NOT NULL").fetchone()==(1,)
                    assert root.execute("SELECT event_type,count(*) FROM jw_dev.security_events GROUP BY event_type ORDER BY 1").fetchall()==[("login_success",2),("logout",2)]
                # Actual persistent lockout and disabled-account checks.
                for _ in range(5):
                    assert a.post(login,json={"email":"a@invalid.test","password":"wrong"},headers=origin).status_code==401
                sign(a,"a@invalid.test",429)
                with psycopg.connect(fixture.root_dsn) as root:
                    root.execute("DELETE FROM jw_dev.login_failures WHERE email='a@invalid.test'")
                    root.execute("INSERT INTO jw_dev.staff_disabled(user_id) VALUES('ci-ua')")
                try:sign(a,"a@invalid.test",401)
                finally:
                    with psycopg.connect(fixture.root_dsn) as root:
                        root.execute("DELETE FROM jw_dev.staff_disabled WHERE user_id='ci-ua'")
        print("NARUV_REAL_PG_AUTH_PASS verified TLS login, MFA recovery single-use, tenant payroll, CSRF, logout replay, lockout, disabled account",flush=True)
    finally:
        # Only fixture objects created above. Restore original synthetic users.
        with psycopg.connect(fixture.root_dsn) as root:
            root.execute("DELETE FROM jw_dev.sessions WHERE user_id=ANY(%s) AND id NOT IN ('A','B')",(list(users),))
            for uid,pw in before:root.execute("UPDATE jw_dev.users SET password_hash=%s WHERE id=%s",(pw,uid))
            for signature in ("v85_auth_candidate(text)","v85_auth_failed(text)","v85_auth_issue_session(text,text,text,bigint,text)","v85_auth_revoke_session(text)","v85_auth_check_csrf(text,text)"):
                root.execute("DROP FUNCTION IF EXISTS jw_dev."+signature)
            root.execute("DROP FUNCTION IF EXISTS naruv_draft.profile_envelope(text,text,jsonb,text)")
            root.execute("DROP TABLE IF EXISTS naruv_draft.profile_envelopes")
            for name in names:root.execute("DROP TABLE jw_dev."+name)
