"""CI-only PostgreSQL session persistence adapter; no HTTP or real authentication.
Caller must already possess a trusted authenticated principal and active transaction.
Do not use the synthetic tables as a production identity store.
"""
import hashlib
from app.naruv_employee_access_review import (
    EmployeeIdentity,StatementEntitlement,EmployeeSession,issue_synthetic_session,
    review_employee_statement_access,need,ident,digest,TOKEN,AccessDenied)

def _guard(conn):
    need(not conn.autocommit)
    row=conn.execute("SELECT current_setting('naruv.employee_store_ci',true),current_database(),current_setting('server_version_num')::int").fetchone()
    need(row[0]=="DISPOSABLE_ONLY" and row[1]=="postgres" and 170000<=row[2]<=179999)

def _live(conn,tenant,principal,receipt):
    need(all(ident(x) for x in (tenant,principal,receipt)))
    i=conn.execute("SELECT tenant,principal,worker,auth_epoch,active FROM naruv_employee_ci.identities WHERE tenant=%s AND principal=%s FOR SHARE",(tenant,principal)).fetchone()
    need(i is not None)
    identity=EmployeeIdentity(*i)
    e=conn.execute("SELECT tenant,worker,receipt,review_sha256,render_sha256,active FROM naruv_employee_ci.entitlements WHERE tenant=%s AND worker=%s AND receipt=%s FOR SHARE",(tenant,identity.worker,receipt)).fetchone()
    need(e is not None)
    return identity,StatementEntitlement(*e)

def _now(conn):
    return conn.execute("SELECT floor(extract(epoch FROM clock_timestamp()))::bigint").fetchone()[0]

def issue(conn,*,trusted_tenant,trusted_principal,receipt,ttl=300):
    _guard(conn)
    i,e=_live(conn,trusted_tenant,trusted_principal,receipt)
    token,s=issue_synthetic_session(identity=i,entitlement=e,now=_now(conn),ttl=ttl)
    conn.execute("""INSERT INTO naruv_employee_ci.sessions
      (audience,tenant,principal,worker,auth_epoch,receipt,review_sha256,render_sha256,token_sha256,issued_at,expires_at,revoked)
      VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
      (s.audience,s.tenant,s.principal,s.worker,s.auth_epoch,s.receipt,s.review_sha256,s.render_sha256,s.token_sha256,s.issued_at,s.expires_at,s.revoked))
    return token

def access(conn,*,trusted_tenant,trusted_principal,receipt,review_sha256,render_sha256,token):
    _guard(conn)
    need(type(token) is str and TOKEN.fullmatch(token) and digest(review_sha256) and digest(render_sha256))
    i,e=_live(conn,trusted_tenant,trusted_principal,receipt)
    row=conn.execute("""SELECT audience,tenant,principal,worker,auth_epoch,receipt,review_sha256,render_sha256,token_sha256,issued_at,expires_at,revoked
      FROM naruv_employee_ci.sessions WHERE tenant=%s AND principal=%s AND token_sha256=%s FOR SHARE""",
      (trusted_tenant,trusted_principal,hashlib.sha256(token.encode("ascii")).hexdigest())).fetchone()
    need(row is not None)
    result=review_employee_statement_access(token=token,session=EmployeeSession(*row),identity=i,entitlement=e,now=_now(conn),
        requested_receipt=receipt,requested_review_sha256=review_sha256,requested_render_sha256=render_sha256)
    return dict(result,status="CI_POSTGRES_EMPLOYEE_SCOPE_MATCH_ONLY",session_store_verified=True)
