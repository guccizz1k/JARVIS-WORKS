"""Transactional boundary initializer for a dedicated synthetic QA schema.

Only the explicit disposable CI entry is executable today. No hosted admin
connection, DB creation, production migration, password generation or release.
A future hosted wrapper must separately establish approved database identity,
TLS, provisioning privileges, and immutable source evidence.
"""
import os
import re
from psycopg import sql
from .naruv_hosted_qa_admission import PURPOSES,PROTECTED,AdmissionBlocked,need

OWNER="naruv_qa_boundary_owner"
SCHEMA="naruv_hosted_qa"

def _initialize(cur,*,database,marker,source_sha):
    """Caller must own one transaction. Failure must roll back the entire DDL."""
    need(type(marker) is str and re.fullmatch(r"[0-9a-f]{64}",marker),"BOUNDARY_MARKER")
    need(type(source_sha) is str and re.fullmatch(r"[0-9a-f]{40}",source_sha),"BOUNDARY_SOURCE")
    cur.execute("""SELECT current_database(),current_setting('server_version_num')::int/10000,
      current_setting('transaction_read_only'),current_user=session_user""")
    need(cur.fetchone()==(database,17,"off",True),"BOUNDARY_DATABASE")
    # Serialize initializer attempts; existing schema is never overwritten.
    cur.execute("SELECT pg_advisory_xact_lock(hashtextextended('naruv-hosted-qa-boundary-v1',0))")
    cur.execute("SELECT to_regnamespace(%s)",(SCHEMA,))
    need(cur.fetchone()==(None,),"BOUNDARY_EXISTS")
    cur.execute("SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication FROM pg_roles WHERE rolname=%s",(OWNER,))
    need(cur.fetchone()==(False,False,False,False,False,False),"BOUNDARY_OWNER")
    for _,user,role in PURPOSES.values():
        cur.execute("""SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication,rolinherit,
            pg_has_role(rolname,%s,'SET'),pg_has_role(rolname,%s,'USAGE')
            FROM pg_roles WHERE rolname=%s""",(role,role,user))
        need(cur.fetchone()==(True,False,False,False,False,False,False,True,False),"BOUNDARY_RUNTIME_ROLE")
    for relation in PROTECTED:
        schema,table=relation.split(".")
        cur.execute("""SELECT c.relrowsecurity,c.relforcerowsecurity FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname=%s AND c.relname=%s AND c.relkind='r'""",(schema,table))
        need(cur.fetchone()==(True,True),"BOUNDARY_SCHEMA_NOT_READY")
    cur.execute(sql.SQL("CREATE SCHEMA {} AUTHORIZATION {}").format(sql.Identifier(SCHEMA),sql.Identifier(OWNER)))
    cur.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(OWNER)))
    cur.execute("REVOKE ALL ON SCHEMA naruv_hosted_qa FROM PUBLIC")
    cur.execute("""CREATE TABLE naruv_hosted_qa.boundary(
        singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
        marker text NOT NULL CHECK(marker ~ '^[0-9a-f]{64}$'),
        source_sha text NOT NULL CHECK(source_sha ~ '^[0-9a-f]{40}$'))""")
    cur.execute("INSERT INTO naruv_hosted_qa.boundary(marker,source_sha) VALUES(%s,%s)",(marker,source_sha))
    cur.execute("REVOKE ALL ON naruv_hosted_qa.boundary FROM PUBLIC")
    for _,user,_ in PURPOSES.values():
        cur.execute(sql.SQL("GRANT USAGE ON SCHEMA naruv_hosted_qa TO {}").format(sql.Identifier(user)))
        cur.execute(sql.SQL("GRANT SELECT ON naruv_hosted_qa.boundary TO {}").format(sql.Identifier(user)))
    cur.execute("RESET ROLE")

def initialize_ci(cur,*,marker,source_sha):
    """No caller-provided environment or remote DB target; CI only."""
    need(os.getenv("GITHUB_ACTIONS")=="true" and os.getenv("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE",
         "BOUNDARY_CI_ONLY")
    cur.execute("SELECT inet_server_addr()::text,inet_server_port(),current_database(),session_user")
    row=cur.fetchone()
    # Actions service is exposed through loopback port 5432 but PostgreSQL
    # sees its own container interface. The caller additionally checks DSN.
    need(row is not None and row[1:]==(5432,"postgres","postgres"),"BOUNDARY_CI_TARGET")
    _initialize(cur,database="postgres",marker=marker,source_sha=source_sha)
