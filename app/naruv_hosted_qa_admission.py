"""Read-only admission probe for a future dedicated hosted synthetic QA database.

Not an ASGI entrypoint, migration, credential provisioner or release approval.
No database access occurs on import. No fallback to existing WORKS DSNs.
"""
from dataclasses import dataclass,field
import os
import re
import psycopg
from psycopg.conninfo import conninfo_to_dict

ACK="DEDICATED_SYNTHETIC_READ_ONLY"
PURPOSES={
    "business":("NARUV_HOSTED_QA_BUSINESS_DSN","naruv_qa_business","jw_app_dev"),
    "auth":("NARUV_HOSTED_QA_AUTH_DSN","naruv_qa_auth","jw_auth_stage_v85"),
    "ingest":("NARUV_HOSTED_QA_INGEST_DSN","naruv_qa_ingest","naruv_native_stage"),
}
FORBIDDEN=("DATABASE_URL","JW_PG_STAGE_DSN","JW_PG_AUTH_STAGE_DSN",
    "NARUV_NATIVE_STAGE_DSN","JW_PG_SOURCE_DSN","JW_PG_TARGET_ADMIN_DSN",
    "SUPABASE_SERVICE_ROLE_KEY","SUPABASE_DB_PASSWORD","JW_PG_BACKUP_KEY",
    "JW_PG_BACKUP_RO_PASSWORD","JW_PG_CI_ROOT_DSN","JW_PG_CI_ALLOW",
    "JW_INSECURE_LOCAL_DEV","GITHUB_ACTIONS")
ALLOWED_DSN=frozenset(("host","port","dbname","user","password","sslmode","sslrootcert"))
PROTECTED=("naruv_draft.staff","naruv_draft.pay_periods","naruv_draft.attendance",
           "naruv_draft.documents","naruv_auth_fence.epochs")

class AdmissionBlocked(RuntimeError):pass

def need(ok,code):
    if not ok:raise AdmissionBlocked(code)

@dataclass(frozen=True)
class Config:
    host:str
    database:str
    source_sha:str
    marker:str=field(repr=False)
    dsns:dict=field(repr=False)

def parse_config(env):
    need(env.get("NARUV_HOSTED_QA_ADMISSION")==ACK and env.get("JW_ENV")=="review","HOSTED_QA_DISABLED")
    need(not any(env.get(k) for k in FORBIDDEN),"HOSTED_QA_MIXED_ENV")
    # Libpq may inherit connection settings from PG* environment variables.
    need(not any(k.startswith("PG") and v for k,v in env.items()),"HOSTED_QA_LIBPQ_ENV")
    host=env.get("NARUV_HOSTED_QA_DB_HOST","")
    db=env.get("NARUV_HOSTED_QA_DB_NAME","")
    sha=env.get("NARUV_HOSTED_QA_SOURCE_SHA","")
    marker=env.get("NARUV_HOSTED_QA_DB_MARKER","")
    need(re.fullmatch(r"dpg-[a-z0-9-]{8,80}\.[a-z0-9-]{2,40}-postgres\.render\.com",host) is not None,"HOSTED_QA_HOST")
    need(re.fullmatch(r"naruv_qa_[a-z0-9_]{8,40}",db) is not None,"HOSTED_QA_DATABASE")
    need(re.fullmatch(r"[0-9a-f]{40}",sha) is not None and env.get("RENDER_GIT_COMMIT")==sha,"HOSTED_QA_SOURCE")
    need(re.fullmatch(r"[0-9a-f]{64}",marker) is not None,"HOSTED_QA_MARKER")
    dsns={};passwords=set()
    for purpose,(variable,user,_) in PURPOSES.items():
        raw=env.get(variable,"")
        need(isinstance(raw,str) and 1<=len(raw)<=4096,"HOSTED_QA_DSN")
        try:opts=conninfo_to_dict(raw)
        except (ValueError,psycopg.Error):raise AdmissionBlocked("HOSTED_QA_DSN") from None
        need(set(opts)==ALLOWED_DSN and opts["host"]==host and opts["port"]=="5432"
            and opts["dbname"]==db and opts["user"]==user and opts["sslmode"]=="verify-full"
            and opts["sslrootcert"]=="system" and 24<=len(opts["password"])<=512
            and opts["password"] not in passwords,"HOSTED_QA_DSN_SCOPE")
        passwords.add(opts["password"]);dsns[purpose]=raw
    return Config(host,db,sha,marker,dsns)

def verify_catalog(cur,*,purpose,config):
    _,user,role=PURPOSES[purpose]
    cur.execute("""SELECT current_database(),session_user,current_user,
      current_setting('server_version_num')::int/10000,
      current_setting('transaction_read_only'),
      (SELECT ssl AND version IN ('TLSv1.2','TLSv1.3') FROM pg_stat_ssl WHERE pid=pg_backend_pid())""")
    need(cur.fetchone()==(config.database,user,user,17,"on",True),"HOSTED_QA_DB_TLS")
    _verify_role_catalog(cur,purpose=purpose,config=config)

def _verify_role_catalog(cur,*,purpose,config):
    # Catalog checks are factored for actual isolated PG tests. Only the
    # public verify_catalog path includes the mandatory connection/TLS gate.
    _,user,role=PURPOSES[purpose]
    cur.execute("""SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,
      rolreplication,rolinherit FROM pg_roles WHERE rolname=session_user""")
    need(cur.fetchone()==(True,False,False,False,False,False,False),"HOSTED_QA_LOGIN_ROLE")
    cur.execute("""SELECT rolcanlogin,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
      FROM pg_roles WHERE rolname=%s""",(role,))
    need(cur.fetchone()==(False,False,False,False,False,False),"HOSTED_QA_DELEGATED_ROLE")
    cur.execute("""SELECT rolname FROM pg_roles WHERE rolname<>session_user
      AND pg_has_role(session_user,oid,'MEMBER') ORDER BY 1""")
    need(cur.fetchall()==[(role,)],"HOSTED_QA_ROLE_MEMBERSHIP")
    cur.execute("SELECT pg_has_role(session_user,%s,'SET'),pg_has_role(session_user,%s,'USAGE')",(role,role))
    need(cur.fetchone()==(True,False),"HOSTED_QA_ROLE_DELEGATION")
    # Check effective access as both login and delegated role; no direct
    # table-level or column-level grants on the selected sensitive relations.
    for relation in PROTECTED:
        schema,table=relation.split(".")
        # Catalog OIDs avoid requiring schema USAGE merely to prove its absence.
        cur.execute("""SELECT c.relrowsecurity,c.relforcerowsecurity FROM pg_class c
          JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s AND c.relkind='r'""",(schema,table))
        need(cur.fetchone()==(True,True),"HOSTED_QA_RLS")
        for principal in (user,role):
            cur.execute("""SELECT has_table_privilege(%s,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'),
              has_any_column_privilege(%s,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=%s AND c.relname=%s AND c.relkind='r'""",(principal,principal,schema,table))
            need(cur.fetchone()==(False,False),"HOSTED_QA_DIRECT_GRANT")
    # Marker must be owner-provisioned on the dedicated DB, not writable by
    # any runtime role. Its existence is NOT a proof of safe schema migration.
    cur.execute("""SELECT c.relowner::regrole::text,r.rolcanlogin
      FROM pg_class c JOIN pg_roles r ON r.oid=c.relowner
      WHERE c.oid=to_regclass('naruv_hosted_qa.boundary') AND c.relkind='r'""")
    need(cur.fetchone()==("naruv_qa_boundary_owner",False),"HOSTED_QA_BOUNDARY_OWNER")
    for principal in (user,role):
        cur.execute("""SELECT has_table_privilege(%s,'naruv_hosted_qa.boundary','INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'),
          has_any_column_privilege(%s,'naruv_hosted_qa.boundary','INSERT,UPDATE,REFERENCES'),
          has_schema_privilege(%s,'naruv_hosted_qa','CREATE'),
          has_database_privilege(%s,current_database(),'CREATE')""",(principal,principal,principal,principal))
        need(cur.fetchone()==(False,False,False,False),"HOSTED_QA_BOUNDARY_WRITABLE")
    cur.execute("SELECT marker,source_sha FROM naruv_hosted_qa.boundary LIMIT 2")
    need(cur.fetchall()==[(config.marker,config.source_sha)],"HOSTED_QA_BOUNDARY_MISMATCH")

def run(env=None):
    # Actual connection must use the same process environment that was checked.
    need(env is None,"HOSTED_QA_ENV_OVERRIDE")
    config=parse_config(os.environ)
    for purpose,dsn in config.dsns.items():
        try:
            with psycopg.connect(dsn,connect_timeout=5,sslmode="verify-full",
                                  sslrootcert="system",gssencmode="disable") as db:
                with db.transaction(),db.cursor() as cur:
                    cur.execute("SET TRANSACTION READ ONLY")
                    cur.execute("SET LOCAL statement_timeout='5s'")
                    cur.execute("SET LOCAL lock_timeout='2s'")
                    verify_catalog(cur,purpose=purpose,config=config)
        except psycopg.Error:
            raise AdmissionBlocked("HOSTED_QA_CONNECTION_OR_CATALOG") from None
    return {"status":"READ_ONLY_ADMISSION_PROBE_PASS","credentials_checked":3,
            "source_sha":config.source_sha,"deployment_authorized":False,
            "production_authorized":False}

if __name__=="__main__":
    import json
    try:print(json.dumps(run(),sort_keys=True))
    except AdmissionBlocked as exc:raise SystemExit(str(exc)) from None
