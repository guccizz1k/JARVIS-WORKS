"""Current scoped PG17 authorization evidence; SELECT only, no restoration or grants.

This supplements (does not change) the backup and role proof engines. A current
snapshot cannot establish historical privileges at archive creation. No passwords,
role settings, row data, or arbitrary SQL are read. Scope: jw_dev and named roles.
"""
import os, sys, re, json
from urllib.parse import urlsplit,parse_qsl
from scripts import pg_backup_v223 as backup
from scripts import jw_role_proof_v223 as role

SCHEMA = "jw_dev"
SCOPE = ("jw_app_dev","jw_auth_stage_v85")
ACK = "OWNER_APPROVES_CURRENT_DEV_ROLE_METADATA_READ_ONLY"
MAX_OBJECTS = 20000
# Explicit privileges, including NULL/default distinction, grantor, grantee,
# grant option, and ownership. No OID is retained in the evidence.
OBJECT_SQL = """
WITH objects AS (
 SELECT 'schema'::text kind, n.nspname::text object_name,''::text sub_name,
 n.nspowner owner_oid,n.nspacl acl
 FROM pg_catalog.pg_namespace n WHERE n.nspname=%s
 UNION ALL
 SELECT 'relation:'||c.relkind,c.relname::text,'',c.relowner,c.relacl
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','S','f')
 UNION ALL
 SELECT 'column',c.relname::text,a.attname::text,c.relowner,a.attacl
 FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=%s AND c.relkind IN ('r','p','v','m','f') AND a.attnum>0 AND NOT a.attisdropped
 UNION ALL
 SELECT 'routine:'||p.prokind,p.proname::text,pg_catalog.pg_get_function_identity_arguments(p.oid),p.proowner,p.proacl
 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname=%s
 UNION ALL
 SELECT 'type:'||t.typtype,t.typname::text,'',t.typowner,t.typacl
 FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid=t.typnamespace
 WHERE n.nspname=%s
)
SELECT o.kind,o.object_name,o.sub_name,r.rolname::text,o.acl IS NULL,
 coalesce((SELECT jsonb_agg(jsonb_build_array(g.rolname::text,
 CASE WHEN a.grantee=0 THEN NULL ELSE m.rolname::text END,
 a.privilege_type,a.is_grantable) ORDER BY g.rolname COLLATE "C",
 (m.rolname::text) COLLATE "C",a.privilege_type COLLATE "C",a.is_grantable)
 FROM pg_catalog.aclexplode(o.acl) a
 LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor
 LEFT JOIN pg_catalog.pg_roles m ON m.oid=a.grantee),'[]'::jsonb)
FROM objects o LEFT JOIN pg_catalog.pg_roles r ON r.oid=o.owner_oid
LIMIT 20001
"""
DEFAULT_SQL = """
SELECT r.rolname::text,coalesce(n.nspname::text,''),d.defaclobjtype::text,
 coalesce((SELECT jsonb_agg(jsonb_build_array(g.rolname::text,
 CASE WHEN a.grantee=0 THEN NULL ELSE m.rolname::text END,
 a.privilege_type,a.is_grantable) ORDER BY g.rolname COLLATE "C",
 (m.rolname::text) COLLATE "C",a.privilege_type COLLATE "C",a.is_grantable)
 FROM pg_catalog.aclexplode(d.defaclacl) a
 LEFT JOIN pg_catalog.pg_roles g ON g.oid=a.grantor
 LEFT JOIN pg_catalog.pg_roles m ON m.oid=a.grantee),'[]'::jsonb)
FROM pg_catalog.pg_default_acl d JOIN pg_catalog.pg_roles r ON r.oid=d.defaclrole
LEFT JOIN pg_catalog.pg_namespace n ON n.oid=d.defaclnamespace
WHERE n.nspname=%s OR (d.defaclnamespace=0 AND r.rolname=ANY(%s::text[]))
LIMIT 20001
"""
def need(ok, code):
    role.need(ok, code)

def acl_entries(value):
    need(type(value) is list and len(value)<=4096,"ACL_FORMAT")
    for e in value:
        need(type(e) is list and len(e)==4 and role.role_name(e[0]) and
             (e[1] is None or role.role_name(e[1])) and type(e[2]) is str and
             re.fullmatch(r"[A-Z_]{1,32}",e[2]) and type(e[3]) is bool,"ACL_FORMAT")
    canon=sorted(value,key=role.canonical)
    need(len({role.canonical(e) for e in canon})==len(canon),"ACL_DUPLICATE")
    return canon

def object_rows(rows):
    need(0<len(rows)<=MAX_OBJECTS,"OBJECT_BUDGET_OR_EMPTY")
    out=[]
    for row in rows:
        need(len(row)==6 and all(type(x) is str and len(x)<=8192 for x in row[:3]) and
             role.role_name(row[3]) and type(row[4]) is bool,"OBJECT_FORMAT")
        a=acl_entries(row[5])
        need(not row[4] or not a,"NULL_ACL_CONTRADICTION")
        out.append([*row[:5],a])
    need(len({tuple(r[:3]) for r in out})==len(out),"DUPLICATE_OBJECT")
    need(sum(r[0]=="schema" and r[1]==SCHEMA for r in out)==1,"SCHEMA_MISSING")
    return sorted(out,key=role.canonical)

def default_rows(rows):
    need(len(rows)<=MAX_OBJECTS,"DEFAULT_BUDGET")
    out=[]
    for r in rows:
        need(len(r)==4 and role.role_name(r[0]) and r[1] in ("",SCHEMA) and
             type(r[2]) is str and len(r[2])==1,"DEFAULT_FORMAT")
        out.append([*r[:3],acl_entries(r[3])])
    need(len({tuple(r[:3]) for r in out})==len(out),"DUPLICATE_DEFAULT")
    return sorted(out,key=role.canonical)

def names(objects,defaults=()):
    scope=set(SCOPE)
    for r in objects:
        scope.add(r[3])
        for a in r[5]: scope.update(x for x in a[:2] if x is not None)
    for r in defaults:
        scope.add(r[0])
        for a in r[3]: scope.update(x for x in a[:2] if x is not None)
    need(len(scope)<=64,"ROLE_SCOPE_BUDGET")
    return sorted(scope)

def collect(conn, *, identity_check):
    """One consistent transaction. identity_check must raise if not authorized."""
    need(conn.autocommit is True and conn.info.transaction_status==0,"IDLE_CONNECTION_REQUIRED")
    with conn.cursor() as cur:
        cur.execute("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY")
        try:
            cur.execute("SET LOCAL statement_timeout='15s'")
            cur.execute("SET LOCAL search_path=pg_catalog")
            cur.execute("SELECT current_setting('server_version_num')::int,current_setting('transaction_read_only')")
            v,ro=cur.fetchone()
            need(type(v) is int and 170000<=v<180000 and ro=="on","PG17_READONLY_REQUIRED")
            identity_check(conn)
            cur.execute(OBJECT_SQL,(SCHEMA,)*5)
            objects=object_rows(cur.fetchall())
            cur.execute(role.ROLE_SQL); roles=cur.fetchall()
            cur.execute(role.EDGE_SQL); edges=cur.fetchall()
            # Expand global default ACL scope to membership-connected roles; stop
            # rather than silently ignore a role discovered by another ACL.
            scope=names(objects)
            for _ in range(65):
                g=role.graph(roles,edges,scope)
                selected=sorted(r[0] for r in g["roles"])
                need(len(selected)<=64,"ROLE_SCOPE_BUDGET")
                cur.execute(DEFAULT_SQL,(SCHEMA,selected))
                defaults=default_rows(cur.fetchall())
                new=sorted(set(scope)|set(names(objects,defaults)))
                if new==scope: break
                scope=new
            else: raise role.Blocked("DEFAULT_SCOPE_NOT_STABLE")
            result={"schema":"jw-current-authz-v1","scope":SCHEMA,"role_graph":g,
                    "objects":objects,"default_acl":defaults}
        finally:
            cur.execute("ROLLBACK")
    need(conn.info.transaction_status==0,"ROLLBACK_NOT_IDLE")
    return result

def summary(doc):
    need(type(doc) is dict and set(doc)=={"schema","scope","role_graph","objects","default_acl"} and
         doc["schema"]=="jw-current-authz-v1" and doc["scope"]==SCHEMA,"DOC_FORMAT")
    role.verify_snapshot(doc["role_graph"])
    need(object_rows(doc["objects"])==doc["objects"] and default_rows(doc["default_acl"])==doc["default_acl"],"DOC_NOT_CANONICAL")
    need(set(names(doc["objects"],doc["default_acl"]))<=set(doc["role_graph"]["scope"]),"ROLE_SCOPE_INCOMPLETE")
    return {"snapshot_sha256":role.digest(doc),"role_graph_sha256":role.digest(doc["role_graph"]),
            "owner_sha256":role.digest([r[:4] for r in doc["objects"]]),
            "object_acl_sha256":role.digest([[*r[:3],*r[4:]] for r in doc["objects"]]),
            "default_acl_sha256":role.digest(doc["default_acl"]),
            "objects":len(doc["objects"]),"roles":len(doc["role_graph"]["roles"]),
            "memberships":len(doc["role_graph"]["memberships"]),"defaults":len(doc["default_acl"])}

def compare(source,target,pin):
    a,b=summary(source),summary(target)
    need(type(pin) is str and role.SHA.fullmatch(pin) and a["snapshot_sha256"]==pin,"SOURCE_PIN_MISMATCH")
    fields=("role_graph_sha256","owner_sha256","object_acl_sha256","default_acl_sha256")
    equal={k:a[k]==b[k] for k in fields}
    return {"current_scoped_metadata":"PASS" if all(equal.values()) else "FAIL",
            "equal":equal,"effective_rls":"NOT_RUN","role_settings":"NOT_ATTESTED",
            "historical_source":"NOT_ATTESTED","independent_custody":"NOT_ATTESTED",
            "overall":"BLOCKED","activation_allowed":False}

def source_options(dsn,expected):
    # Reject query override/duplicate keys rather than allow libpq to override
    # the host/user checked by the original URL parser.
    q=parse_qsl(urlsplit(dsn).query,keep_blank_values=True,strict_parsing=True)
    need(len(q)==2 and {k for k,v in q}=={"sslmode","sslrootcert"},"DSN_OPTIONS_DENIED")
    opt=backup.guard_source(dsn)
    need(all(expected.get(k) for k in backup.IDENTITY_ENV),"SOURCE_EXPECTATIONS_MISSING")
    need(opt["host"]==expected["host"].lower() and opt["port"]==expected["port"] and
         opt["dbname"]==expected["dbname"] and backup.project_ref_from_dsn(opt)==expected["project_ref"] and
         backup.dsn_role(opt)==expected["role"],"SOURCE_ENDPOINT_MISMATCH")
    return opt

def capture_current_source(environ):
    need(environ.get("JW_PG_CURRENT_ROLE_ACK")==ACK,"OWNER_READONLY_ACK_REQUIRED")
    expected=backup.read_identity_expectations(environ)
    opt=source_options(environ.get("JW_PG_SOURCE_DSN",""),expected)
    import psycopg
    # No inherited libpq service/options/hostaddr overrides.
    need(not any(k.startswith("PG") for k in os.environ),"LIBPQ_ENV_MUST_BE_ISOLATED")
    with psycopg.connect(host=opt["host"],port=opt["port"],dbname=opt["dbname"],
            user=opt["user"],password=opt["password"],sslmode="verify-full",
            sslrootcert=opt["sslrootcert"],connect_timeout=10,autocommit=True,
            options="-c default_transaction_read_only=on -c statement_timeout=15000") as conn:
        def check(c):
            need(backup.identity_verified(backup.check_source_identity(opt,backup.fetch_live_identity(c,SCHEMA),expected)),"SOURCE_IDENTITY_FAILED")
            need(not backup.evaluate_source_privileges(backup.fetch_role_facts(c,SCHEMA)),"SOURCE_LEAST_PRIVILEGE_FAILED")
        return collect(conn,identity_check=check)

def main():
    # Digest-only output. A later owner-controlled comparison needs a separately
    # approved/pinned reference; no private role names or ACL content leave here.
    if sys.argv[1:]!=["capture-current-source"]: return 2
    try:
        s=summary(capture_current_source(os.environ))
        print(json.dumps({"current_source_metadata":"PASS","summary":s,"historic_source":"NOT_ATTESTED","overall":"BLOCKED","activation_allowed":False},sort_keys=True))
        return 0
    except Exception as exc:
        code=str(exc) if isinstance(exc,role.Blocked) and re.fullmatch(r"[A-Z0-9_]{1,100}",str(exc)) else type(exc).__name__
        print("BLOCKED_CURRENT_SOURCE:"+code,file=sys.stderr)
        return 1

if __name__=="__main__": sys.exit(main())
