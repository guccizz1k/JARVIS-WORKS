"""Full synthetic ERP database archive to a distinct PG17 CI service.

Restore is deliberately offline: login roles are reconstructed NOLOGIN, no
password or source cluster role dump is copied, and no production DSN accepted.
"""
import hashlib
import json
import os
import re
import subprocess
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict

DEST_DSN="postgresql://postgres:naruv-erp-restore-ci-only@127.0.0.1:5433/postgres"
def need(condition,reason):
    if not condition:raise RuntimeError(reason)

def docker_guard(cid,port,password):
    need(re.fullmatch(r"[a-f0-9]{64}",cid or "") is not None,"ERP_RESTORE_SERVICE_ID")
    rows=json.loads(subprocess.run(["docker","inspect",cid],check=True,capture_output=True,text=True,timeout=10).stdout)
    need(len(rows)==1,"ERP_RESTORE_SERVICE_LOOKUP")
    c=rows[0];e=dict(x.split("=",1) for x in c["Config"]["Env"] if "=" in x)
    need(c["Id"]==cid and c["Config"]["Image"]=="postgres:17" and c["State"]["Running"]
        and e.get("POSTGRES_DB")=="postgres" and e.get("POSTGRES_USER")=="postgres" and e.get("POSTGRES_PASSWORD")==password
        and any(x.get("HostPort")==str(port) for x in c["HostConfig"]["PortBindings"].get("5432/tcp",[])),"ERP_RESTORE_WRONG_SERVICE")
    return {x["Source"] for x in c.get("Mounts",[]) if x.get("Source")}

def identity(c):
    db,user,ver,system=c.execute("SELECT current_database(),session_user,current_setting('server_version_num')::int,system_identifier::text FROM pg_control_system()").fetchone()
    need((db,user)==("postgres","postgres") and 170000<=ver<180000,"ERP_RESTORE_DB_ID")
    return system

def snapshot(c):
    # All application tables, row multisets, schema owners, ACLs, RLS policies,
    # constraints, and function definitions. No data or credentials in logs.
    tables=c.execute("""SELECT n.nspname,t.relname,t.relrowsecurity,t.relforcerowsecurity,
      pg_get_userbyid(t.relowner),CASE WHEN t.relacl IS NULL THEN '' ELSE array_to_string(ARRAY(SELECT x::text FROM unnest(t.relacl) x ORDER BY x::text),',') END
      FROM pg_class t JOIN pg_namespace n ON n.oid=t.relnamespace
      WHERE t.relkind IN ('r','p') AND (n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%')
      ORDER BY 1,2""").fetchall()
    rows=[]
    for n,t,*_ in tables:
        query=sql.SQL("SELECT to_jsonb(x)::text FROM {}.{} x ORDER BY (to_jsonb(x)::text) COLLATE \"C\"").format(sql.Identifier(n),sql.Identifier(t))
        h=hashlib.sha256();cnt=0
        for (row,) in c.execute(query):
            data=row.encode();h.update(len(data).to_bytes(8,"big"));h.update(data);cnt+=1
        rows.append((n,t,cnt,h.hexdigest()))
    policies=c.execute("""SELECT schemaname,tablename,policyname,permissive,roles::text,cmd,qual,with_check
      FROM pg_policies WHERE schemaname='jw_dev' OR schemaname LIKE 'naruv_%' ORDER BY 1,2,3""").fetchall()
    constraints=c.execute("""SELECT n.nspname,t.relname,k.conname,pg_get_constraintdef(k.oid)
      FROM pg_constraint k JOIN pg_class t ON t.oid=k.conrelid JOIN pg_namespace n ON n.oid=t.relnamespace
      WHERE n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%' ORDER BY 1,2,3""").fetchall()
    functions=c.execute("""SELECT n.nspname,p.proname,pg_get_function_identity_arguments(p.oid),pg_get_functiondef(p.oid),
      pg_get_userbyid(p.proowner),CASE WHEN p.proacl IS NULL THEN '' ELSE array_to_string(ARRAY(SELECT x::text FROM unnest(p.proacl) x ORDER BY x::text),',') END
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE p.prokind IN ('f','p') AND (n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%') ORDER BY 1,2,3""").fetchall()
    triggers=c.execute("""SELECT n.nspname,t.relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid)
      FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid JOIN pg_namespace n ON n.oid=t.relnamespace
      WHERE NOT g.tgisinternal AND (n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%') ORDER BY 1,2,3""").fetchall()
    indexes=c.execute("""SELECT schemaname,tablename,indexname,indexdef FROM pg_indexes
      WHERE schemaname='jw_dev' OR schemaname LIKE 'naruv_%' ORDER BY 1,2,3""").fetchall()
    return (tables,rows,policies,constraints,functions,triggers,indexes)

def prove_restore(source_dsn):
    need(os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("NARUV_ERP_RESTORE_ALLOW")=="TWO_DISPOSABLE_SERVICES_ONLY"
         and os.environ.get("JW_PG_CI_ALLOW")=="ONLY_EPHEMERAL_LOCAL_DATABASE","ERP_RESTORE_SCOPE")
    source=conninfo_to_dict(source_dsn)
    need(source.get("host")=="127.0.0.1" and source.get("port")=="5432" and source.get("dbname")=="postgres"
         and source.get("user")=="postgres" and source.get("password")=="ci-only-ephemeral-test-password","ERP_RESTORE_SOURCE_DSN")
    src=os.environ.get("NARUV_ERP_SOURCE_SERVICE","");dst=os.environ.get("NARUV_ERP_DEST_SERVICE","")
    need(src!=dst,"ERP_RESTORE_SAME_SERVICE")
    need(not docker_guard(src,5432,"ci-only-ephemeral-test-password").intersection(docker_guard(dst,5433,"naruv-erp-restore-ci-only")),"ERP_RESTORE_SHARED_STORAGE")
    with psycopg.connect(source_dsn) as a,psycopg.connect(DEST_DSN) as b:
        need(identity(a)!=identity(b),"ERP_RESTORE_SAME_CLUSTER")
        need(b.execute("SELECT to_regnamespace('jw_dev') IS NULL AND to_regnamespace('naruv_valuation') IS NULL").fetchone()[0],"ERP_RESTORE_DEST_NOT_EMPTY")
        roles=a.execute("""SELECT rolname,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication
          FROM pg_roles WHERE rolname<>'postgres' AND rolname NOT LIKE 'pg_%' ORDER BY 1""").fetchall()
        for name,*flags in roles:
            need(re.fullmatch(r"(jw_[a-z0-9_]+|naruv_[a-z0-9_]+|anon|authenticated|service_role)",name) is not None and not any(flags),"ERP_RESTORE_UNEXPECTED_ROLE")
            b.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE").format(sql.Identifier(name)))
        b.commit()
        before=snapshot(a);need(len(before[0])>10,"ERP_RESTORE_EMPTY")
        a.rollback()
    archive=subprocess.run(["docker","exec",src,"pg_dump","-U","postgres","-d","postgres","-Fc","--no-password"],capture_output=True,timeout=45)
    need(archive.returncode==0 and 0<len(archive.stdout)<=32*1024*1024,"ERP_RESTORE_DUMP")
    digest=hashlib.sha256(archive.stdout).hexdigest()
    restored=subprocess.run(["docker","exec","-i",dst,"pg_restore","-U","postgres","-d","postgres","--exit-on-error","--single-transaction","--no-password"],input=archive.stdout,capture_output=True,timeout=60)
    need(restored.returncode==0,"ERP_RESTORE_APPLY")
    need(hashlib.sha256(archive.stdout).hexdigest()==digest,"ERP_RESTORE_ARCHIVE_CHANGED")
    with psycopg.connect(source_dsn) as a,psycopg.connect(DEST_DSN) as b:
        need(identity(a)!=identity(b),"ERP_RESTORE_SAME_CLUSTER")
        need(snapshot(a)==before,"ERP_RESTORE_SOURCE_CHANGED")
        need(snapshot(b)==before,"ERP_RESTORE_SCHEMA_DATA_MISMATCH")
        need(b.execute("SELECT count(*) FROM pg_authid WHERE rolname<>'postgres' AND rolname NOT LIKE 'pg_%' AND (rolcanlogin OR rolpassword IS NOT NULL OR rolsuper OR rolbypassrls)").fetchone()[0]==0,"ERP_RESTORE_LOGIN_EXPOSURE")
    print("NARUV_ERP_INDEPENDENT_RESTORE_PASS", "tables="+str(len(before[0])), "archive_sha256="+digest, "login_disabled=true")
    return {"tables":len(before[0]),"distinct_clusters":True}
