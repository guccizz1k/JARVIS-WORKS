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

def acl_preflight(c):
    # unnest emits no rows for NULL/empty arrays, never passes a zero-dimensional
    # array to aclexplode. Exercise the exact expression on actual PG17.
    rows=c.execute("""SELECT tag,ARRAY(SELECT x.privilege_type
      FROM unnest(v) AS item(acl) CROSS JOIN LATERAL aclexplode(ARRAY[item.acl]) x ORDER BY 1)
      FROM (VALUES ('null',NULL::aclitem[]),('empty','{}'::aclitem[]),
      ('grant',ARRAY['postgres=r/postgres'::aclitem]),('grant_option',ARRAY['postgres=r*/postgres'::aclitem])) q(tag,v)
      ORDER BY tag""").fetchall()
    need(rows==[('empty',[]),('grant',['SELECT']),('grant_option',['SELECT']),('null',[])],"ERP_RESTORE_ACL_PREFLIGHT")
    proof=c.execute("""SELECT x.is_grantable FROM unnest(ARRAY['postgres=r*/postgres'::aclitem]) AS item(acl)
      CROSS JOIN LATERAL aclexplode(ARRAY[item.acl]) x""").fetchall()
    need(proof==[(True,)],"ERP_RESTORE_ACL_GRANT_OPTION")

def snapshot(c):
    # All application tables, row multisets, schema owners, ACLs, RLS policies,
    # constraints, and function definitions. No data or credentials in logs.
    tables=c.execute("""SELECT n.nspname,t.relname,t.relrowsecurity,t.relforcerowsecurity,
      pg_get_userbyid(t.relowner),ARRAY(SELECT jsonb_build_array(pg_get_userbyid(x.grantor),CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable)::text FROM unnest(coalesce(t.relacl,acldefault('r',t.relowner))) AS item(acl) CROSS JOIN LATERAL aclexplode(ARRAY[item.acl]) x ORDER BY 1)
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
      pg_get_userbyid(p.proowner),ARRAY(SELECT jsonb_build_array(pg_get_userbyid(x.grantor),CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable)::text FROM unnest(coalesce(p.proacl,acldefault('f',p.proowner))) AS item(acl) CROSS JOIN LATERAL aclexplode(ARRAY[item.acl]) x ORDER BY 1)
      FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
      WHERE p.prokind IN ('f','p') AND (n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%') ORDER BY 1,2,3""").fetchall()
    triggers=c.execute("""SELECT n.nspname,t.relname,g.tgname,g.tgenabled,pg_get_triggerdef(g.oid)
      FROM pg_trigger g JOIN pg_class t ON t.oid=g.tgrelid JOIN pg_namespace n ON n.oid=t.relnamespace
      WHERE NOT g.tgisinternal AND (n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%') ORDER BY 1,2,3""").fetchall()
    indexes=c.execute("""SELECT schemaname,tablename,indexname,indexdef FROM pg_indexes
      WHERE schemaname='jw_dev' OR schemaname LIKE 'naruv_%' ORDER BY 1,2,3""").fetchall()
    columns=c.execute("""SELECT n.nspname,t.relname,a.attnum,a.attname,format_type(a.atttypid,a.atttypmod),
      a.attnotnull,a.attidentity,a.attgenerated,coalesce(pg_get_expr(d.adbin,d.adrelid),''),
      ARRAY(SELECT jsonb_build_array(pg_get_userbyid(x.grantor),CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable)::text
       FROM unnest(coalesce(a.attacl,'{}'::aclitem[])) AS item(acl) CROSS JOIN LATERAL aclexplode(ARRAY[item.acl]) x ORDER BY 1)
      FROM pg_attribute a JOIN pg_class t ON t.oid=a.attrelid JOIN pg_namespace n ON n.oid=t.relnamespace
      LEFT JOIN pg_attrdef d ON (d.adrelid,d.adnum)=(a.attrelid,a.attnum)
      WHERE a.attnum>0 AND NOT a.attisdropped AND t.relkind IN ('r','p') AND (n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%')
      ORDER BY 1,2,3""").fetchall()
    schemas=c.execute("""SELECT n.nspname,pg_get_userbyid(n.nspowner),ARRAY(SELECT jsonb_build_array(pg_get_userbyid(x.grantor),CASE WHEN x.grantee=0 THEN 'PUBLIC' ELSE pg_get_userbyid(x.grantee) END,x.privilege_type,x.is_grantable)::text FROM unnest(coalesce(n.nspacl,acldefault('n',n.nspowner))) AS item(acl) CROSS JOIN LATERAL aclexplode(ARRAY[item.acl]) x ORDER BY 1)
      FROM pg_namespace n WHERE n.nspname='jw_dev' OR n.nspname LIKE 'naruv_%' ORDER BY 1""").fetchall()
    return (tables,rows,policies,constraints,functions,triggers,indexes,columns,schemas)

def compare_snapshots(expected,actual):
    # Diagnose mismatches by section, public fixture object name and field index;
    # never emit data, ACL values, session hashes, or function bodies.
    for section,left,right in zip(("TABLES","ROWS","POLICIES","CONSTRAINTS","FUNCTIONS","TRIGGERS","INDEXES","COLUMNS","SCHEMAS"),expected,actual,strict=True):
        if left==right:continue
        for x,y in zip(left,right):
            if x!=y:
                fields=[i for i,(a,b) in enumerate(zip(x,y,strict=True)) if a!=b]
                raise RuntimeError("ERP_RESTORE_MISMATCH_"+section+" object="+str(x[0])+"."+str(x[1] if section!="SCHEMAS" else "")+" fields="+str(fields))
        raise RuntimeError("ERP_RESTORE_MISMATCH_"+section+" row_count="+str(len(left))+"/"+str(len(right)))

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
        acl_preflight(a);acl_preflight(b)
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
        compare_snapshots(before,snapshot(a))
        after=snapshot(b)
        compare_snapshots(before,after)
        # Negative proof: a newly granted privilege must invalidate the exact snapshot.
        with b.transaction():
            b.execute("SAVEPOINT acl_negative")
            b.execute("GRANT SELECT ON naruv_valuation.entries TO jw_app_dev")
            try:
                compare_snapshots(before,snapshot(b))
            except RuntimeError as exc:
                need(str(exc).startswith("ERP_RESTORE_MISMATCH_TABLES"),"ERP_RESTORE_ACL_NEGATIVE_WRONG_REASON")
            else:raise RuntimeError("ERP_RESTORE_ACL_NEGATIVE_ACCEPTED")
            b.execute("ROLLBACK TO SAVEPOINT acl_negative")
            compare_snapshots(before,snapshot(b))
            # A column-only grant must be detected separately from table grants.
            b.execute("SAVEPOINT column_negative")
            b.execute("GRANT SELECT (movement_id) ON naruv_valuation.entries TO jw_app_dev")
            try:
                compare_snapshots(before,snapshot(b))
            except RuntimeError as exc:
                need(str(exc).startswith("ERP_RESTORE_MISMATCH_COLUMNS"),"ERP_RESTORE_COLUMN_NEGATIVE_WRONG_REASON")
            else:raise RuntimeError("ERP_RESTORE_COLUMN_NEGATIVE_ACCEPTED")
            b.execute("ROLLBACK TO SAVEPOINT column_negative")
            compare_snapshots(before,snapshot(b))
        # Verify the restored role boundary even without enabling login.
        with b.cursor() as cur:
            for role in ("jw_app_dev","naruv_native_stage"):
                cur.execute("SELECT has_table_privilege(%s,'naruv_valuation.entries','SELECT'),has_table_privilege(%s,'naruv_finance.events','INSERT')",(role,role))
                need(cur.fetchone()==(False,False),"ERP_RESTORE_DIRECT_ACCESS")
        need(b.execute("SELECT count(*) FROM pg_authid WHERE rolname<>'postgres' AND rolname NOT LIKE 'pg_%' AND (rolcanlogin OR rolpassword IS NOT NULL OR rolsuper OR rolbypassrls)").fetchone()[0]==0,"ERP_RESTORE_LOGIN_EXPOSURE")
    print("NARUV_ERP_INDEPENDENT_RESTORE_PASS", "tables="+str(len(before[0])), "archive_sha256="+digest, "login_disabled=true")
    return {"tables":len(before[0]),"distinct_clusters":True}
