"""J5 V18.1 synthetic *scale-equivalent* 43 table, 62 policy PG17 restore.

ONLY an unshared freshly provisioned local 127.0.0.1 PG17 GitHub Action.
This deliberately is NOT a dump of the user's 43 real Supabase DEV tables.
RTO/RPO of any hosted or production workload remain NOT MEASURED.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo

from scripts.ci_j6_postgres_restore import run_docker,validate_container_id,IMAGE

SCHEMA="jw_ci_v181"
ROLE="jw_ci_v181_reader"
N_TABLES=43
N_POLICIES=62
N_TRIGGERS=43


def guard(dsn: str) -> None:
    if (os.getenv("JW_ENV")!="review" or
        os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"):
        raise RuntimeError("BLOCKED_V181_NOT_EPHEMERAL_CI")
    d=conninfo_to_dict(dsn)
    if (d.get("host"),d.get("dbname"),d.get("user"),d.get("port","5432"))!=(
        "127.0.0.1","postgres","postgres","5432"):
        raise RuntimeError("BLOCKED_V181_FOREIGN_DATABASE")
    with psycopg.connect(dsn) as conn:
        if int(conn.execute("SHOW server_version_num").fetchone()[0])//10000!=17:
            raise RuntimeError("BLOCKED_V181_NOT_PG17")
        if conn.execute("""SELECT count(*) FROM pg_database
                        WHERE NOT datistemplate AND datname<>'postgres'""").fetchone()!=(0,):
            raise RuntimeError("BLOCKED_V181_OTHER_DATABASE_PRESENT")
        if conn.execute("""SELECT count(*) FROM pg_roles WHERE
              rolname<>'postgres' AND rolname !~ '^pg_'""").fetchone()!=(0,):
            raise RuntimeError("BLOCKED_V181_FOREIGN_PRINCIPAL_PRESENT")
        if conn.execute("""SELECT count(*) FROM pg_namespace
              WHERE nspname NOT IN ('pg_catalog','information_schema','public')
              AND nspname NOT LIKE 'pg_%'""").fetchone()!=(0,):
            raise RuntimeError("BLOCKED_V181_FOREIGN_SCHEMA_PRESENT")


def create_test_schema(dsn: str):
    with psycopg.connect(dsn,autocommit=True) as c:
        c.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOBYPASSRLS").format(
            sql.Identifier(ROLE)))
        c.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(SCHEMA)))
        c.execute(sql.SQL("CREATE FUNCTION {}.reject_mutation() RETURNS trigger "
             "LANGUAGE plpgsql SET search_path=pg_catalog AS "
             "$$BEGIN RAISE EXCEPTION 'IMMUTABLE' USING ERRCODE='42501'; END$$").format(
             sql.Identifier(SCHEMA)))
        c.execute(sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
             sql.Identifier(SCHEMA),sql.Identifier(ROLE)))
        for i in range(N_TABLES):
            t="tenant_ledger_"+str(i).zfill(2)
            identifier=sql.SQL("{}.{}").format(sql.Identifier(SCHEMA),sql.Identifier(t))
            c.execute(sql.SQL("CREATE TABLE {} (id text PRIMARY KEY,"
              "org_id text NOT NULL,value bigint NOT NULL CHECK (value>=0),"
              "proof_hash text NOT NULL)").format(identifier))
            c.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(identifier))
            c.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(identifier))
            c.execute(sql.SQL("GRANT SELECT ON {} TO {}").format(
              identifier,sql.Identifier(ROLE)))
            c.execute(sql.SQL("CREATE POLICY {} ON {} FOR SELECT TO {} "
                 "USING (org_id = current_setting('jw.test_org',true))").format(
                 sql.Identifier("v181_read_"+str(i).zfill(2)),identifier,sql.Identifier(ROLE)))
            if i<19:
                c.execute(sql.SQL("GRANT INSERT ON {} TO {}").format(
                    identifier,sql.Identifier(ROLE)))
                c.execute(sql.SQL("CREATE POLICY {} ON {} FOR INSERT TO {} "
                    "WITH CHECK (org_id = current_setting('jw.test_org',true))").format(
                    sql.Identifier("v181_insert_"+str(i).zfill(2)),
                    identifier,sql.Identifier(ROLE)))
            c.execute(sql.SQL("CREATE TRIGGER {} BEFORE UPDATE OR DELETE ON {} "
                   "FOR EACH ROW EXECUTE FUNCTION {}.reject_mutation()").format(
                   sql.Identifier("v181_immutable_"+str(i).zfill(2)),
                   identifier,sql.Identifier(SCHEMA)))
            for org in ("tenant-a","tenant-b"):
                idval=t+"-"+org
                c.execute(sql.SQL("INSERT INTO {} (id,org_id,value,proof_hash) "
                     "VALUES (%s,%s,%s,%s)").format(identifier),(
                    idval,org,i*100,hashlib.sha256(idval.encode()).hexdigest()))
    print("PASS_V181_43_SYNTHETIC_FORCE_RLS_TABLES_SEEDED",flush=True)


def fingerprint(dsn: str):
    result={}
    with psycopg.connect(dsn) as conn:
        cur=conn.cursor()
        cur.execute("""SELECT tablename,policyname,cmd,roles::text,qual,with_check
             FROM pg_policies WHERE schemaname=%s
             ORDER BY tablename,policyname""",(SCHEMA,))
        policies=cur.fetchall()
        if len(policies)!=N_POLICIES:
            raise AssertionError(f"V181 policy count {len(policies)}")
        cur.execute("""SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=%s AND c.relkind='r'
              ORDER BY c.relname""",(SCHEMA,))
        tables=cur.fetchall()
        if len(tables)!=N_TABLES or any(not row[1] or not row[2] for row in tables):
            raise AssertionError("V181 FORCE RLS schema incomplete")
        cur.execute("""SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid)
              FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
              JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname=%s AND NOT t.tgisinternal
              ORDER BY c.relname,t.tgname""",(SCHEMA,))
        triggers=cur.fetchall()
        if len(triggers)!=N_TRIGGERS:
            raise AssertionError("V181 mutation guards missing")
        def digest(rows):
            return hashlib.sha256(json.dumps(rows,sort_keys=True,
                separators=(",",":"),default=str).encode()).hexdigest()
        result["policy"]=(len(policies),digest(policies))
        result["forced_rls"]=(len(tables),digest(tables))
        result["triggers"]=(len(triggers),digest(triggers))
        for table,_,_ in tables:
            cur.execute(sql.SQL("SELECT id,org_id,value,proof_hash FROM {}.{} "
                 "ORDER BY id").format(sql.Identifier(SCHEMA),sql.Identifier(table)))
            rows=cur.fetchall()
            if len(rows)!=2 or {r[1] for r in rows}!={"tenant-a","tenant-b"}:
                raise AssertionError("V181 row missing or duplicate")
            result[table]=(2,digest(rows))
    return result


def deny_foreign_read_and_write(dsn: str):
    # PostgreSQL SUPERUSER can SET ROLE for the isolated READ and 19 INSERT
    # policies; no customer identities nor credentials are involved.
    with psycopg.connect(dsn,autocommit=True) as conn:
        with conn.transaction():
            conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(ROLE)))
            conn.execute("SELECT set_config('jw.test_org','tenant-a',true)")
            for i in range(N_TABLES):
                t="tenant_ledger_"+str(i).zfill(2)
                sel=sql.SQL("SELECT count(*) FROM {}.{}").format(
                    sql.Identifier(SCHEMA),sql.Identifier(t))
                if conn.execute(sel).fetchone()!=(1,):
                    raise AssertionError("V181 tenant A visibility")
            # To keep the whole test atomic, each deliberately rejected write
            # occurs in a SAVEPOINT; the final transaction is always rolled back.
            for i in range(19):
                t="tenant_ledger_"+str(i).zfill(2)
                stmt=sql.SQL("INSERT INTO {}.{} (id,org_id,value,proof_hash)"
                    " VALUES (%s,'tenant-b',1,'forged')").format(
                    sql.Identifier(SCHEMA),sql.Identifier(t))
                try:
                    with conn.transaction():
                        conn.execute(stmt,("attacker-"+str(i),))
                except psycopg.errors.InsufficientPrivilege:
                    pass
                else:
                    raise AssertionError("V181 forged company insert allowed")
            conn.execute("SELECT set_config('jw.test_org','unknown',true)")
            for i in range(N_TABLES):
                t="tenant_ledger_"+str(i).zfill(2)
                stmt=sql.SQL("SELECT count(*) FROM {}.{}").format(
                    sql.Identifier(SCHEMA),sql.Identifier(t))
                if conn.execute(stmt).fetchone()!=(0,):
                    raise AssertionError("V181 unauthenticated foreign visibility")
            # Only read queries and rejected INSERTS were attempted.
            # Each rejected INSERT was rolled back to its own SAVEPOINT.
    print("PASS_V181_19_INSERT_DENIALS_43_TENANT_READ_BARRIERS",flush=True)


def run():
    dsn=os.getenv("JW_PG_CI_ROOT_DSN","")
    guard(dsn)
    opts=conninfo_to_dict(dsn)
    env=os.environ.copy()
    env["PGPASSWORD"]=opts["password"]
    cid=validate_container_id(run_docker(
        "ps","--filter","ancestor=postgres:17","--format","{{.ID}}",timeout=10))
    if run_docker("inspect","--format","{{.Config.Image}}",cid,timeout=10)!=IMAGE:
        raise RuntimeError("BLOCKED_V181_UNEXPECTED_CONTAINER_IMAGE")
    backup_name="jw_v181_"+secrets.token_hex(5)
    backup="/tmp/"+backup_name+".dump"
    created=False
    source_created=False
    baseline=None
    t0=time.monotonic()
    try:
        source_created=True
        create_test_schema(dsn)
        deny_foreign_read_and_write(dsn)
        baseline=fingerprint(dsn)
        run_docker("exec","-e","PGPASSWORD",cid,
          "pg_dump","-U","postgres","-h","127.0.0.1","-d","postgres",
          "--schema="+SCHEMA,"--format=custom","--file",backup,
          timeout=55,env=env)
        run_docker("exec","-e","PGPASSWORD",cid,
          "createdb","-U","postgres","-h","127.0.0.1",backup_name,
          timeout=15,env=env)
        created=True
        run_docker("exec","-e","PGPASSWORD",cid,
          "pg_restore","-U","postgres","-h","127.0.0.1",
          "-d",backup_name,"--no-owner","--exit-on-error",backup,
          timeout=55,env=env)
        restored=fingerprint(make_conninfo(dsn,dbname=backup_name))
        if restored!=baseline:
            raise AssertionError("V181 43-table 62-policy 43-trigger row/schema mismatch")
        if fingerprint(dsn)!=baseline:
            raise AssertionError("V181 source mutated after dump and restore")
        elapsed=round(time.monotonic()-t0,3)
        print("PASS_V181_43_TABLE_62_POLICY_43_TRIGGER_86_ROW_PG17_BACKUP_RESTORE_EXACT",flush=True)
        print(f"MEASURED_V181_SYNTHETIC_RESTORE_VERIFY_SECONDS={elapsed}",flush=True)
        print("LIMIT_V181_REAL_DEV_43_TABLE_CONTENT_NOT_BACKED_UP_OR_RESTORED",flush=True)
        print("LIMIT_V181_PRODUCTION_RTO_RPO_NOT_MEASURED",flush=True)
    finally:
        errors=[]
        if created:
            try:run_docker("exec","-e","PGPASSWORD",cid,"dropdb","--if-exists",
                   "-U","postgres","-h","127.0.0.1",backup_name,
                   timeout=15,env=env)
            except Exception:errors.append("drop_restore")
        try:run_docker("exec",cid,"rm","-f",backup,timeout=12)
        except Exception:errors.append("drop_archive")
        if source_created:
            try:
                with psycopg.connect(dsn,autocommit=True) as c:
                    c.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(SCHEMA)))
                    c.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(ROLE)))
            except Exception:errors.append("drop_synthetic_source")
        if errors:raise RuntimeError("V181 EPHEMERAL cleanup failed: "+",".join(errors))
        print("PASS_V181_SYNTHETIC_DATABASE_AND_ARCHIVE_CLEANUP",flush=True)


if __name__=="__main__":
    run()
