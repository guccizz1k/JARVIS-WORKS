"""V18.5 J5 actual 86,000-row PostgreSQL17 disaster-recovery experiment.

ONLY a new, disposable 127.0.0.1 PG17 GitHub Actions database; this neither
touches the 43 real DEV tables nor estimates production RTO/RPO. Reuses
the V18.1 guarded 43-table/62-policy/43-trigger schema and immutable writes.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import secrets
import time

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from scripts import ci_v181_pg17_scaled_restore as original

ROWS_PER_TENANT = 1000
EXPECTED_ROWS = original.N_TABLES * ROWS_PER_TENANT * 2


def populate(dsn: str) -> None:
    with psycopg.connect(dsn) as conn:
        for i in range(original.N_TABLES):
            table=sql.SQL("{}.{}").format(
                sql.Identifier(original.SCHEMA),
                sql.Identifier(f"tenant_ledger_{i:02}"))
            query=sql.SQL("""INSERT INTO {} (id,org_id,value,proof_hash)
                SELECT 'v185-'||lpad(gs::text,4,'0')||'-'||org,org,
                       %s+gs,
                       md5('v185-'||lpad(gs::text,4,'0')||'-'||org)
                FROM generate_series(2,1000) AS gs
                CROSS JOIN (VALUES ('tenant-a'),('tenant-b')) AS tenants(org)""").format(table)
            conn.execute(query,(i*100,))
    print("PASS_V185_GENERATED_86000_SYNTHETIC_ROWS", flush=True)


def signature(dsn: str) -> dict:
    output={}
    with psycopg.connect(dsn) as conn:
        sqls={
            "policies":("""SELECT tablename,policyname,cmd,roles::text,qual,with_check
                           FROM pg_policies WHERE schemaname=%s
                           ORDER BY tablename,policyname""",original.N_POLICIES),
            "tables":("""SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity
                         FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid
                         WHERE n.nspname=%s AND c.relkind='r'
                         ORDER BY c.relname""",original.N_TABLES),
            "triggers":("""SELECT c.relname,t.tgname,pg_get_triggerdef(t.oid)
                           FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
                           JOIN pg_namespace n ON n.oid=c.relnamespace
                           WHERE n.nspname=%s AND NOT t.tgisinternal
                           ORDER BY c.relname,t.tgname""",original.N_TRIGGERS),
        }
        for label,(query,n) in sqls.items():
            rows=conn.execute(query,(original.SCHEMA,)).fetchall()
            if len(rows)!=n: raise AssertionError("V185_SCHEMA_COUNT_"+label)
            if label=="tables" and any(not r[1] or not r[2] for r in rows):
                raise AssertionError("V185_MISSING_FORCE_RLS")
            output[label]=hashlib.sha256(json.dumps(
                rows,default=str,ensure_ascii=False,separators=(",",":")
            ).encode("utf-8")).hexdigest()
        total=0
        for i in range(original.N_TABLES):
            statement=sql.SQL("SELECT id,org_id,value,proof_hash FROM {}.{} ORDER BY id").format(
                sql.Identifier(original.SCHEMA),
                sql.Identifier(f"tenant_ledger_{i:02}"))
            digest=hashlib.sha256()
            count=0
            per_org={"tenant-a":0,"tenant-b":0}
            with conn.cursor(name=f"v185_{i}") as cur:
                cur.execute(statement)
                while True:
                    block=cur.fetchmany(256)
                    if not block:break
                    for r in block:
                        count+=1
                        if r[1] not in per_org:raise AssertionError("V185_UNEXPECTED_TENANT")
                        per_org[r[1]]+=1
                        digest.update(json.dumps(
                            r,ensure_ascii=False,separators=(",",":"),default=str
                        ).encode("utf-8")+b"\n")
            if count!=ROWS_PER_TENANT*2 or any(v!=ROWS_PER_TENANT for v in per_org.values()):
                raise AssertionError("V185_INCOMPLETE_RECORD_"+str(i))
            output[f"table_{i:02}"]=digest.hexdigest()
            total+=count
        if total!=EXPECTED_ROWS:
            raise AssertionError("V185_INCORRECT_TOTAL_ROW_COUNT")
    return output


def tenant_barriers(dsn: str) -> None:
    with psycopg.connect(dsn) as conn:
        with conn.transaction():
            conn.execute(sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(original.ROLE)))
            conn.execute("SELECT set_config('jw.test_org','tenant-a',true)")
            for i in range(original.N_TABLES):
                count=conn.execute(sql.SQL("SELECT count(*) FROM {}.{}").format(
                    sql.Identifier(original.SCHEMA),
                    sql.Identifier(f"tenant_ledger_{i:02}"))).fetchone()[0]
                if count!=ROWS_PER_TENANT:raise AssertionError("V185_TENANT_LEAK")
            for i in range(19):
                insert=sql.SQL("""INSERT INTO {}.{} (id,org_id,value,proof_hash)
                                 VALUES (%s,'tenant-b',1,'forgery')""").format(
                    sql.Identifier(original.SCHEMA),
                    sql.Identifier(f"tenant_ledger_{i:02}"))
                try:
                    with conn.transaction():
                        conn.execute(insert,(f"v185-attacker-{i}",))
                except psycopg.errors.InsufficientPrivilege:
                    pass
                else:
                    raise AssertionError("V185_FOREIGN_TENANT_WRITE_ALLOWED")
            conn.execute("SELECT set_config('jw.test_org','unauthorized',true)")
            for i in range(original.N_TABLES):
                count=conn.execute(sql.SQL("SELECT count(*) FROM {}.{}").format(
                    sql.Identifier(original.SCHEMA),
                    sql.Identifier(f"tenant_ledger_{i:02}"))).fetchone()[0]
                if count!=0:raise AssertionError("V185_UNKNOWN_TENANT_VISIBLE")
    print("PASS_V185_43_TENANT_READS_19_FORBIDDEN_WRITES_43_UNKNOWN_READS",flush=True)


class ExpectedRollback(Exception):
    pass


def mutation_resistance(dsn: str, baseline: dict) -> None:
    # Mutation always ROLLS BACK; our immutable triggers are not disabled.
    with psycopg.connect(dsn) as conn:
        try:
            with conn.transaction():
                conn.execute(sql.SQL("""INSERT INTO {}.tenant_ledger_00
                    (id,org_id,value,proof_hash) VALUES
                    ('v185-artificial-corruption','tenant-a',777,'forged')""").format(
                    sql.Identifier(original.SCHEMA)))
                n=conn.execute(sql.SQL("SELECT count(*) FROM {}.tenant_ledger_00").format(
                    sql.Identifier(original.SCHEMA))).fetchone()[0]
                if n!=2001:raise AssertionError("V185_ROW_TAMPER_NOT_DETECTED")
                raise ExpectedRollback
        except ExpectedRollback:pass
        try:
            with conn.transaction():
                conn.execute(sql.SQL("""ALTER POLICY v181_read_00 ON {}.tenant_ledger_00
                                       USING (true)""").format(sql.Identifier(original.SCHEMA)))
                r=conn.execute("""SELECT qual FROM pg_policies
                       WHERE schemaname=%s AND tablename='tenant_ledger_00'
                       AND policyname='v181_read_00'""",(original.SCHEMA,)).fetchone()
                if r is None or r[0]!="true":
                    raise AssertionError("V185_POLICY_CORRUPTION_NOT_DETECTED")
                raise ExpectedRollback
        except ExpectedRollback:pass
    if signature(dsn)!=baseline:
        raise AssertionError("V185_CORRUPTION_NOT_ROLLED_BACK")
    print("PASS_V185_DB_ROW_AND_RLS_POLICY_TAMPER_CAUGHT_AND_ROLLED_BACK",flush=True)


def run() -> None:
    dsn=os.getenv("JW_PG_CI_ROOT_DSN","")
    original.guard(dsn)
    config=conninfo_to_dict(dsn)
    env=os.environ.copy()
    env["PGPASSWORD"]=config["password"]
    cid=original.validate_container_id(original.run_docker(
        "ps","--filter","ancestor=postgres:17","--format","{{.ID}}",timeout=10))
    if original.run_docker("inspect","--format","{{.Config.Image}}",cid,timeout=10)!=original.IMAGE:
        raise RuntimeError("BLOCKED_V185_UNEXPECTED_CONTAINER_IMAGE")
    restore_db="jw_v185_"+secrets.token_hex(5)
    archive="/tmp/"+restore_db+".dump"
    prepared=False
    destination=False
    t0=time.monotonic()
    try:
        prepared=True
        original.create_test_schema(dsn)
        populate(dsn)
        tenant_barriers(dsn)
        baseline=signature(dsn)
        original.run_docker("exec","-e","PGPASSWORD",cid,
            "pg_dump","-U","postgres","-h","127.0.0.1","-d","postgres",
            "--schema="+original.SCHEMA,"--format=custom","--file",archive,
            timeout=100,env=env)
        t1=time.monotonic()
        original.run_docker("exec","-e","PGPASSWORD",cid,
            "createdb","-U","postgres","-h","127.0.0.1",restore_db,
            timeout=15,env=env)
        destination=True
        original.run_docker("exec","-e","PGPASSWORD",cid,
            "pg_restore","-U","postgres","-h","127.0.0.1",
            "-d",restore_db,"--no-owner","--exit-on-error",archive,
            timeout=100,env=env)
        t2=time.monotonic()
        restored=make_conninfo(dsn,dbname=restore_db)
        if signature(restored)!=baseline:
            raise AssertionError("V185_BACKUP_RESTORE_SCHEMA_OR_86000_ROW_HASH_MISMATCH")
        tenant_barriers(restored)
        mutation_resistance(restored,baseline)
        if signature(dsn)!=baseline:
            raise AssertionError("V185_SOURCE_CHANGED_AFTER_RESTORE")
        print("PASS_V185_REAL_PG17_43_TABLE_62_POLICY_43_TRIGGER_86000_ROWS_EXACT_RESTORE",flush=True)
        print("MEASURED_V185_EPHEMERAL_DUMP_SECONDS="+str(round(t1-t0,3)),flush=True)
        print("MEASURED_V185_EPHEMERAL_RESTORE_SECONDS="+str(round(t2-t1,3)),flush=True)
        print("LIMIT_V185_PRODUCTION_RTO_RPO_NOT_MEASURED",flush=True)
        print("LIMIT_V185_NOT_REAL_DEV_SCHEMA_OR_CUSTOMER_BACKUP",flush=True)
    finally:
        errors=[]
        if destination:
            try:original.run_docker("exec","-e","PGPASSWORD",cid,
                "dropdb","--if-exists","-U","postgres","-h","127.0.0.1",
                restore_db,timeout=15,env=env)
            except Exception:errors.append("restore_db")
        try:original.run_docker("exec",cid,"rm","-f",archive,timeout=12)
        except Exception:errors.append("archive")
        if prepared:
            try:
                with psycopg.connect(dsn,autocommit=True) as conn:
                    conn.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(
                        sql.Identifier(original.SCHEMA)))
                    conn.execute(sql.SQL("DROP ROLE {}").format(
                        sql.Identifier(original.ROLE)))
            except Exception:errors.append("source")
        if errors:
            raise RuntimeError("FAIL_V185_EPHEMERAL_CLEANUP_"+",".join(errors))
        print("PASS_V185_EPHEMERAL_DB_AND_ARCHIVE_CLEANUP",flush=True)


if __name__=="__main__":
    run()
