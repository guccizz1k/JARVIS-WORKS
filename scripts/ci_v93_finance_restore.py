"""V9.3 actual custom pg_dump/isolated pg_restore; complete 13-table CI fixture.

This is a synthetic, ephemeral PostgreSQL 17 rehearsal only. The script never
uses real Supabase credentials; source remains byte-equivalent after restore.
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import time

import psycopg
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from scripts.ci_j6_postgres_restore import run_docker,validate_container_id,IMAGE
from scripts.ci_v90_postgres_browser import require_disposable

TABLES=("organizations","users","sessions","messenger_companies",
 "messenger_connections","messenger_messages","messenger_attachments",
 "messenger_edits","messenger_read_positions","customers","quotes",
 "quote_items","audit_logs")


def check_snapshot(conn) -> dict:
    counts={}
    for name in TABLES:
        with conn.cursor() as cur:
            cur.execute(f"SELECT row_to_json(t)::text FROM jw_dev.{name} AS t")
            values=sorted(row[0] for row in cur.fetchall())
        data=json.dumps(values,sort_keys=True,separators=(",",":")).encode()
        counts[name]=(len(values),hashlib.sha256(data).hexdigest())
    with conn.cursor() as cur:
        cur.execute("""SELECT relname,relrowsecurity,relforcerowsecurity
           FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
           WHERE n.nspname='jw_dev' AND c.relkind='r' ORDER BY relname""")
        rls=cur.fetchall()
        if len(rls)!=13 or any(not r[1] or not r[2] for r in rls):
            raise RuntimeError("Not all 13 synthetic tables have FORCE RLS")
        cur.execute("""SELECT tablename,policyname,cmd,roles::text,qual,with_check
          FROM pg_policies WHERE schemaname='jw_dev'
          ORDER BY tablename,policyname""")
        policies=cur.fetchall()
        cur.execute("""SELECT proname,md5(pg_get_functiondef(p.oid))
          FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
          WHERE n.nspname='jw_dev' ORDER BY proname""")
        functions=cur.fetchall()
    for kind,rows in (("rls",rls),("policies",policies),("functions",functions)):
        counts[kind]=(len(rows),hashlib.sha256(
            json.dumps(rows,default=str).encode()).hexdigest())
    if counts["quotes"][0]<1 or counts["quote_items"][0]<2 or counts["audit_logs"][0]<1:
        raise RuntimeError("Quote end-to-end fixture records absent")
    if counts["policies"][0]<6:
        raise RuntimeError("Synthetic tenant policies absent")
    return counts


def run()->int:
    if (os.environ.get("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"
       or os.environ.get("JW_ENV")!="review"):
        raise RuntimeError("BLOCKED: cannot restore outside one ephemeral CI DB")
    require_disposable()  # fresh-service check applies before bootstrap, not here
    return 0

def restore_proof()->None:
    # This runs after the stage bootstrap; re-check connection independently.
    from scripts import ci_v90_postgres_browser as fixture
    dsn=fixture.root_dsn
    args=conninfo_to_dict(dsn)
    if (os.environ.get("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"
        or args.get("host")!="127.0.0.1" or args.get("user")!="postgres"
        or args.get("dbname")!="postgres"):
        raise RuntimeError("Unapproved source host/user/database")
    with psycopg.connect(dsn) as original:
        pgver=original.execute("SHOW server_version_num").fetchone()[0]
        if int(pgver)//10000!=17:
            raise RuntimeError("PG17 is required")
        state=check_snapshot(original)
    cid=validate_container_id(run_docker("ps","--filter","ancestor=postgres:17",
                                         "--format","{{.ID}}",timeout=8))
    if run_docker("inspect","--format","{{.Config.Image}}",cid,timeout=8)!=IMAGE:
        raise RuntimeError("Unsafe source container")
    name="jw_j6_restore_"+secrets.token_hex(5)
    dump="/tmp/"+name+".dump"
    env=os.environ.copy()
    env["PGPASSWORD"]=args["password"]
    started=time.monotonic()
    created=False
    try:
        run_docker("exec","-e","PGPASSWORD",cid,"pg_dump","-U","postgres",
                   "-h","127.0.0.1","-d","postgres","--format=custom",
                   "--file",dump,timeout=40,env=env)
        run_docker("exec","-e","PGPASSWORD",cid,"createdb","-U","postgres",
                   "-h","127.0.0.1",name,timeout=12,env=env)
        created=True
        run_docker("exec","-e","PGPASSWORD",cid,"pg_restore","-U","postgres",
                   "-h","127.0.0.1","-d",name,"--no-owner","--exit-on-error",
                   dump,timeout=50,env=env)
        with psycopg.connect(make_conninfo(dsn,dbname=name)) as restored:
            other=check_snapshot(restored)
        if other!=state:
            mismatch=[key for key in state if state[key]!=other.get(key)]
            raise AssertionError("Data/ACL restore mismatch: "+",".join(mismatch))
        print("PASS: real 13-table PG17 dump/restore, 16 dataset/force-RLS/policy/function fingerprints exact",flush=True)
        print("MEASURED: synthetic PG17 restore/verify elapsed %.3fs (NOT production RTO/RPO)" % (time.monotonic()-started),flush=True)
    finally:
        cleanup_errors=[]
        if created:
            try:
                run_docker("exec","-e","PGPASSWORD",cid,"dropdb","--if-exists",
                           "-U","postgres","-h","127.0.0.1",name,env=env)
            except Exception:cleanup_errors.append("db")
        try:run_docker("exec",cid,"rm","-f",dump,timeout=8)
        except Exception:cleanup_errors.append("dump")
        if cleanup_errors:raise RuntimeError("Failed safe cleanup: "+",".join(cleanup_errors))
        with psycopg.connect(dsn) as original:
            if check_snapshot(original)!=state:
                raise AssertionError("Original source mutated during restore")
        print("PASS: restored target/dump removed, source left intact",flush=True)
