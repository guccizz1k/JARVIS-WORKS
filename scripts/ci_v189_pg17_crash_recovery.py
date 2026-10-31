"""V18.9 disposable PostgreSQL17 real SIGKILL recovery and data integrity.

ONLY an empty LOCAL 127.0.0.1 GitHub Actions PG17 service container.
Live customer data, Supabase DB, Render database and real operational RTO/RPO
are NOT touched or measured. Crash drops an uncommitted synthetic transaction,
retains a committed marker, preserves 86k synthetic business rows + FORCE RLS.
"""
from __future__ import annotations

import os
import time

import psycopg
from psycopg import sql

from scripts import ci_v181_pg17_scaled_restore as original
from scripts import ci_v185_pg17_86k_restore as verified

_ACK="ONLY_EPHEMERAL_LOCAL_DATABASE"


def recover() -> None:
    dsn=os.getenv("JW_PG_CI_ROOT_DSN","")
    if os.getenv("JW_ENV")!="review" or os.getenv("JW_PG_CI_ALLOW")!=_ACK:
        raise RuntimeError("BLOCKED_V189_ONLY_DISPOSABLE_LOCAL_PG")
    original.guard(dsn)
    cid=original.validate_container_id(original.run_docker(
        "ps","--filter","ancestor=postgres:17","--format","{{.ID}}",timeout=12))
    if original.run_docker("inspect","--format","{{.Config.Image}}",cid,
                           timeout=10)!=original.IMAGE:
        raise RuntimeError("BLOCKED_V189_NON_PG17_DOCKER_IMAGE")
    prepared=False
    marker_created=False
    crashed=False
    recovered=False
    pending=None
    start=None
    try:
        prepared=True
        original.create_test_schema(dsn)
        verified.populate(dsn)
        before=verified.signature(dsn)
        with psycopg.connect(dsn,autocommit=True) as conn:
            conn.execute("""CREATE TABLE public.v189_crash_marker
                (id text PRIMARY KEY, value text NOT NULL)""")
            marker_created=True
            conn.execute("""INSERT INTO public.v189_crash_marker
                (id,value) VALUES ('committed','durable')""")
            assert conn.execute("SHOW synchronous_commit").fetchone()[0]=="on",(
                "FAIL_V189_UNEXPECTED_ASYNC_COMMIT")
        pending=psycopg.connect(dsn,autocommit=False,connect_timeout=4)
        pending.execute("""INSERT INTO public.v189_crash_marker
                (id,value) VALUES ('uncommitted','must-not-survive')""")
        # No COMMIT on the second session. Real DB container process death.
        start=time.monotonic()
        original.run_docker("kill","--signal=SIGKILL",cid,timeout=15)
        crashed=True
        try:
            original.run_docker("start",cid,timeout=25)
        except Exception:
            # Always let finally restore the isolated service if it is down.
            raise
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            try:
                with psycopg.connect(dsn,connect_timeout=2) as probe:
                    actual=probe.execute("""SELECT id,value FROM
                        public.v189_crash_marker ORDER BY id""").fetchall()
                    if actual!=[("committed","durable")]:
                        raise AssertionError(
                            "FAIL_V189_UNCOMMITTED_ROW_PRESENT_OR_COMMITTED_MISSING")
                    recovered=True
                    break
            except (psycopg.OperationalError,psycopg.InterfaceError):
                time.sleep(.4)
        if not recovered:
            raise RuntimeError("FAIL_V189_DATABASE_CRASH_RECOVERY_TIMEOUT")
        outage=round(time.monotonic()-start,3)
        assert verified.signature(dsn)==before,(
            "FAIL_V189_86000_ROWS_SCHEMA_RLS_AFTER_PROCESS_CRASH")
        verified.tenant_barriers(dsn)
        print("PASS_V189_REAL_SIGKILL_POSTGRES17_RECOVERY_COMMITTED_ONLY",flush=True)
        print("PASS_V189_86000_ROWS_43_TABLE_62_POLICY_43_TRIGGER_EXACT_POSTCRASH",flush=True)
        print("MEASURED_V189_EPHEMERAL_OUTAGE_SECONDS="+str(outage),flush=True)
        print("LIMIT_V189_NOT_HOSTED_RTO_RPO_OR_FAILOVER",flush=True)
    finally:
        errors=[]
        if pending is not None:
            try:pending.close()
            except Exception:pass
        if crashed and not recovered:
            try:original.run_docker("start",cid,timeout=25)
            except Exception:errors.append("restart")
        if marker_created:
            try:
                with psycopg.connect(dsn,autocommit=True,connect_timeout=5) as c:
                    c.execute("DROP TABLE IF EXISTS public.v189_crash_marker")
            except Exception:errors.append("marker")
        if prepared:
            try:
                with psycopg.connect(dsn,autocommit=True,connect_timeout=5) as c:
                    c.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(
                        sql.Identifier(original.SCHEMA)))
                    c.execute(sql.SQL("DROP ROLE {}").format(
                        sql.Identifier(original.ROLE)))
            except Exception:errors.append("synthetic_schema")
        if errors:raise RuntimeError("FAIL_V189_CLEANUP_"+",".join(errors))
        print("PASS_V189_ISOLATED_DATABASE_CLEANUP",flush=True)


if __name__=="__main__":
    recover()
