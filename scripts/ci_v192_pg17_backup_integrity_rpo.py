"""V19.2 real PG17 backup integrity, corrupted archive rejection and RPO gap.

Everything runs ONLY on a single freshly initialized Docker postgres:17 local
GitHub Actions service. This intentionally shows that snapshot backup LOSES
a committed post-dump synthetic row; it does NOT claim 0 RPO or any production
RTO/RPO, availability, customer backup, or true PITR. Avoid changing real DB.
"""
from __future__ import annotations

import hashlib
import os
import re
import secrets
import time

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo

from scripts import ci_v181_pg17_scaled_restore as original
from scripts import ci_v185_pg17_86k_restore as load

HEX=re.compile(r"^[a-f0-9]{64}$")


def digest(cid: str,path: str) -> str:
    result=original.run_docker("exec",cid,"sha256sum",path,timeout=15)
    checksum=result.split()[0] if len(result.split())==2 else ""
    if not HEX.fullmatch(checksum):
        raise RuntimeError("FAIL_V192_BACKUP_DIGEST_UNAVAILABLE")
    return checksum


def require_good_archive(cid: str,path: str,expected: str) -> None:
    if not HEX.fullmatch(expected) or digest(cid,path)!=expected:
        raise ValueError("BLOCKED_V192_CORRUPTED_BACKUP_NOT_RESTORABLE")


def run() -> None:
    dsn=os.getenv("JW_PG_CI_ROOT_DSN","")
    if (os.getenv("JW_ENV")!="review" or
        os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"):
        raise RuntimeError("BLOCKED_V192_NOT_DISPOSABLE_CI")
    original.guard(dsn)
    opts=conninfo_to_dict(dsn)
    env={**os.environ,"PGPASSWORD":opts["password"]}
    cid=original.validate_container_id(original.run_docker(
        "ps","--filter","ancestor=postgres:17","--format","{{.ID}}",timeout=10))
    if original.run_docker(
        "inspect","--format","{{.Config.Image}}",cid,timeout=10)!=original.IMAGE:
        raise RuntimeError("BLOCKED_V192_UNEXPECTED_DOCKER_IMAGE")
    nonce=secrets.token_hex(5)
    restore_db="jw_v192_"+nonce
    archive="/tmp/jw_v192_"+nonce+".dump"
    corrupted="/tmp/jw_v192_"+nonce+".corrupt.dump"
    # All dynamically created paths are limited to safe filenames (no shell injection).
    assert re.fullmatch(r"/tmp/jw_v192_[0-9a-f]{10}\.(dump|corrupt\.dump)",archive)
    assert re.fullmatch(r"/tmp/jw_v192_[0-9a-f]{10}\.(dump|corrupt\.dump)",corrupted)
    setup=False
    created=False
    t0=time.monotonic()
    late="v192-post-snapshot-"+nonce
    try:
        setup=True
        original.create_test_schema(dsn)
        load.populate(dsn)
        expected=load.signature(dsn)
        original.run_docker("exec","-e","PGPASSWORD",cid,
           "pg_dump","-U","postgres","-h","127.0.0.1","-d","postgres",
           "--schema="+original.SCHEMA,"--format=custom","--file",archive,
           timeout=110,env=env)
        dump_ended=time.monotonic()
        checksum=digest(cid,archive)
        original.run_docker("exec",cid,"cp",archive,corrupted,timeout=15)
        # Make a synthetic archive copy unreadable, preserving the original.
        cmd="printf X | dd of="+corrupted+" bs=1 count=1 conv=notrunc status=none"
        original.run_docker("exec",cid,"sh","-c",cmd,timeout=15)
        try:
            require_good_archive(cid,corrupted,checksum)
        except ValueError as exc:
            if str(exc)!="BLOCKED_V192_CORRUPTED_BACKUP_NOT_RESTORABLE":
                raise
        else:
            raise AssertionError("FAIL_V192_CORRUPTED_ARCHIVE_ACCEPTED")
        require_good_archive(cid,archive,checksum)
        # A subsequent durable commit is EXPECTED to be absent from a
        # snapshot taken before this commit, proving nonzero snapshot RPO.
        with psycopg.connect(dsn) as root:
            root.execute(sql.SQL("""INSERT INTO {}.tenant_ledger_00
              (id,org_id,value,proof_hash) VALUES
              (%s,'tenant-a',999999,%s)""").format(
              sql.Identifier(original.SCHEMA)),
              (late,hashlib.sha256(late.encode()).hexdigest()))
        late_committed=time.monotonic()
        original.run_docker("exec","-e","PGPASSWORD",cid,
          "createdb","-U","postgres","-h","127.0.0.1",restore_db,
          timeout=15,env=env)
        created=True
        require_good_archive(cid,archive,checksum)
        original.run_docker("exec","-e","PGPASSWORD",cid,
           "pg_restore","-U","postgres","-h","127.0.0.1",
           "-d",restore_db,"--no-owner","--exit-on-error",archive,
           timeout=110,env=env)
        restore_ended=time.monotonic()
        recovered=make_conninfo(dsn,dbname=restore_db)
        assert load.signature(recovered)==expected,(
            "FAIL_V192_86000_SNAPSHOT_ROWS_OR_ROLE_POLICY_TRIGGER_CHANGED")
        with psycopg.connect(dsn) as source:
            assert source.execute(sql.SQL("SELECT count(*) FROM {}.tenant_ledger_00 "
               "WHERE id=%s").format(sql.Identifier(original.SCHEMA)),
               (late,)).fetchone()==(1,), "FAIL_V192_POSTBACKUP_ROW_NOT_DURABLE"
        with psycopg.connect(recovered) as target:
            assert target.execute(sql.SQL("SELECT count(*) FROM {}.tenant_ledger_00 "
               "WHERE id=%s").format(sql.Identifier(original.SCHEMA)),
               (late,)).fetchone()==(0,), "FAIL_V192_FALSE_ZERO_RPO"
        load.tenant_barriers(recovered)
        print("PASS_V192_REAL_PG17_SIGNED_DIGEST_ARCHIVE_TAMPER_REJECTED",flush=True)
        print("PASS_V192_86000_SNAPSHOT_ROWS_AND_43_RLS_62_POLICY_43_TRIGGER",flush=True)
        print("PASS_V192_POST_DUMP_DURABLE_COMMIT_NOT_IN_SNAPSHOT_EXPOSES_RPO_GAP",flush=True)
        print("MEASURED_V192_EPHEMERAL_DUMP_SECONDS="+str(round(dump_ended-t0,3)),flush=True)
        print("MEASURED_V192_EPHEMERAL_RESTORE_SECONDS="+str(round(restore_ended-late_committed,3)),flush=True)
        print("LIMIT_V192_REAL_STAGING_RTO_RPO_NOT_MEASURED_AND_SNAPSHOT_RPO_NOT_ZERO",flush=True)
    finally:
        cleanup=[]
        if created:
            try:
                original.run_docker("exec","-e","PGPASSWORD",cid,
                    "dropdb","--if-exists","-U","postgres","-h","127.0.0.1",
                    restore_db,timeout=20,env=env)
            except Exception:cleanup.append("restore")
        for path in (archive,corrupted):
            try:original.run_docker("exec",cid,"rm","-f",path,timeout=15)
            except Exception:cleanup.append("archive")
        if setup:
            try:
                with psycopg.connect(dsn,autocommit=True) as root:
                    root.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(
                        sql.Identifier(original.SCHEMA)))
                    root.execute(sql.SQL("DROP ROLE {}").format(
                        sql.Identifier(original.ROLE)))
            except Exception:cleanup.append("source")
        if cleanup:
            raise RuntimeError("FAIL_V192_CLEANUP_"+",".join(cleanup))
        print("PASS_V192_ONLY_EPHEMERAL_PG17_DATABASE_AND_ARCHIVE_CLEANUP",flush=True)


if __name__=="__main__":
    run()
