"""Disposable PG17 logical backup/restore proof; not production recovery.

Only the fixed CI service and fresh named databases inside it are used.
Roles are shared within this test cluster; cluster-wide role recovery,
PITR, external backup storage, and production failover are not tested.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

import psycopg

from scripts.naruv_recovery_pg17_lab import guarded_container, db_identity, CID
from scripts.naruv_approval_pg17_lab import root, actor, inspect
from scripts.naruv_atomic_fixture_pg17_lab import AtomicFixtureTests, commit_fixture, receipt

SOURCE_DB="naruv_approval_ci"
RESTORE_DB="naruv_restore_ci"
NEGATIVE_DB="naruv_restore_bad_ci"
MAX_BYTES=8*1024*1024
TABLES=("actors","targets","approvals","fixture_stage","fixture_items","fixture_receipts")

def need(ok,reason):
    if not ok:
        raise RuntimeError(reason)

def scope():
    need(os.environ.get("NARUV_BACKUP_ALLOW")=="ONLY_FRESH_CI_DATABASES","BACKUP_SCOPE")
    guarded_container(running=True)
    db_identity()

def connect(db,org=None):
    need(db in (SOURCE_DB,RESTORE_DB,NEGATIVE_DB),"BACKUP_DATABASE_SCOPE")
    need(org in (None,"org-a","org-b"),"BACKUP_ROLE_SCOPE")
    need(os.environ.get("NARUV_BACKUP_ALLOW")=="ONLY_FRESH_CI_DATABASES"
         and os.environ.get("NARUV_APPROVAL_PG_ALLOW")=="ONLY_DISPOSABLE_CI"
         and os.environ.get("GITHUB_ACTIONS")=="true","BACKUP_SCOPE")
    suffix={"org-a":"a","org-b":"b"}.get(org)
    user,password=("postgres","naruv-ci-root-fixture") if org is None else (
        "naruv_lab_"+suffix,"naruv-ci-"+suffix+"-fixture")
    c=psycopg.connect(dbname=db,user=user,password=password,host="127.0.0.1",port=5432,
                      connect_timeout=5,options="-c statement_timeout=5000 -c lock_timeout=4000")
    try:
        actual,version,login=c.execute("SELECT current_database(),current_setting('server_version_num')::int,session_user").fetchone()
        need((actual,login)==(db,user) and 170000<=version<180000,"BACKUP_DATABASE_IDENTITY")
        c.rollback()
        return c
    except BaseException:
        c.close()
        raise

def create_fresh(db):
    need(db in (RESTORE_DB,NEGATIVE_DB),"BACKUP_DATABASE_SCOPE")
    scope()
    with root() as c:
        c.autocommit=True
        need(c.execute("SELECT 1 FROM pg_database WHERE datname=%s",(db,)).fetchone() is None,
             "BACKUP_DESTINATION_EXISTS")
        # Identifiers are strictly allowlisted above, never external input.
        c.execute("CREATE DATABASE "+db+" TEMPLATE template0")
    with connect(db) as c:
        need(c.execute("SELECT to_regnamespace('naruv_approval_lab')").fetchone()[0] is None,
             "BACKUP_DESTINATION_NOT_EMPTY")

def snapshot(db):
    # Test service is quiescent during backup and comparisons. Include exact
    # row values (including staged payload and actor revisions), not counts only.
    with connect(db) as c:
        c.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        rows={}
        for table in TABLES:
            rows[table]=tuple(x[0] for x in c.execute(
                "SELECT to_jsonb(t)::text FROM naruv_approval_lab."+table+" t ORDER BY to_jsonb(t)::text COLLATE \"C\"").fetchall())
        catalog=c.execute("""SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,
              pg_get_userbyid(c.relowner),coalesce(c.relacl::text,'')
              FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname='naruv_approval_lab' AND c.relkind='r' ORDER BY c.relname""").fetchall()
        policies=c.execute("""SELECT tablename,policyname,permissive,roles::text,cmd,qual,with_check
              FROM pg_policies WHERE schemaname='naruv_approval_lab' ORDER BY tablename,policyname""").fetchall()
        funcs=c.execute("""SELECT p.proname,pg_get_function_identity_arguments(p.oid),
              p.prosecdef,pg_get_userbyid(p.proowner),p.proconfig::text,coalesce(p.proacl::text,''),
              pg_get_functiondef(p.oid)
              FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
              WHERE n.nspname='naruv_approval_lab' ORDER BY p.proname,pg_get_function_identity_arguments(p.oid)""").fetchall()
        constraints=c.execute("""SELECT t.relname,c.conname,pg_get_constraintdef(c.oid)
              FROM pg_constraint c JOIN pg_class t ON t.oid=c.conrelid
              JOIN pg_namespace n ON n.oid=t.relnamespace
              WHERE n.nspname='naruv_approval_lab' ORDER BY t.relname,c.conname""").fetchall()
        need(len(catalog)==6 and all(x[1] and x[2] and x[3]=="naruv_lab_owner" for x in catalog),
             "BACKUP_RLS_OWNER")
        need(len(policies)==6 and len(funcs)>0 and len(constraints)>0,"BACKUP_SCHEMA_EVIDENCE")
        return rows,catalog,policies,funcs,constraints

def digest(path):
    need(path.is_file() and 0<path.stat().st_size<=MAX_BYTES,"BACKUP_SIZE")
    return hashlib.sha256(path.read_bytes()).hexdigest()

def verify_archive(path,expected):
    need(type(expected) is str and re.fullmatch(r"[a-f0-9]{64}",expected) is not None,
         "BACKUP_DIGEST_FORMAT")
    need(digest(path)==expected,"BACKUP_DIGEST_MISMATCH")

def dump_archive(path):
    scope()
    # Binary archive transferred directly to an exclusive temp file; no
    # shell expansion, external destination, credentials in logs, or artifact upload.
    with path.open("xb") as out:
        subprocess.run(["docker","exec",CID,"pg_dump","-U","postgres","-d",SOURCE_DB,
                        "--schema=naruv_approval_lab","--format=custom","--no-password"],
                       stdout=out,stderr=subprocess.PIPE,check=True,timeout=30)
        out.flush()
        os.fsync(out.fileno())
    os.chmod(path,0o600)
    return digest(path)

def restore_archive(path,expected,db,*,expect_failure=False):
    need(db in (RESTORE_DB,NEGATIVE_DB),"BACKUP_DATABASE_SCOPE")
    need(expect_failure==(db==NEGATIVE_DB),"BACKUP_NEGATIVE_SCOPE")
    scope()
    verify_archive(path,expected)
    with connect(db) as c:
        need(c.execute("SELECT to_regnamespace('naruv_approval_lab')").fetchone()[0] is None,
             "BACKUP_DESTINATION_NOT_EMPTY")
    with path.open("rb") as inp:
        p=subprocess.run(["docker","exec","-i",CID,"pg_restore","-U","postgres","-d",db,
                          "--exit-on-error","--single-transaction","--no-password"],
                         stdin=inp,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30)
    verify_archive(path,expected)
    if expect_failure:
        need(p.returncode!=0,"BACKUP_NEGATIVE_RESTORE_UNEXPECTED_SUCCESS")
        with connect(db) as c:
            need(c.execute("SELECT to_regnamespace('naruv_approval_lab')").fetchone()[0] is None,
                 "BACKUP_PARTIAL_RESTORE")
    else:
        need(p.returncode==0,"BACKUP_RESTORE_FAILED")

def reject_sql(db,org,reason,fn):
    with connect(db,org) as c:
        try:
            fn(c)
        except psycopg.Error as exc:
            need(reason in (exc.diag.message_primary or ""),"BACKUP_WRONG_REJECTION")
            c.rollback()
        else:
            raise RuntimeError("BACKUP_REJECTION_MISSING")

def main():
    started=time.monotonic()
    scope()
    AtomicFixtureTests.setUpClass()
    f=AtomicFixtureTests("test_commit_and_receipt_after_reconnect")
    f.setUp()
    target_a=f.stage("org-a")
    f.stage("org-b")
    with actor("org-a") as c:
        need(commit_fixture(c)=="FIXTURE_COMMITTED","BACKUP_SOURCE_COMMIT")
    before=snapshot(SOURCE_DB)
    with tempfile.TemporaryDirectory(prefix="naruv-ci-backup-") as tmp:
        directory=Path(tmp)
        archive=directory/"fixture.dump"
        archive_hash=dump_archive(archive)
        need(snapshot(SOURCE_DB)==before,"BACKUP_SOURCE_CHANGED")
        # Verify exact same source snapshot before/after dump, then deliberately
        # add a later transaction: restored backup must not pretend to include it.
        with actor("org-b") as c:
            need(commit_fixture(c,"org-b")=="FIXTURE_COMMITTED","BACKUP_LATER_COMMIT")
        need(snapshot(SOURCE_DB)!=before,"BACKUP_LATER_COMMIT_NOT_OBSERVED")
        create_fresh(RESTORE_DB)
        create_fresh(NEGATIVE_DB)

        tampered=directory/"tampered.dump"
        payload=bytearray(archive.read_bytes())
        payload[len(payload)//2]^=1
        tampered.write_bytes(payload)
        try:
            verify_archive(tampered,archive_hash)
        except RuntimeError as exc:
            need(str(exc)=="BACKUP_DIGEST_MISMATCH","BACKUP_TAMPER_REASON")
        else:
            raise RuntimeError("BACKUP_TAMPER_ACCEPTED")
        print("NARUV_BACKUP_TAMPER_REJECTED")

        # Actual invalid archive with independently computed hash: checksum
        # consistency alone cannot make an invalid archive restorable.
        invalid=directory/"invalid.dump"
        invalid.write_bytes(b"not a PostgreSQL archive")
        restore_archive(invalid,digest(invalid),NEGATIVE_DB,expect_failure=True)
        print("NARUV_BACKUP_INVALID_ARCHIVE_REJECTED")

        restore_archive(archive,archive_hash,RESTORE_DB)
        need(snapshot(RESTORE_DB)==before,"BACKUP_RESTORED_DATA_OR_SCHEMA_MISMATCH")
        print("NARUV_BACKUP_EXACT_SIX_TABLES_AND_SCHEMA_PASS")
        with connect(RESTORE_DB,"org-a") as c:
            need(inspect(c,"org-a")==("RESERVED","request-1",False),"BACKUP_APPROVAL_STATE")
            need(receipt(c)==("FIXTURE_COMMITTED",2,False),"BACKUP_RECEIPT_STATE")
        reject_sql(RESTORE_DB,"org-a","APPROVAL_TARGET_CHANGED",commit_fixture)
        reject_sql(RESTORE_DB,"org-b","FIXTURE_SCOPE",lambda c:receipt(c,"org-a"))
        reject_sql(RESTORE_DB,"org-a","permission denied",
                   lambda c:c.execute("DELETE FROM naruv_approval_lab.fixture_items"))
        with connect(RESTORE_DB,"org-b") as c:
            need(inspect(c,"org-b")==("APPROVED",None,False),"BACKUP_PENDING_APPROVAL")
            need(receipt(c,"org-b") is None,"BACKUP_POST_SNAPSHOT_RECEIPT")
        with connect(SOURCE_DB,"org-b") as c:
            need(receipt(c,"org-b")==("FIXTURE_COMMITTED",2,False),"BACKUP_SOURCE_LATER_RECEIPT")
        with connect(RESTORE_DB) as c:
            items=c.execute("SELECT organization_id,source_item_id,name FROM naruv_approval_lab.fixture_items ORDER BY organization_id,source_item_id").fetchall()
            need(items==[("org-a","001","품목 A"),("org-a","002","품목 B")],"BACKUP_ROW_VALUES")
            need(c.execute("SELECT snapshot_sha256 FROM naruv_approval_lab.targets WHERE organization_id='org-a'").fetchone()[0]
                 ==target_a.snapshot_sha256,"BACKUP_TARGET_BINDING")
        verify_archive(archive,archive_hash)
        print("NARUV_BACKUP_REPLAY_TENANT_AND_SNAPSHOT_CUTOFF_PASS")
        print("NARUV_BACKUP_PG17_PASS", "archive_bytes="+str(archive.stat().st_size),
              "sha256="+archive_hash,"elapsed_ms="+str(int((time.monotonic()-started)*1000)),
              "shared_cluster_roles=true production_import_authorized=false auto_retry=false")
    # Temporary archive removed; restored DBs intentionally remain only in
    # this disposable service until GitHub Actions cleanup. Never DROP a DB.

if __name__=="__main__":
    main()
