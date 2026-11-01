"""V19.6 isolated PG17 encrypted disaster recovery of V19.5 approval evidence.

Only disposable local postgres:17 service. Reuse the ACTUAL previous real-TLS
XLSX upload -> signed approval receipt -> internal order acceptance test, then
back up the real temporary tables, protect the archive with authenticated
encryption, restore to a fresh disposable DB, revalidate immutable evidence
and minimal privileged function ownership. A later committed synthetic preview
must be ABSENT from the snapshot, proving a nonzero RPO window.

NEVER run against shared DEV, hosted Render, Supabase or customer documents.
This is NOT a production RTO/RPO test, PITR, KMS, or external-site backup.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time

from cryptography.fernet import Fernet,InvalidToken
import psycopg
from psycopg import errors,sql
from psycopg.conninfo import conninfo_to_dict,make_conninfo

from scripts import ci_v195_atomic_approval_receipt_https as case
from scripts import ci_v181_pg17_scaled_restore as isolated

TABLES=(
    "import_previews","v195_approval_receipts","v195_approval_secrets",
    "quotes","quote_items","order_drafts_v127","orders","order_items",
    "audit_logs","users","sessions",
)
OWNER="jw_ci_v195_proof_owner"
DEF_FN="jw_dev.v195_confirm_import(text,text,text,text,text,text,text)"
SOURCE_SCHEMA="jw_dev"


def source_fingerprint(dsn: str) -> dict:
    # Full-row digests: include encrypted normalized document, receipts,
    # original business lineages, audit and secret material without logging it.
    fingerprints={}
    with psycopg.connect(dsn,connect_timeout=5) as root:
        for table in TABLES:
            rows=root.execute(sql.SQL("SELECT * FROM jw_dev.{} ORDER BY 1").format(
                sql.Identifier(table))).fetchall()
            fingerprints[table]=(len(rows),hashlib.sha256(
                json.dumps(rows,ensure_ascii=False,default=str,
                    separators=(",",":")).encode()).hexdigest())
        expected={
            "import_previews":3,"v195_approval_receipts":1,
            "v195_approval_secrets":1,
        }
        for key,n in expected.items():
            assert fingerprints[key][0]==n,("V196_SOURCE_EVIDENCE_MISSING",key)
        for table in ("import_previews","v195_approval_receipts",
                      "v195_approval_secrets"):
            row=root.execute("""SELECT relrowsecurity,relforcerowsecurity
                 FROM pg_class WHERE oid=%s::regclass""",
                 ("jw_dev."+table,)).fetchone()
            assert row==(True,True),("V196_FORCE_RLS_MISSING",table,row)
        owner=root.execute("""SELECT pg_get_userbyid(proowner) FROM pg_proc
              WHERE oid=%s::regprocedure""",(DEF_FN,)).fetchone()
        assert owner==(OWNER,),("V196_UNSAFE_SOURCE_APPROVAL_OWNER",owner)
        function_def=root.execute("""SELECT pg_get_functiondef(%s::regprocedure)""",
                                  (DEF_FN,)).fetchone()[0]
        fingerprints["function_source_hash"]=hashlib.sha256(
           function_def.encode()).hexdigest()
        grants={
            "trade_status":root.execute("""SELECT has_column_privilege(
              'jw_app_dev','jw_dev.import_previews','status','UPDATE')""").fetchone()[0],
            "reviewer_status":root.execute("""SELECT has_column_privilege(
              'jw_ci_v194_approver','jw_dev.import_previews','status','UPDATE')""").fetchone()[0],
            "reviewer_rpc":root.execute("""SELECT has_function_privilege(
              'jw_ci_v194_approver',%s,'EXECUTE')""",(DEF_FN,)).fetchone()[0]
        }
        assert grants=={"trade_status":False,"reviewer_status":False,
                        "reviewer_rpc":True},("V196_UNSAFE_SOURCE_GRANTS",grants)
        fingerprints["role_grants"]=grants
    return fingerprints


def verify_restored(dsn: str, baseline: dict, *, owner_repaired: bool) -> None:
    recovered=source_fingerprint(dsn)
    assert recovered==baseline,"V196_DATA_OR_SECURITY_PROOFS_CHANGED_AFTER_RESTORE"
    with psycopg.connect(dsn) as root:
        first=root.execute("""SELECT r.preview_id,r.signature,r.statement,
          p.status,p.preview_digest,s.secret
          FROM jw_dev.v195_approval_receipts r
          JOIN jw_dev.import_previews p ON p.id=r.preview_id
          JOIN jw_dev.v195_approval_secrets s ON s.name='active'""").fetchone()
        assert first and first[3]=="confirmed" and first[4] is not None
        import hmac
        assert hmac.compare_digest(first[1],hmac.new(first[5],
            first[2].encode("utf-8"),hashlib.sha256).hexdigest()),(
            "V196_RESTORED_APPROVAL_HMAC_INVALID")
        assert root.execute("""SELECT count(*) FROM jw_dev.import_previews
          WHERE status='pending'""").fetchone()==(1,)
        # Even after restoring, the immutable trigger must work.
        receipt_id=root.execute("""SELECT id FROM jw_dev.v195_approval_receipts
                                 LIMIT 1""").fetchone()[0]
        try:
            with root.transaction():
                root.execute("""UPDATE jw_dev.v195_approval_receipts
                     SET signature=%s WHERE id=%s""",("f"*64,receipt_id))
        except errors.InsufficientPrivilege:
            pass
        else:
            raise AssertionError("V196_RESTORED_IMMUTABLE_RECEIPT_MUTATED")
    assert owner_repaired
    print("PASS_V196_RESTORED_SIGNED_APPROVAL_QUOTE_ORDER_AUDIT_AND_IMMUTABILITY",
          flush=True)


def run() -> None:
    dsn=os.getenv("JW_PG_CI_ROOT_DSN","")
    if (os.getenv("JW_ENV")!="review" or
        os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"):
        raise RuntimeError("BLOCKED_V196_NOT_DISPOSABLE_REVIEW")
    # Must check BEFORE V19.5 bootstraps roles and synthetic tables.
    isolated.guard(dsn)
    opts=conninfo_to_dict(dsn)
    env={**os.environ,"PGPASSWORD":opts["password"]}
    cid=isolated.validate_container_id(isolated.run_docker(
        "ps","--filter","ancestor=postgres:17","--format","{{.ID}}",timeout=10))
    image=isolated.run_docker("inspect","--format","{{.Config.Image}}",cid,timeout=10)
    if image!=isolated.IMAGE:
        raise RuntimeError("BLOCKED_V196_UNEXPECTED_DOCKER_IMAGE")
    case.main()  # actual HTTPS, PG17, 20 forged signatures + 12 concurrent replays
    baseline=source_fingerprint(dsn)
    restore_db="jw_v196_"+secrets.token_hex(6)
    assert restore_db.startswith("jw_v196_") and len(restore_db)==20
    cpath="/tmp/"+restore_db+".pgdump"
    created=False
    with TemporaryDirectory(prefix="jw-v196-encrypted-dr-") as directory:
        plaintext=Path(directory)/"sensitive.pgdump"
        encrypted=Path(directory)/"archive.fernet"
        unpacked=Path(directory)/"unpacked.pgdump"
        key=Fernet.generate_key()
        cipher=Fernet(key)
        start=time.monotonic()
        try:
            # Custom PostgreSQL17 pg_dump contains sensitive snapshot data.
            # No archive or key ever leaves this isolated CI worker.
            isolated.run_docker("exec","-e","PGPASSWORD",cid,
                "pg_dump","-U","postgres","-h","127.0.0.1",
                "-d","postgres","--schema=jw_dev","--format=custom",
                "--file",cpath,timeout=90,env=env)
            dumped=time.monotonic()
            isolated.run_docker("cp",cid+":"+cpath,str(plaintext),timeout=15)
            raw=plaintext.read_bytes()
            assert raw[:5]==b"PGDMP" and len(raw)>5000
            digest=hashlib.sha256(raw).hexdigest()
            # Persist ONLY ciphertext in the runner's backup storage.
            encrypted.write_bytes(cipher.encrypt(raw))
            plaintext.unlink()
            isolated.run_docker("exec",cid,"rm","-f",cpath,timeout=15)
            blob=encrypted.read_bytes()
            assert not blob.startswith(b"PGDMP")
            damage=bytearray(blob)
            damage[len(damage)//2]^=0x01
            try:
                cipher.decrypt(bytes(damage))
            except InvalidToken:
                pass
            else:
                raise AssertionError("V196_TAMPERED_ENCRYPTED_BACKUP_DECRYPTED")
            print("PASS_V196_AUTHENTICATED_ENCRYPTED_BACKUP_TAMPER_REJECTION",
                  flush=True)
            # Commit a post-backup synthetic preview to prove snapshot RPO gap.
            later=secrets.token_hex(16)
            with psycopg.connect(dsn) as root:
                root.execute("""INSERT INTO jw_dev.import_previews(
                     id,org_id,uploaded_by,file_sha256,normalized_json,
                     preview_digest,status,quote_id)
                   SELECT %s,org_id,uploaded_by,%s,normalized_json,
                     preview_digest,'pending',NULL
                   FROM jw_dev.import_previews
                   WHERE status='confirmed' LIMIT 1""",
                   (later,hashlib.sha256(secrets.token_bytes(32)).hexdigest()))
            with psycopg.connect(dsn) as root:
                assert root.execute("""SELECT count(*) FROM jw_dev.import_previews
                     WHERE id=%s""",(later,)).fetchone()==(1,)
            isolated.run_docker("exec","-e","PGPASSWORD",cid,
                "createdb","-U","postgres","-h","127.0.0.1",
                restore_db,timeout=20,env=env)
            created=True
            # pgcrypto extension in public schema is outside jw_dev schema dump.
            restore_dsn=make_conninfo(dsn,dbname=restore_db)
            with psycopg.connect(restore_dsn) as root:
                root.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            recovered=cipher.decrypt(blob)
            assert hashlib.sha256(recovered).hexdigest()==digest
            unpacked.write_bytes(recovered)
            isolated.run_docker("cp",str(unpacked),cid+":"+cpath,timeout=15)
            unpacked.unlink()
            isolated.run_docker("exec","-e","PGPASSWORD",cid,
                "pg_restore","-U","postgres","-h","127.0.0.1",
                "--dbname",restore_db,"--no-owner","--exit-on-error",cpath,
                timeout=110,env=env)
            # An unowned dump with --no-owner gives SECURITY DEFINER functions
            # the restore login's privileges; superuser ownership is UNSAFE.
            with psycopg.connect(restore_dsn) as root:
                found=root.execute("""SELECT pg_get_userbyid(proowner)
                       FROM pg_proc WHERE oid=%s::regprocedure""",
                       (DEF_FN,)).fetchone()
                assert found==("postgres",),("V196_EXPECTED_OWNER_DRIFT",found)
                print("PASS_V196_RESTORE_SUPERUSER_OWNER_DRIFT_DETECTED",flush=True)
                # Quarantined restore is never served before this strict
                # role re-binding; inherited table privileges remain RLS.
                root.execute(sql.SQL("ALTER FUNCTION {} OWNER TO {}").format(
                     sql.SQL(DEF_FN),sql.Identifier(OWNER)))
                root.execute("REVOKE CREATE ON SCHEMA jw_dev FROM "+OWNER)
            restored=time.monotonic()
            verify_restored(restore_dsn,baseline,owner_repaired=True)
            with psycopg.connect(restore_dsn) as root:
                assert root.execute("""SELECT count(*) FROM jw_dev.import_previews
                     WHERE id=%s""",(later,)).fetchone()==(0,),(
                     "V196_FALSE_CLAIM_OF_ZERO_RPO")
            # Twenty adversarial checks on restored approval boundary.
            with psycopg.connect(make_conninfo(case.review._reviewer_dsn,
                 dbname=restore_db)) as reviewer:
                restored_pending=psycopg.connect(restore_dsn)
                try:
                    row=restored_pending.execute("""SELECT id,org_id,
                       uploaded_by,preview_digest FROM jw_dev.import_previews
                       WHERE status='pending' LIMIT 1""").fetchone()
                finally:
                    restored_pending.close()
                assert row is not None
                rid,org,actor,rdigest=row
                statement=json.dumps({"schema":"jw-import-approval-v195",
                   "preview_id":rid,"org_id":org,"actor_id":actor,
                   "preview_digest":rdigest,"approved":True,
                   "company":"Customer A","quote_date":"2026-10-31",
                   "total_krw":176000},sort_keys=True,separators=(",",":"))
                for i in range(20):
                    forged=f"{i+1:064x}"
                    try:
                        with reviewer.transaction():
                            reviewer.execute("""SELECT jw_dev.v195_confirm_import(
                                 %s,%s,%s,%s,%s,%s,%s)""",
                                 (rid,org,actor,rdigest,statement,forged,
                                  secrets.token_hex(16)))
                    except errors.InsufficientPrivilege:
                        pass
                    else:
                        raise AssertionError("V196_RESTORED_ROLE_ACCEPTED_FORGED_SIGNATURE")
            with psycopg.connect(restore_dsn) as root:
                assert root.execute("""SELECT status FROM jw_dev.import_previews
                     WHERE id=%s""",(rid,)).fetchone()==("pending",)
                assert root.execute("""SELECT count(*) FROM jw_dev.v195_approval_receipts""").fetchone()==(1,)
            print("PASS_V196_TWENTY_POST_RESTORE_FORGED_APPROVALS_DENIED",flush=True)
            print("PASS_V196_POST_BACKUP_COMMIT_MISSING_SNAPSHOT_RPO_NOT_ZERO",flush=True)
            print("MEASURED_V196_EPHEMERAL_DUMP_SECONDS="+str(round(dumped-start,3)),flush=True)
            print("MEASURED_V196_EPHEMERAL_RESTORE_SECONDS="+str(round(restored-dumped,3)),flush=True)
            print("LIMIT_V196_NOT_HOSTED_DR_OR_PRODUCTION_RTO_RPO",flush=True)
        finally:
            if created:
                isolated.run_docker("exec","-e","PGPASSWORD",cid,
                    "dropdb","--if-exists","-U","postgres","-h","127.0.0.1",
                    restore_db,timeout=25,env=env)
            isolated.run_docker("exec",cid,"rm","-f",cpath,timeout=10)
            for file in (plaintext,unpacked,encrypted):
                file.unlink(missing_ok=True)
            print("PASS_V196_EPHEMERAL_RESTORE_AND_ARCHIVE_CLEANED",flush=True)


if __name__=="__main__":
    run()
