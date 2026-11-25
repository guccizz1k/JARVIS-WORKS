"""V19.7 real *separate PostgreSQL17 clusters* restore of signed approval.

Two fresh postgres:17 Docker SERVICE CONTAINERS on ONE GitHub runner,
with isolated database volumes, separate host ports and distinct reviewer
credentials. This is stronger than restoring to a second database in one
Postgres instance (V19.6), but is NOT an independent physical host,
offsite backup, PITR, or production/Render RTO/RPO measurement.

Everything is synthetic, read-only with respect to the original project,
and strictly blocked outside approved local disposable GitHub PG17.
"""
from __future__ import annotations

from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import secrets
from tempfile import TemporaryDirectory
import time

from cryptography.fernet import Fernet, InvalidToken
import psycopg
from psycopg import errors,sql
from psycopg.conninfo import make_conninfo,conninfo_to_dict

from scripts import ci_v195_atomic_approval_receipt_https as live
from scripts import ci_v196_pg17_approval_encrypted_dr as previous
from scripts import ci_v181_pg17_scaled_restore as original

HEX = re.compile(r"^[0-9a-f]{12,64}$")
PORTS = {"source": 5432, "target": 5433}


def fresh_guard(dsn: str,port: int) -> None:
    original.guard(dsn) if port==5432 else None
    details=conninfo_to_dict(dsn)
    assert (details.get("host"),details.get("user"),
            details.get("dbname"),details.get("port","5432"))==(
        "127.0.0.1","postgres","postgres",str(port)),(
        "BLOCKED_V197_FOREIGN_POSTGRES_TARGET")
    with psycopg.connect(dsn,connect_timeout=5) as db:
        assert int(db.execute("SHOW server_version_num").fetchone()[0])//10000==17
        assert db.execute("""SELECT count(*) FROM pg_database
             WHERE NOT datistemplate AND datname<>'postgres'""").fetchone()==(0,)
        assert db.execute("""SELECT count(*) FROM pg_roles
             WHERE rolname<>'postgres' AND rolname!~'^pg_'""").fetchone()==(0,)
        assert db.execute("""SELECT count(*) FROM pg_namespace
             WHERE nspname NOT IN ('pg_catalog','information_schema','public')
             AND nspname NOT LIKE 'pg_%'""").fetchone()==(0,)


def isolated_pair() -> tuple[str,str]:
    # Prefer host-port mapping identity to "first postgres" in an environment
    # containing two identical images. Require exactly the two expected ones.
    lines=original.run_docker("ps","--filter","ancestor=postgres:17",
             "--format","{{.ID}}|{{.Ports}}",timeout=15).splitlines()
    if len(lines)!=2:
        raise RuntimeError("BLOCKED_V197_EXPECTED_TWO_FRESH_DOCKER_CONTAINERS")
    results={}
    for line in lines:
        parts=line.split("|",1)
        if len(parts)!=2 or not HEX.fullmatch(parts[0]):
            raise RuntimeError("BLOCKED_V197_BAD_CONTAINER_IDENTIFIER")
        cid,ports=parts
        image=original.run_docker("inspect","--format","{{.Config.Image}}",cid,
                                   timeout=10)
        if image!=original.IMAGE:
            raise RuntimeError("BLOCKED_V197_UNEXPECTED_IMAGE")
        matches=[label for label,port in PORTS.items()
                 if re.search(r"(?<!\d):"+str(port)+r"->5432/tcp",ports)]
        if len(matches)!=1 or matches[0] in results:
            raise RuntimeError("BLOCKED_V197_CONTAINER_PORT_AMBIGUOUS")
        results[matches[0]]=cid
    if set(results)!=set(PORTS) or len(set(results.values()))!=2:
        raise RuntimeError("BLOCKED_V197_SOURCE_TARGET_NOT_DISTINCT")
    return results["source"],results["target"]


def source_users(dsn: str) -> list[str]:
    with psycopg.connect(dsn) as db:
        rows=db.execute("""SELECT rolname FROM pg_roles
            WHERE rolname<>'postgres' AND rolname NOT LIKE 'pg_%'
            ORDER BY rolname""").fetchall()
    names=[r[0] for r in rows]
    required={"jw_app_dev","jw_ci_v194_approver",
              "jw_ci_v195_proof_owner","jw_ci_v157_trade",
              "jw_auth_stage_v85","anon","authenticated"}
    if not required.issubset(names) or len(names)>25:
        raise RuntimeError("BLOCKED_V197_UNEXPECTED_ROLE_INVENTORY")
    if any(not re.fullmatch(r"[a-z][a-z0-9_]{0,62}",n) for n in names):
        raise RuntimeError("BLOCKED_V197_UNSAFE_ROLE_NAME")
    return names


def create_isolated_target_roles(dsn: str,names: list[str]) -> str:
    # Never reuse source passwords. All roles except the review-only verifier
    # are deliberately NOLOGIN. Requires genuine cross-cluster bootstrap.
    passwd=secrets.token_urlsafe(42)
    with psycopg.connect(dsn,autocommit=True) as admin:
        admin.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public")
        for name in names:
            if name=="jw_ci_v194_approver":
                q=sql.SQL("""CREATE ROLE {} LOGIN NOINHERIT NOBYPASSRLS
                     NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}""").format(
                     sql.Identifier(name),sql.Literal(passwd))
            else:
                q=sql.SQL("""CREATE ROLE {} NOLOGIN NOINHERIT NOBYPASSRLS
                     NOSUPERUSER NOCREATEDB NOCREATEROLE""").format(sql.Identifier(name))
            admin.execute(q)
    return make_conninfo(dsn,user="jw_ci_v194_approver",password=passwd)


def check_restored_boundary(dsn: str,baseline: dict,reviewer_dsn: str) -> None:
    previous.verify_restored(dsn,baseline,owner_repaired=True)
    # Every restored source signature has to independently verify with
    # the restored secret, preserving original normalized evidence.
    with psycopg.connect(dsn) as root:
        rows=root.execute("""SELECT r.preview_id,r.statement,r.signature,
            p.status,s.secret FROM jw_dev.v195_approval_receipts r
            JOIN jw_dev.import_previews p ON p.id=r.preview_id
            JOIN jw_dev.v195_approval_secrets s ON s.name='active'""").fetchall()
        assert len(rows)==1,("FAIL_V197_MISSING_OR_MULTIPLE_RECEIPTS",len(rows))
        preview,statement,signature,status,key=rows[0]
        assert status=="confirmed"
        assert hmac.compare_digest(signature,hmac.new(key,statement.encode(),
                    "sha256").hexdigest()),"FAIL_V197_RESTORED_HMAC"
        pending=root.execute("""SELECT id,org_id,uploaded_by,preview_digest
               FROM jw_dev.import_previews WHERE status='pending'""").fetchall()
        assert len(pending)==1
        pid,org,actor,digest=pending[0]
        assert root.execute("""SELECT count(*) FROM jw_dev.v195_approval_receipts
           WHERE preview_id=%s""",(pid,)).fetchone()==(0,)
    # Reviewer login is confined to a *new* PG17 cluster and must not
    # gain direct status WRITE or secret access after schema restoration.
    with psycopg.connect(reviewer_dsn,connect_timeout=5) as reviewer:
        for q in ("SELECT secret FROM jw_dev.v195_approval_secrets",
                  "UPDATE jw_dev.import_previews SET status='confirmed' WHERE id=%s"):
            try:
                with reviewer.transaction():
                    reviewer.execute(q,(pid,) if "%s" in q else None)
            except errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError("FAIL_V197_RESTORED_REVIEWER_DIRECT_PRIVILEGE")
        payload=json.dumps({"schema":"jw-import-approval-v195",
            "preview_id":pid,"org_id":org,"actor_id":actor,
            "preview_digest":digest,"approved":True,"company":"Customer A",
            "quote_date":"2026-10-31","total_krw":176000},
            ensure_ascii=False,sort_keys=True,separators=(",",":"))
        for i in range(20):
            try:
                with reviewer.transaction():
                    reviewer.execute("""SELECT jw_dev.v195_confirm_import(
                      %s,%s,%s,%s,%s,%s,%s)""",
                      (pid,org,actor,digest,payload,f"{i+1:064x}",
                       secrets.token_hex(16)))
            except errors.InsufficientPrivilege:
                pass
            else:
                raise AssertionError("FAIL_V197_RESTORED_FORGED_APPROVAL")
    with psycopg.connect(dsn) as root:
        assert root.execute("SELECT status FROM jw_dev.import_previews WHERE id=%s",
                    (pid,)).fetchone()==("pending",)
        assert root.execute("SELECT count(*) FROM jw_dev.v195_approval_receipts"
                    ).fetchone()==(1,)
    print("PASS_V197_TWO_CLUSTER_RESTORED_ROLES_AND_TWENTY_FORGED_HMAC_DENIAL",
          flush=True)


def run() -> None:
    if (os.getenv("JW_ENV")!="review" or
        os.getenv("JW_PG_CI_ALLOW")!="ONLY_EPHEMERAL_LOCAL_DATABASE"):
        raise RuntimeError("BLOCKED_V197_NOT_EPHEMERAL_REVIEW")
    source=os.getenv("JW_PG_CI_ROOT_DSN","")
    target=os.getenv("JW_PG_CI_RESTORE_DSN","")
    # Both must be completely EMPTY before any test data is created.
    fresh_guard(source,5432)
    fresh_guard(target,5433)
    source_cid,target_cid=isolated_pair()
    assert source_cid!=target_cid
    live.main()  # Existing real network and PG17 acceptance; source ONLY.
    before=previous.source_fingerprint(source)
    roles=source_users(source)
    src_opts=conninfo_to_dict(source)
    dst_opts=conninfo_to_dict(target)
    snapshot_name="jw_v197_"+secrets.token_hex(5)+".dump"
    source_archive="/tmp/"+snapshot_name
    target_archive="/tmp/"+snapshot_name
    later=secrets.token_hex(16)
    dump_env={**os.environ,"PGPASSWORD":src_opts["password"]}
    restore_env={**os.environ,"PGPASSWORD":dst_opts["password"]}
    with TemporaryDirectory(prefix="jw-v197-cross-cluster-dr-") as workspace:
        private=Path(workspace)/"source.pgdump"
        encrypted=Path(workspace)/"sealed.backup"
        decrypted=Path(workspace)/"restore.pgdump"
        key=Fernet.generate_key()
        cipher=Fernet(key)
        start=time.monotonic()
        try:
            original.run_docker("exec","-e","PGPASSWORD",source_cid,
              "pg_dump","-U","postgres","-h","127.0.0.1","-d","postgres",
              "--schema=jw_dev","--format=custom","--file",source_archive,
              timeout=90,env=dump_env)
            dumped=time.monotonic()
            original.run_docker("cp",source_cid+":"+source_archive,str(private),
                                timeout=20)
            raw=private.read_bytes()
            assert len(raw)>5000 and raw[:5]==b"PGDMP"
            original_sha=sha256(raw).hexdigest()
            encrypted.write_bytes(cipher.encrypt(raw))
            private.unlink()
            original.run_docker("exec",source_cid,"rm","-f",source_archive,timeout=12)
            blob=encrypted.read_bytes()
            bad=bytearray(blob)
            bad[len(bad)//2]^=1
            try:
                cipher.decrypt(bytes(bad))
            except InvalidToken:
                pass
            else:
                raise AssertionError("FAIL_V197_TAMPERED_CIPHERTEXT_ACCEPTED")

            # Commit AFTER backup to witness a real snapshot recovery gap.
            with psycopg.connect(source) as root:
                root.execute("""INSERT INTO jw_dev.import_previews(
                   id,org_id,uploaded_by,file_sha256,normalized_json,
                   preview_digest,status,quote_id)
                   SELECT %s,org_id,uploaded_by,%s,normalized_json,
                     preview_digest,'pending',NULL
                   FROM jw_dev.import_previews
                   WHERE status='confirmed' LIMIT 1""",
                   (later,sha256(secrets.token_bytes(32)).hexdigest()))
            with psycopg.connect(source) as db:
                assert db.execute("SELECT count(*) FROM jw_dev.import_previews "
                  "WHERE id=%s",(later,)).fetchone()==(1,)

            # The second PG17 cluster has independent roles, separate DB
            # storage, and newly generated one-use credentials.
            reviewer_dsn=create_isolated_target_roles(target,roles)
            recovered=cipher.decrypt(blob)
            assert sha256(recovered).hexdigest()==original_sha
            decrypted.write_bytes(recovered)
            original.run_docker("cp",str(decrypted),target_cid+":"+target_archive,
                                timeout=20)
            decrypted.unlink()
            restore_started=time.monotonic()
            original.run_docker("exec","-e","PGPASSWORD",target_cid,
                "pg_restore","-U","postgres","-h","127.0.0.1",
                "--dbname","postgres","--no-owner","--exit-on-error",
                target_archive,timeout=110,env=restore_env)

            # CRITICAL: pg_restore --no-owner leaves SECURITY DEFINER owner
            # postgres. Never use the restored application before rebind.
            with psycopg.connect(target) as root:
                owner=root.execute("""SELECT pg_get_userbyid(proowner)
                   FROM pg_proc WHERE oid=%s::regprocedure""",
                   (previous.DEF_FN,)).fetchone()
                assert owner==("postgres",),("FAIL_V197_EXPECTED_OWNER_DRIFT",owner)
                root.execute(sql.SQL("ALTER FUNCTION {} OWNER TO {}").format(
                    sql.SQL(previous.DEF_FN),
                    sql.Identifier(previous.OWNER)))
                root.execute("REVOKE CREATE ON SCHEMA jw_dev FROM "+
                             previous.OWNER)
            restored=time.monotonic()
            check_restored_boundary(target,before,reviewer_dsn)
            with psycopg.connect(target) as db:
                assert db.execute("SELECT count(*) FROM jw_dev.import_previews "
                  "WHERE id=%s",(later,)).fetchone()==(0,)
            print("PASS_V197_INDEPENDENT_PG17_CLUSTER_ENCRYPTED_BACKUP_AND_OWNER_REBIND",
                  flush=True)
            print("PASS_V197_CIPHERTEXT_TAMPER_REJECT_AND_CROSS_CLUSTER_SIGNATURE",
                  flush=True)
            print("PASS_V197_POST_SNAPSHOT_COMMIT_LOST_RPO_NONZERO",flush=True)
            print("MEASURED_V197_CI_PG_DUMP_SECONDS="+str(round(dumped-start,3)),
                  flush=True)
            print("MEASURED_V197_CI_SECOND_CLUSTER_RESTORE_SECONDS="+
                  str(round(restored-restore_started,3)),flush=True)
            print("LIMIT_V197_SAME_GITHUB_RUNNER_TWO_CONTAINERS_NOT_OFFSITE_HOSTED_DR",
                  flush=True)
        finally:
            for cid,p in ((source_cid,source_archive),
                          (target_cid,target_archive)):
                original.run_docker("exec",cid,"rm","-f",p,timeout=15)
            for path in (private,encrypted,decrypted):
                path.unlink(missing_ok=True)
            print("PASS_V197_EPHEMERAL_ARCHIVE_CLEANUP",flush=True)


if __name__=="__main__":
    run()
