#!/usr/bin/env python3
"""Independent local PG17 restore and signature verification for Windows encrypted export.

The Supabase SOURCE is never contacted. Decrypted data exists only temporarily
inside a private directory. All SQL writes target a marked, disposable local
PG17 database. No original local DB is overwritten. Never echo private inputs.
"""
from __future__ import annotations
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.ci_cinema_pg_m import read_private_target
from scripts.pg_backup_v223 import (
    BackupError, decrypt_file, diff_signatures, fetch_signature,
    parse_dsn, signature_digest, verify_ephemeral_target,
    write_negative_cipher_copy, write_partial_restore_copy,
)

ROOT=Path(__file__).resolve().parents[1]
STAGING=ROOT/"jw-private-transfer"
PRIVATE=Path.home()/".local/share/jw-v223-restore/real-backup-input"
PROJECT="rvymwwzclagvljnofyss"
SCHEMA="jw_dev"
FINGERPRINT="afd89e64e80ecbc8216af114e0682ee7"
# Independently confirmed in the live DEV catalog (read-only, 2026-11-07).
# Windows exporter v1 inventories table ACL and policy grantees, but excludes
# schema and function ACL grantees. pg_dump includes those GRANTs regardless.
# Only locally created NOLOGIN placeholder roles are permitted on the disposable
# restore cluster; the source Supabase role definitions are NEVER modified.
SOURCE_VERIFIED_SCHEMA_FUNCTION_ONLY_GRANTEES = (
    "jw_auth_stage_v85",
    "jw_dev_import_review_executor_v201",
)

ARCHIVE_RE=re.compile(r"\d{8}-\d{6}Z-[0-9a-f]{6}\.jwpgbk\Z")
ROLE_RE=re.compile(r"[a-z][a-z0-9_]{0,62}\Z")

def sha256(path):
    h=hashlib.sha256()
    with open(path,"rb") as f:
        while chunk:=f.read(1<<20):
            h.update(chunk)
    return h.hexdigest()

def find_input(directory=None):
    directory=STAGING if directory is None else Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise BackupError("BLOCKED_ARCHIVE_DIRECTORY_MISSING")
    found=[p for p in directory.iterdir() if p.is_file() and
           not p.is_symlink() and ARCHIVE_RE.fullmatch(p.name)]
    if len(found)!=1:
        raise BackupError("BLOCKED_EXPECT_EXACTLY_ONE_ARCHIVE")
    a=found[0]
    label=a.name.removesuffix(".jwpgbk")
    m=directory/(label+".manifest.jwpgbk")
    k=directory/(label+".key")
    if any(not p.is_file() or p.is_symlink() for p in (a,m,k)):
        raise BackupError("BLOCKED_MATCHING_MANIFEST_OR_KEY_MISSING")
    if not 40<a.stat().st_size<1<<30 or not 40<m.stat().st_size<1<<24 or k.stat().st_size>256:
        raise BackupError("BLOCKED_ENCRYPTED_FILE_SIZE_INVALID")
    return a,m,k

def private_transfer(files):
    """Copies three ignored files into HOME, then erases the staged copies."""
    for p in files:
        rel=p.relative_to(ROOT)
        a=subprocess.run(["git","check-ignore","-q","--",str(rel)],
                         cwd=ROOT,capture_output=True,timeout=5)
        b=subprocess.run(["git","ls-files","--error-unmatch","--",str(rel)],
                         cwd=ROOT,capture_output=True,timeout=5)
        if a.returncode!=0 or b.returncode==0:
            raise BackupError("BLOCKED_STAGING_IS_GIT_TRACKABLE")
    if PRIVATE.is_symlink():
        raise BackupError("BLOCKED_PRIVATE_DIRECTORY_SYMLINK")
    os.umask(0o077)
    PRIVATE.mkdir(parents=True,exist_ok=True,mode=0o700)
    PRIVATE.chmod(0o700)
    dest=[PRIVATE/p.name for p in files]
    if any(p.exists() or p.is_symlink() for p in dest):
        raise BackupError("BLOCKED_FILES_ALREADY_IMPORTED")
    for a,b in zip(files,dest):
        with a.open("rb") as src,b.open("xb") as out:
            shutil.copyfileobj(src,out,1<<20)
            out.flush()
            os.fsync(out.fileno())
        b.chmod(0o600)
        if sha256(a)!=sha256(b):
            raise BackupError("BLOCKED_FILE_TRANSFER_CHECKSUM")
        a.unlink()
    return dest

def find_or_import_archive():
    """Keep authenticated backups reusable after a failed restore attempt.

    First intake: verify staged paths are git-ignored, then copy into protected
    HOME. Later invocations reuse ONLY the matching complete private triplet;
    they never require re-uploading the user's encrypted source backup.
    """
    try:
        return private_transfer(find_input())
    except BackupError as exc:
        # Only the absence of a *staged archive* permits a private-file retry.
        # A partial or invalid staged archive must fail closed instead.
        if str(exc)!="BLOCKED_EXPECT_EXACTLY_ONE_ARCHIVE":
            raise
        if STAGING.is_dir() and any(p.name.endswith(".jwpgbk") or
                                     p.name.endswith(".key") for p in STAGING.iterdir()):
            raise BackupError("BLOCKED_STAGING_PARTIAL_ARCHIVE")
        return find_input(PRIVATE)


def read_key(path):
    if path.is_symlink() or (path.stat().st_mode & 0o077):
        raise BackupError("BLOCKED_KEY_FILE_PERMISSIONS")
    k=base64.urlsafe_b64decode(path.read_text("ascii").strip())
    if len(k)!=32:
        raise BackupError("BLOCKED_AES256_KEY_LENGTH")
    return k

def check_manifest(m,encrypted):
    if (m.get("real_source") is not True or m.get("project_ref")!=PROJECT or
        m.get("schema")!=SCHEMA or m.get("source_fingerprint")!=FINGERPRINT or
        m.get("snapshot_consistent") is not True or
        m.get("source_backup_verdict")!="EXPORT_ONLY_NOT_DR_PASS" or
        m.get("tables")!=62 or m.get("table_row_total")!=22 or
        m.get("server_major")!=17):
        raise BackupError("BLOCKED_SOURCE_MANIFEST_IDENTITY")
    if m.get("cipher_sha256")!=sha256(encrypted) or not re.fullmatch(
            r"[0-9a-f]{64}",str(m.get("plain_sha256",""))):
        raise BackupError("BLOCKED_MANIFEST_ARCHIVE_DIGEST")
    sig=m.get("signature")
    if (not isinstance(sig,dict) or sig.get("schema")!=SCHEMA or
        len(sig.get("tables",[]))!=62 or
        sum(int(v[0]) for v in sig.get("rows",{}).values())!=22):
        raise BackupError("BLOCKED_MANIFEST_SIGNATURE_COUNTS")
    roles=m.get("roles")
    if (not isinstance(roles,list) or len(roles)>64 or
        len(set(roles))!=len(roles) or
        any(not isinstance(r,str) or not ROLE_RE.fullmatch(r) or
            r.startswith("pg_") for r in roles)):
        raise BackupError("BLOCKED_MANIFEST_ROLE_NAMES")
    return roles

def run_pg(args,dsn,db="postgres",seconds=120):
    d=parse_dsn(dsn)
    env=dict(os.environ)
    env.update(PGHOST="127.0.0.1",PGPORT="55432",PGUSER="postgres",
               PGPASSWORD=d["password"],PGDATABASE=db,PGSSLMODE="disable",
               PGCONNECT_TIMEOUT="6")
    try:
        p=subprocess.run(args,env=env,capture_output=True,text=True,
                         check=False,timeout=seconds)
        return p.returncode==0
    except (OSError,subprocess.TimeoutExpired):
        return False

def run_restore_with_reason(args,dsn,db,seconds):
    """pg_restore only: report a fixed error class, never SQL/error contents."""
    if not args or args[0]!="pg_restore" or "--exit-on-error" not in args:
        raise BackupError("BLOCKED_RESTORE_COMMAND_GUARD")
    d=parse_dsn(dsn)
    env=dict(os.environ)
    env.update(PGHOST="127.0.0.1",PGPORT="55432",PGUSER="postgres",
               PGPASSWORD=d["password"],PGDATABASE=db,PGSSLMODE="disable",
               PGCONNECT_TIMEOUT="6")
    try:
        p=subprocess.run(args,env=env,capture_output=True,text=True,
                         check=False,timeout=seconds)
    except subprocess.TimeoutExpired:
        return "TIMEOUT"
    except OSError:
        return "CLIENT_UNAVAILABLE"
    if p.returncode==0:
        return "PASS"
    error=p.stderr.lower()
    if "role " in error and "does not exist" in error:
        return "MISSING_GRANTEE_ROLE"
    if "permission denied" in error:
        return "PERMISSION_DENIED"
    if "extension " in error and "does not exist" in error:
        return "EXTENSION_MISSING"
    if "function " in error and "does not exist" in error:
        return "FUNCTION_DEPENDENCY_MISSING"
    if "relation " in error and "does not exist" in error:
        return "RELATION_DEPENDENCY_MISSING"
    if "already exists" in error:
        return "UNEXPECTED_TARGET_OBJECT_EXISTS"
    return "OTHER_PG_RESTORE_ERROR"


def negatives(archive,key,wd):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    out={}
    for label,kind in (("tamper_rejected","tamper"),
                       ("truncation_rejected","truncation")):
        p=wd/(label+".jwpgbk")
        write_negative_cipher_copy(archive,p,kind)
        try:
            decrypt_file(p,wd/(label+".dump"),key)
            out[label]=False
        except BackupError:
            out[label]=True
    try:
        decrypt_file(archive,wd/"wrong_key.dump",AESGCM.generate_key(256))
        out["wrong_key_rejected"]=False
    except BackupError:
        out["wrong_key_rejected"]=True
    return out

def inspect_disposable_container():
    """Verify identity of pre-existing local PG17 before allowing docker start.

    Never create a container, replace credentials, or start any unexpected DB.
    docker inspect returns sensitive env vars, so parse entirely in-process.
    """
    from scripts.ci_cinema_pg_r import CONTAINER
    try:
        p=subprocess.run(["docker", "container", "inspect", CONTAINER],
                         capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise BackupError("BLOCKED_LOCAL_DOCKER_UNAVAILABLE") from None
    if p.returncode or not p.stdout:
        raise BackupError("BLOCKED_LOCAL_CONTAINER_NOT_FOUND")
    try:
        obj=json.loads(p.stdout)
        if not isinstance(obj,list) or len(obj)!=1:
            raise ValueError()
        c=obj[0]
        cfg=c["Config"]
        host=c["HostConfig"]
        state=c["State"]
        bindings=host["PortBindings"]["5432/tcp"]
        if (c["Name"]!="/"+CONTAINER or cfg["Image"]!="postgres:17" or
            host.get("Privileged") is not False or
            host.get("NetworkMode")!="default" and host.get("NetworkMode")!="bridge" or
            host.get("RestartPolicy",{}).get("Name")!="no" or
            len(bindings)!=1 or bindings[0].get("HostIp")!="127.0.0.1" or
            str(bindings[0].get("HostPort"))!="55432" or
            any(m.get("Type")=="bind" for m in c.get("Mounts",[]))):
            raise ValueError()
        return bool(state["Running"])
    except (KeyError,TypeError,ValueError,IndexError):
        raise BackupError("BLOCKED_LOCAL_CONTAINER_IDENTITY_UNVERIFIED") from None


def ensure_local_target(dsn: str, token: str) -> str:
    """Reconnect, or safely restart only the known stopped disposable container."""
    import psycopg
    try:
        with psycopg.connect(dsn,autocommit=True,connect_timeout=5) as conn:
            verify_ephemeral_target(conn,token)
        return "RUNNING_MARKER_VERIFIED"
    except psycopg.OperationalError:
        # Transport failure only. A live but mismarked target is NOT restarted.
        pass
    running=inspect_disposable_container()
    if running:
        raise BackupError("BLOCKED_RUNNING_LOCAL_DB_UNREACHABLE")
    try:
        p=subprocess.run(["docker","start","jw-v223-restore"],
                         capture_output=True,text=True,timeout=25,check=False)
    except (OSError,subprocess.TimeoutExpired):
        raise BackupError("BLOCKED_LOCAL_CONTAINER_RESTART_FAILED") from None
    if p.returncode:
        raise BackupError("BLOCKED_LOCAL_CONTAINER_RESTART_FAILED")
    import time
    for _ in range(12):
        try:
            with psycopg.connect(dsn,autocommit=True,connect_timeout=2) as conn:
                verify_ephemeral_target(conn,token)
            return "RESTARTED_MARKER_VERIFIED"
        except psycopg.OperationalError:
            time.sleep(1)
    raise BackupError("BLOCKED_LOCAL_DB_UNREACHABLE_AFTER_RESTART")


def verify_restore():
    if os.environ.get("CODESPACES")!="true" or Path.cwd().resolve()!=ROOT.resolve():
        raise BackupError("BLOCKED_APPROVED_CODESPACE_REQUIRED")
    import psycopg
    from psycopg import sql
    config=read_private_target()
    dsn=config["JW_PG_TARGET_ADMIN_DSN"]
    token=config["JW_PG_TARGET_EPHEMERAL_TOKEN"]
    # PROVE the disposable target is real before any private file transfer.
    # If Codespaces suspended Docker, only the exact previously-approved
    # stopped container may be restarted; never initialize another database.
    target_status=ensure_local_target(dsn,token)
    print("LOCAL_RESTORE_TARGET="+target_status)
    files=find_or_import_archive()
    archive,manifest,keyfile=files
    key=read_key(keyfile)
    db="jw_v223_"+secrets.token_hex(5)
    with tempfile.TemporaryDirectory(prefix="jw_restore_",dir=PRIVATE) as tmp:
        work=Path(tmp)
        manifest_plain=work/"manifest.json"
        decrypt_file(manifest,manifest_plain,key)
        m=json.loads(manifest_plain.read_text("utf-8"))
        roles=check_manifest(m,archive)
        plaintext=work/"backup.dump"
        if decrypt_file(archive,plaintext,key)!=m["plain_sha256"]:
            raise BackupError("BLOCKED_PLAIN_DUMP_DIGEST_MISMATCH")
        neg=negatives(archive,key,work)
        if not all(neg.values()) or not run_pg(["pg_restore","--list",str(plaintext)],dsn,seconds=30):
            raise BackupError("BLOCKED_CIPHER_NEGATIVE_OR_ARCHIVE_CHECK")
        if not run_pg(["pg_restore","--version"],dsn,seconds=10):
            raise BackupError("BLOCKED_PG_RESTORE_MISSING")
        created=False
        try:
            with psycopg.connect(dsn,autocommit=True,connect_timeout=6) as c:
                verify_ephemeral_target(c,token)
                # The source manifest misses two schema/function-only grantees.
                # Without them, pg_restore aborts when replaying source GRANTs.
                all_roles=sorted(set(roles)|set(SOURCE_VERIFIED_SCHEMA_FUNCTION_ONLY_GRANTEES))
                for role in all_roles:
                    attributes=c.execute(
                        "SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,"
                        "rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s",
                        (role,)).fetchone()
                    if attributes is None:
                        if role=="postgres":
                            raise BackupError("BLOCKED_LOCAL_POSTGRES_ADMIN_MISSING")
                        c.execute(sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role)))
                    elif role!="postgres" and any(attributes):
                        raise BackupError("BLOCKED_LOCAL_GRANTEE_ROLE_NOT_RESTRICTED")
                c.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(db)))
                created=True
            # Mirror the source's non-business pgcrypto dependency in the
            # DISPOSABLE restore DB only. The source has pgcrypto in extensions.
            with psycopg.connect(dsn,dbname=db,connect_timeout=6,autocommit=True) as c:
                c.execute("CREATE SCHEMA IF NOT EXISTS extensions")
                c.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA extensions")
            restore_status=run_restore_with_reason(
                ["pg_restore","--exit-on-error","--dbname",db,str(plaintext)],
                dsn,db=db,seconds=360)
            if restore_status!="PASS":
                raise BackupError("BLOCKED_INDEPENDENT_RESTORE_"+restore_status)
            with psycopg.connect(dsn,dbname=db,connect_timeout=6) as c:
                actual=fetch_signature(c,SCHEMA)
            mismatch=diff_signatures(m["signature"],actual)
            count=sum(int(r[0]) for r in actual.get("rows",{}).values())
            truncated=work/"truncated.dump"
            write_partial_restore_copy(plaintext,truncated)
            bad_db=db+"_truncated"
            with psycopg.connect(dsn,autocommit=True,connect_timeout=6) as c:
                c.execute(sql.SQL("CREATE DATABASE {} TEMPLATE template0").format(sql.Identifier(bad_db)))
            try:
                neg["partial_dump_restore_rejected"]=not run_pg(
                    ["pg_restore","--exit-on-error","--dbname",bad_db,str(truncated)],
                    dsn,db=bad_db,seconds=90)
            finally:
                with psycopg.connect(dsn,autocommit=True,connect_timeout=6) as c:
                    c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(bad_db)))
            passed=(len(actual.get("tables",[]))==62 and count==22 and
                    not mismatch and all(neg.values()))
            report={"verdict":"PASS" if passed else "FAIL",
                    "source_real":True,"verified_disposable_pg17":True,
                    "encrypted_archive_sha256":sha256(archive),
                    "schema_fingerprint":FINGERPRINT,
                    "source_signature_sha256":signature_digest(m["signature"]),
                    "restore_signature_sha256":signature_digest(actual),
                    "table_count":len(actual.get("tables",[])),"row_count":count,
                    "mismatch_count":len(mismatch),"mismatch_labels":mismatch[:60],
                    "negative_tests":neg}
            evidence=PRIVATE/(archive.name.removesuffix(".jwpgbk")+".restore-report.json")
            if evidence.is_symlink():
                raise BackupError("BLOCKED_RESTORE_REPORT_SYMLINK")
            if evidence.exists():
                # Never silently overwrite an earlier verdict. Identical, verified
                # reruns are safe, but altered/mismatched evidence is a hard block.
                try:
                    old=json.loads(evidence.read_text(encoding="utf-8"))
                except (OSError,ValueError,TypeError):
                    raise BackupError("BLOCKED_RESTORE_REPORT_INVALID") from None
                if old!=report:
                    raise BackupError("BLOCKED_RESTORE_REPORT_CONFLICT")
                print("REUSED_IDENTICAL_PRIVATE_REPORT=PASS")
            else:
                with evidence.open("x",encoding="utf-8") as f:
                    json.dump(report,f,sort_keys=True,indent=2)
                evidence.chmod(0o600)
            for name in ("verdict","table_count","row_count","mismatch_count","negative_tests"):
                print(name.upper()+"="+str(report[name]))
            print("LOCAL_REPORT_PRIVATE=PASS")
            print("SOURCE_DB_NEVER_CONTACTED=PASS")
            return 0 if passed else 2
        finally:
            if created:
                with psycopg.connect(dsn,autocommit=True,connect_timeout=6) as c:
                    c.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(db)))

def main():
    try:
        return verify_restore()
    except Exception as err:
        code=str(err) if isinstance(err,BackupError) else type(err).__name__
        if not re.fullmatch(r"(?:BLOCKED|FAIL)_[A-Z0-9_]+",code):
            code="UNEXPECTED_"+type(err).__name__
        print("DR_RESTORE_STATUS=BLOCKED_OR_FAILED")
        print("REASON="+code)
        print("SOURCE_DB_NEVER_CONTACTED=PASS")
        return 2

if __name__=="__main__":
    sys.exit(main())
