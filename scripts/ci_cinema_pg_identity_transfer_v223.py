#!/usr/bin/env python3
"""V22.3 identity import rehearsal: transactionally stage identities from offline SQLite.

Disposable PG17 only. No deployed write path; real-world migrations require
source freeze, backup/recovery proof, matching encryption keys and fresh login.
"""
from __future__ import annotations
import json
import os
import secrets
import sqlite3
import tempfile
from pathlib import Path

from app.security_hardening import secret_for_user
from cryptography.fernet import Fernet
import psycopg
from scripts import ci_cinema_pg_identity_bridge_v223 as identity
from scripts import ci_cinema_pg_sql_gate as gate

ORG=identity.ORG
CASES=0
class CutoverBlocked(RuntimeError):
    pass

def passed(ok, code):
    global CASES
    CASES+=1
    if not ok:
        raise AssertionError("FAIL_V223_TRANSFER_"+code)
    print("PASS_V223_TRANSFER_"+code, flush=True)

KEYS={
    "organizations": ("id",),
    "users": ("id",),
    "staff_disabled": ("user_id",),
    "mfa_credentials": ("user_id",),
    "mfa_recovery_codes": ("user_id","code_hash"),
    "login_failures": ("email",),
}

def row_scope(table):
    if table=="organizations":
        return "id=?", "id=%s"
    if table in ("users","staff_disabled"):
        return "org_id=?", "org_id=%s"
    if table in ("mfa_credentials","mfa_recovery_codes"):
        return "user_id IN (SELECT id FROM users WHERE org_id=?)", "user_id IN (SELECT id FROM jw_dev.users WHERE org_id=%s)"
    return "lower(email) IN (SELECT lower(email) FROM users WHERE org_id=?)", "lower(email) IN (SELECT lower(email) FROM jw_dev.users WHERE org_id=%s)"

def import_checked(source, pg, fail_after=None):
    # The authenticated, stopped SQLite snapshot MUST have already been backed up.
    src_sessions=source.execute(
        "SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.org_id=?",(ORG,)).fetchone()[0]
    pg_sessions=pg.execute(
        "SELECT count(*) FROM jw_dev.sessions s JOIN jw_dev.users u ON u.id=s.user_id WHERE u.org_id=%s",(ORG,)).fetchone()[0]
    admins=source.execute(
        "SELECT count(*) FROM users u LEFT JOIN staff_disabled d ON d.user_id=u.id "
        "WHERE u.org_id=? AND u.role='admin' AND d.user_id IS NULL",(ORG,)).fetchone()[0]
    if src_sessions or pg_sessions or admins<2:
        raise CutoverBlocked("sessions_or_two_admin_gate")
    source_users=source.execute("SELECT id,org_id,email,password_hash,name,role,created_at FROM users WHERE org_id=?",(ORG,)).fetchall()
    if not source_users or len(source_users)>10000:
        raise CutoverBlocked("user_count_invalid")
    # Never create a mismatched identity or silently replace a password/MFA credential.
    with pg.transaction():
        pg.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        inserted=0
        for table,cols in identity.TABLES.items():
            src_where,_=row_scope(table)
            columns=", ".join(cols)
            source_rows=source.execute(
                f"SELECT {columns} FROM {table} WHERE {src_where}",(ORG,)).fetchall()
            for source_row in source_rows:
                values=tuple(source_row)
                # Password encoding is the exact format accepted by the existing
                # v85 verifier. Never log a credential or a record identifier.
                if table=="mfa_credentials" and values[1]:
                    try:
                        # A copied Fernet ciphertext is not sufficient: the
                        # actual application key must decrypt the TOTP secret.
                        decrypted = secret_for_user(values[1])
                        if not decrypted or len(decrypted)>512:
                            raise ValueError("invalid synthetic TOTP secret")
                    except Exception as exc:
                        raise CutoverBlocked("mfa_key_unavailable") from exc
                if table=="users":
                    encoded=values[3]
                    parts=encoded.split("$") if isinstance(encoded,str) else []
                    if (len(parts)!=4 or parts[0]!="pbkdf2_sha256" or parts[1]!="260000"
                            or len(parts[2])!=32 or len(parts[3])!=64):
                        raise CutoverBlocked("unsupported_password_encoding")
                clauses=" AND ".join(k+"=%s" for k in KEYS[table])
                key_indexes=[cols.index(k) for k in KEYS[table]]
                key_values=tuple(values[i] for i in key_indexes)
                existing=pg.execute(
                    f"SELECT {columns} FROM jw_dev.{table} WHERE {clauses}",key_values).fetchall()
                if len(existing)>1 or (existing and tuple(existing[0])!=values):
                    raise CutoverBlocked("conflicting_existing_identity")
                if existing:
                    continue
                placeholders=", ".join(["%s"]*len(cols))
                pg.execute(f"INSERT INTO jw_dev.{table} ({columns}) VALUES ({placeholders})",values)
                inserted+=1
                if fail_after is not None and inserted>=fail_after:
                    raise CutoverBlocked("simulated_mid_transfer_failure")
        remaining=identity.parity(source,pg,ORG)
        if remaining:
            raise CutoverBlocked("identity_parity_after_import")
    return inserted

def reset_one_org(pg):
    """Fixture preparation only: never invoked outside a throw-away PG17 cluster."""
    for tab in ("login_failures","mfa_recovery_codes","mfa_credentials","staff_disabled"):
        pg.execute(f"DELETE FROM jw_dev.{tab}")
    pg.execute("DELETE FROM jw_dev.users WHERE id IN ('ci-ua2','ci-um')")

def run():
    if os.environ.get("JW_CINEMA_PG_DISPOSABLE")!="1" or os.environ.get("PGHOST") not in ("localhost","127.0.0.1"):
        raise SystemExit("BLOCKED: disposable local PG17 only")
    gate.local_server_or_die()
    dbname="jw_identity_transfer_"+secrets.token_hex(4)
    admin=gate.Psql("postgres")
    if admin.sql("CREATE DATABASE "+dbname).returncode:
        raise SystemExit("BLOCKED: cannot create disposable postgres database")
    try:
        for role in ("jw_app_dev","jw_auth_stage_v85","anon","authenticated","service_role"):
            admin.sql(f"DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$")
        db=gate.Psql(dbname)
        for path in gate.BASE_FILES:
            p=db.file(path)
            if p.returncode:
                raise AssertionError("FAIL_V223_TRANSFER_BASE_SCHEMA")
        with tempfile.TemporaryDirectory(prefix="jw-identity-transfer-") as tmp:
            path=Path(tmp)/"offline-sqlite-copy.db"
            identity.fixture_sqlite(path)
            identity.fixture_pg(dbname)
            sealed=identity.file_hash(path)
            with identity.ro_sqlite(path) as src, psycopg.connect(dbname=dbname,autocommit=True) as pg:
                reset_one_org(pg)
                pg_before=pg.execute("SELECT count(*) FROM jw_dev.users WHERE org_id=%s",(ORG,)).fetchone()[0]
                passed(pg_before==1,"SYNTHETIC_TARGET_HAS_ONLY_ONE_USER")
                passed(bool(identity.parity(src,pg)),"MISSING_IDENTITY_DETECTED")
                try:
                    import_checked(src,pg,fail_after=1)
                except CutoverBlocked as exc:
                    passed(str(exc)=="simulated_mid_transfer_failure","INTERRUPTED_IMPORT_REJECTED")
                else:
                    raise AssertionError("FAIL_V223_TRANSFER_INTERRUPTED_ACCEPTED")
                after=pg.execute("SELECT count(*) FROM jw_dev.users WHERE org_id=%s",(ORG,)).fetchone()[0]
                passed(after==pg_before,"INTERRUPTED_IMPORT_ROLLS_BACK_ALL_ROWS")
                passed(bool(identity.parity(src,pg)),"INTERRUPTED_IMPORT_NOT_FALSLY_CERTIFIED")
                inserted=import_checked(src,pg)
                passed(inserted>=5,"REAL_TRANSACTIONAL_IDENTITY_COPY_PERFORMED")
                passed(not identity.parity(src,pg),"FULL_MFA_RECOVERY_LOCKOUT_PARITY")
                counts_before=[pg.execute(f"SELECT count(*) FROM jw_dev.{table}").fetchone()[0]
                               for table in ("users","mfa_credentials","mfa_recovery_codes","login_failures")]
                passed(import_checked(src,pg)==0,"RETRY_IS_IDEMPOTENT")
                counts_after=[pg.execute(f"SELECT count(*) FROM jw_dev.{table}").fetchone()[0]
                              for table in ("users","mfa_credentials","mfa_recovery_codes","login_failures")]
                passed(counts_before==counts_after,"RETRY_CREATES_NO_DUPLICATES")
                pg.execute("UPDATE jw_dev.mfa_credentials SET secret_encrypted='TAMPERED' WHERE user_id='ci-ua'")
                try:
                    import_checked(src,pg)
                except CutoverBlocked as exc:
                    passed(str(exc)=="conflicting_existing_identity","MFA_TAMPERING_FAIL_CLOSED")
                else:
                    raise AssertionError("FAIL_V223_TRANSFER_MFA_TAMPERING_ACCEPTED")
                finally:
                    pg.execute("UPDATE jw_dev.mfa_credentials SET secret_encrypted=%s WHERE user_id='ci-ua'",
                               (identity.SYNTHETIC_CIPHER,))
                passed(not identity.parity(src,pg),"MFA_RESTORE_EXACT")
                good_key=os.environ["JW_DATA_KEY"]
                os.environ["JW_DATA_KEY"]=Fernet.generate_key().decode("ascii")
                try:
                    try:
                        import_checked(src,pg)
                    except CutoverBlocked as exc:
                        passed(str(exc)=="mfa_key_unavailable","WRONG_MFA_KEY_FAIL_CLOSED")
                    else:
                        raise AssertionError("FAIL_V223_TRANSFER_WRONG_MFA_KEY_ACCEPTED")
                finally:
                    os.environ["JW_DATA_KEY"]=good_key
                passed(not identity.parity(src,pg),"WRONG_KEY_DID_NOT_MUTATE_PG")
                with sqlite3.connect(path) as local:
                    local.execute("INSERT INTO sessions VALUES('fake-token','ci-ua','2099-01-01','csrf','x','2026')")
                    local.commit()
                try:
                    import_checked(src,pg)
                except CutoverBlocked as exc:
                    passed(str(exc)=="sessions_or_two_admin_gate","LEGACY_BEARER_TOKEN_BLOCKED")
                else:
                    raise AssertionError("FAIL_V223_TRANSFER_LEGACY_SESSION_COPIED")
                with sqlite3.connect(path) as local:
                    local.execute("DELETE FROM sessions WHERE token_hash='fake-token'")
                    local.commit()
                passed(not identity.parity(src,pg),"TOKEN_BLOCK_RESTORED")
                passed(pg.execute("SELECT count(*) FROM jw_dev.sessions WHERE user_id IN "
                                  "(SELECT id FROM jw_dev.users WHERE org_id=%s)",(ORG,)).fetchone()[0]==0,
                       "NO_SESSION_TOKENS_MIGRATED")
                current_hash=identity.file_hash(path)
                passed(bool(sealed) and len(sealed)==64 and len(current_hash)==64,"SNAPSHOT_SHA256_AVAILABLE")
                # Actual source database is not accessed. The local synthetic
                # fixture was mutated only for explicit negative cases.
                print("PASS_V223_DISPOSABLE_IDENTITY_TRANSFER",
                      json.dumps({"checks":CASES,"failures":0,"actual_sqlite":False,"actual_supabase":False}),
                      flush=True)
                return 0
    finally:
        admin.sql("DROP DATABASE IF EXISTS "+dbname+" WITH (FORCE)")

if __name__=="__main__":
    raise SystemExit(run())
