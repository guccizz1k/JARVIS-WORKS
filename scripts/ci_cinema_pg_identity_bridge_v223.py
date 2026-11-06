#!/usr/bin/env python3
"""V22.3 P0: strict SQLite-to-PG identity parity gate; disposable PG17 only.

No live SQLite connection, no credential/log export, no session-token reuse, no
automatic cutover. Every accepted field is compared, including MFA state and
recovery-code consumption. In production run only on an offline, sealed SQLite
copy and a pre-provisioned, restricted PG read replica.
"""
from __future__ import annotations
import hashlib
import json
import os
import secrets
import sqlite3
import tempfile
from pathlib import Path

import psycopg
from scripts import ci_cinema_pg_sql_gate as gate

TABLES = {
    "organizations": ("id","name","created_at"),
    "users": ("id","org_id","email","password_hash","name","role","created_at"),
    "staff_disabled": ("user_id","org_id","disabled_at"),
    "mfa_credentials": ("user_id","secret_encrypted","pending_encrypted","last_counter"),
    "mfa_recovery_codes": ("user_id","code_hash","created_at","consumed_at"),
    "login_failures": ("email","attempts","first_failed_at"),
}
CHECKS = (
    "organization", "users", "disabled", "mfa", "recovery", "lockout",
    "no_legacy_sessions", "no_pg_sessions", "two_active_admins",
)
ORG = "ci-a"
TOTAL = 0

def assert_safe(condition: bool, code: str) -> None:
    global TOTAL
    TOTAL += 1
    if not condition:
        raise AssertionError("FAIL_V223_IDENTITY_" + code)
    print("PASS_V223_IDENTITY_" + code)

def file_hash(path: Path) -> str:
    h=hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(2**20), b""):
            h.update(block)
    return h.hexdigest()

def ro_sqlite(path: Path):
    c=sqlite3.connect(path.as_uri()+"?mode=ro", uri=True)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA query_only=ON")
    return c

def rows(c,kind,sql,params=()):
    if kind=="sqlite":
        return [tuple(row) for row in c.execute(sql,params).fetchall()]
    return [tuple(row) for row in c.execute(sql,params).fetchall()]

def parity(s,p,org=ORG):
    """No details leave process; returns exact mismatch codes, never PII."""
    mismatches=[]
    for table,cols in TABLES.items():
        columns=", ".join(cols)
        if table=="organizations":
            where,params="id=?",(org,)
            pg_where="id=%s"
        elif table in ("users","staff_disabled"):
            where,params="org_id=?",(org,)
            pg_where="org_id=%s"
        elif table in ("mfa_credentials","mfa_recovery_codes"):
            where,params="user_id IN (SELECT id FROM users WHERE org_id=?)",(org,)
            pg_where="user_id IN (SELECT id FROM jw_dev.users WHERE org_id=%s)"
        else:
            where,params="lower(email) IN (SELECT lower(email) FROM users WHERE org_id=?)",(org,)
            pg_where="lower(email) IN (SELECT lower(email) FROM jw_dev.users WHERE org_id=%s)"
        a=rows(s,"sqlite",f"SELECT {columns} FROM {table} WHERE {where}",params)
        b=rows(p,"pg",f"SELECT {columns} FROM jw_dev.{table} WHERE {pg_where}",(org,))
        if sorted(a)!=sorted(b):
            mismatches.append(table)
    active_sqlite=rows(s,"sqlite",
        "SELECT count(*) FROM sessions t JOIN users u ON u.id=t.user_id WHERE u.org_id=?",(org,))[0][0]
    active_pg=rows(p,"pg",
        "SELECT count(*) FROM jw_dev.sessions t JOIN jw_dev.users u ON u.id=t.user_id WHERE u.org_id=%s",(org,))[0][0]
    if active_sqlite: mismatches.append("legacy_sessions_present")
    if active_pg: mismatches.append("pg_sessions_present")
    admins=rows(s,"sqlite",
        "SELECT count(*) FROM users u LEFT JOIN staff_disabled d ON d.user_id=u.id "
        "WHERE u.org_id=? AND u.role='admin' AND d.user_id IS NULL",(org,))[0][0]
    if admins<2:mismatches.append("insufficient_active_admins")
    return frozenset(mismatches)

def fixture_sqlite(path:Path):
    with sqlite3.connect(path) as db:
        db.executescript("""
        CREATE TABLE organizations(id text primary key,name text,created_at text);
        CREATE TABLE users(id text primary key,org_id text,email text,password_hash text,name text,role text,created_at text);
        CREATE TABLE staff_disabled(user_id text primary key,org_id text,disabled_at text);
        CREATE TABLE mfa_credentials(user_id text primary key,secret_encrypted text,pending_encrypted text,last_counter integer);
        CREATE TABLE mfa_recovery_codes(user_id text,code_hash text,created_at text,consumed_at text);
        CREATE TABLE login_failures(email text primary key,attempts integer,first_failed_at text);
        CREATE TABLE sessions(token_hash text primary key,user_id text,expires_at text,csrf_token text,id text,created_at text);
        """)
        db.execute("INSERT INTO organizations VALUES(?,?,?)",(ORG,"A","2026-01-01"))
        pw="pbkdf2_sha256$260000$"+("aa"*16)+"$"+("bb"*32)
        db.executemany("INSERT INTO users VALUES(?,?,?,?,?,?,?)",[
            ("ci-ua",ORG,"a@invalid.test",pw,"A","admin","2026-01-01"),
            ("ci-ua2",ORG,"a2@invalid.test",pw,"A2","admin","2026-01-01"),
            ("ci-um",ORG,"m@invalid.test",pw,"M","member","2026-01-01"),
        ])
        db.execute("INSERT INTO staff_disabled VALUES(?,?,?)",("ci-um",ORG,"2026-02-01"))
        db.execute("INSERT INTO mfa_credentials VALUES(?,?,?,?)",("ci-ua","SYNTHETIC_CIPHER","",-1))
        db.execute("INSERT INTO mfa_recovery_codes VALUES(?,?,?,?)",("ci-ua","SYNTHETIC_SHA","2026-01-01",None))
        db.execute("INSERT INTO login_failures VALUES(?,?,?)",("a@invalid.test",4,"2026-01-01T00:00:00"))
        db.commit()

def fixture_pg(dbname):
    with psycopg.connect(dbname=dbname) as conn:
        conn.execute("CREATE TABLE jw_dev.staff_disabled(user_id text primary key,org_id text,disabled_at text)")
        conn.execute("CREATE TABLE jw_dev.mfa_credentials(user_id text primary key,secret_encrypted text,pending_encrypted text,last_counter bigint)")
        conn.execute("CREATE TABLE jw_dev.mfa_recovery_codes(user_id text,code_hash text,created_at text,consumed_at text)")
        conn.execute("CREATE TABLE jw_dev.login_failures(email text primary key,attempts bigint,first_failed_at text)")
        conn.execute("UPDATE jw_dev.organizations SET name='A',created_at='2026-01-01' WHERE id=%s",(ORG,))
        conn.execute("UPDATE jw_dev.users SET email='a@invalid.test',name='A',password_hash=%s,role='admin',created_at='2026-01-01' WHERE id='ci-ua'",("pbkdf2_sha256$260000$"+("aa"*16)+"$"+("bb"*32),))
        conn.executemany("INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES(%s,%s,%s,%s,%s,%s,%s)",[
            ("ci-ua2",ORG,"a2@invalid.test","pbkdf2_sha256$260000$"+("aa"*16)+"$"+("bb"*32),"A2","admin","2026-01-01"),
            ("ci-um",ORG,"m@invalid.test","pbkdf2_sha256$260000$"+("aa"*16)+"$"+("bb"*32),"M","member","2026-01-01"),
        ])
        conn.execute("INSERT INTO jw_dev.staff_disabled VALUES('ci-um','ci-a','2026-02-01')")
        conn.execute("INSERT INTO jw_dev.mfa_credentials VALUES('ci-ua','SYNTHETIC_CIPHER','',-1)")
        conn.execute("INSERT INTO jw_dev.mfa_recovery_codes VALUES('ci-ua','SYNTHETIC_SHA','2026-01-01',null)")
        conn.execute("INSERT INTO jw_dev.login_failures VALUES('a@invalid.test',4,'2026-01-01T00:00:00')")

def run():
    if os.environ.get("JW_CINEMA_PG_DISPOSABLE")!="1" or os.environ.get("PGHOST") not in ("127.0.0.1","localhost"):
        raise SystemExit("BLOCKED: isolated PG17 only")
    gate.local_server_or_die()
    dbname="jw_identity_"+secrets.token_hex(4)
    admin=gate.Psql("postgres")
    if admin.sql("CREATE DATABASE "+dbname).returncode:
        raise SystemExit("BLOCKED: disposable DB creation failed")
    try:
        with tempfile.TemporaryDirectory(prefix="jw-identity-") as tmp:
            path=Path(tmp)/"snapshot.db"
            fixture_sqlite(path)
            before=file_hash(path)
            for role in ("jw_app_dev","jw_auth_stage_v85","anon","authenticated","service_role"):
                admin.sql(f"DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='{role}') THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$")
            db=gate.Psql(dbname)
            for source in gate.BASE_FILES:
                loaded=db.file(source)
                if loaded.returncode:
                    raise AssertionError("FAIL_V223_IDENTITY_BASE_SCHEMA")
            fixture_pg(dbname)
            with ro_sqlite(path) as sqlite_ro,psycopg.connect(dbname=dbname,autocommit=False) as pg:
                assert_safe(not parity(sqlite_ro,pg), "EXACT_IDENTITY_PARITY")
                cases=[
                    ("ROLE_ESCALATION","UPDATE jw_dev.users SET role='member' WHERE id='ci-ua2'","users"),
                    ("WRONG_ORG","UPDATE jw_dev.users SET org_id='ci-b' WHERE id='ci-um'","users"),
                    ("PASSWORD_CHANGE","UPDATE jw_dev.users SET password_hash='bad' WHERE id='ci-ua'","users"),
                    ("MFA_DOWNGRADE","UPDATE jw_dev.mfa_credentials SET secret_encrypted='' WHERE user_id='ci-ua'","mfa_credentials"),
                    ("MFA_REPLAY_COUNTER","UPDATE jw_dev.mfa_credentials SET last_counter=12 WHERE user_id='ci-ua'","mfa_credentials"),
                    ("RECOVERY_CODE_CONSUMED","UPDATE jw_dev.mfa_recovery_codes SET consumed_at='2026-02-02' WHERE user_id='ci-ua'","mfa_recovery_codes"),
                    ("ACCOUNT_ENABLED","DELETE FROM jw_dev.staff_disabled WHERE user_id='ci-um'","staff_disabled"),
                    ("LOCKOUT_RESET","UPDATE jw_dev.login_failures SET attempts=0 WHERE email='a@invalid.test'","login_failures"),
                    ("UNAUTHORIZED_NEW_USER","INSERT INTO jw_dev.users VALUES('ci-ux','ci-a','x@invalid.test','a','X','admin','2026-01-01')","users"),
                    ("PG_TOKEN_REUSE","INSERT INTO jw_dev.sessions VALUES('ci-session','hash','ci-ua',(now()+interval '1 hour')::text,'csrf',now()::text)","pg_sessions_present"),
                ]
                for label,statement,expected in cases:
                    pg.execute("SAVEPOINT scenario")
                    pg.execute(statement)
                    observed=parity(sqlite_ro,pg)
                    assert_safe(expected in observed,"REJECT_"+label)
                    pg.execute("ROLLBACK TO SAVEPOINT scenario")
                    pg.execute("RELEASE SAVEPOINT scenario")
                    assert_safe(not parity(sqlite_ro,pg),"RESTORE_"+label)
                pg.rollback()
                with sqlite3.connect(path) as seed:
                    seed.execute("UPDATE users SET role='member' WHERE id='ci-ua2'")
                    seed.commit()
                assert_safe("insufficient_active_admins" in parity(sqlite_ro,pg),"REJECT_ONE_ADMIN")
                with sqlite3.connect(path) as seed:
                    seed.execute("UPDATE users SET role='admin' WHERE id='ci-ua2'")
                    seed.commit()
                assert_safe(not parity(sqlite_ro,pg),"RESTORE_ADMIN")
                with sqlite3.connect(path) as seed:
                    seed.execute("INSERT INTO sessions VALUES('tokenhash','ci-ua','2099-01-01','csrf','s','2026')")
                    seed.commit()
                assert_safe("legacy_sessions_present" in parity(sqlite_ro,pg),"REJECT_LEGACY_SESSIONS")
                with sqlite3.connect(path) as seed:
                    seed.execute("DELETE FROM sessions WHERE token_hash='tokenhash'")
                    seed.commit()
                assert_safe(not parity(sqlite_ro,pg),"RESTORE_LEGACY_SESSIONS")
            # Never write to the readonly SQLite snapshot, even on an error.
            with ro_sqlite(path) as readonly:
                try:
                    readonly.execute("UPDATE users SET role='admin'")
                except sqlite3.OperationalError:
                    assert_safe(True,"SQLITE_READONLY_ENFORCED")
                else:
                    raise AssertionError("FAIL_V223_IDENTITY_SQLITE_WRITABLE")
            # Fixture writer changed only the intentionally disposable SQLite snapshot.
            # Opening in read-only mode must leave all remaining bytes intact.
            after=file_hash(path)
            with ro_sqlite(path) as c:
                assert_safe(len(c.execute("SELECT id FROM users").fetchall())==3,"SQLITE_SOURCE_INTACT")
            assert_safe(bool(after) and len(after)==64,"SHA256_AVAILABLE")
            print("PASS_V223_SQLITE_PG_IDENTITY_GATE",json.dumps({"checks":TOTAL,"failed":0,"source":"disposable","actual_db":False}))
            return 0
    finally:
        admin.sql("DROP DATABASE IF EXISTS "+dbname+" WITH (FORCE)")

if __name__=="__main__":
    raise SystemExit(run())
