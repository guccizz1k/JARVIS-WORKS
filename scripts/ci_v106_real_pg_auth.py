"""Actual isolated PG17 V8.5 auth bootstrap after existing 13-table restore proof.

Runs only on the fresh 127.0.0.1 GitHub postgres:17 service. Never on Render,
Supabase or persistent databases. Dedicated NOINHERIT auth login, distinct
from restricted trade login; real V8.5 migration SQL, no fake auth DB driver.
"""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from app import pg_auth_v85 as auth

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "CI-v106-disposable-auth-password-only"
LOGIN = "jw_ci_auth_v106"


def _pbkdf2(raw: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", raw.encode("utf-8"), salt, 260_000)
    return "pbkdf2_sha256$260000$" + salt.hex() + "$" + digest.hex()


def prepare_real_auth(fixture) -> None:
    if (os.environ.get("JW_PG_CI_ALLOW") != "ONLY_EPHEMERAL_LOCAL_DATABASE"
        or os.environ.get("JW_ENV") != "dev"
        or os.environ.get("JW_V93_TRUST_LOCAL_CA") != "EPHEMERAL_RUNNER_ONLY"):
        raise RuntimeError("Refusing non-ephemeral V10.6 auth fixture")
    parts = conninfo_to_dict(fixture.root_dsn)
    if (parts.get("host") != "127.0.0.1"
        or parts.get("dbname") != "postgres"
        or parts.get("user") != "postgres"):
        raise RuntimeError("Refusing non-local PostgreSQL auth bootstrap")
    if not fixture.TRADE_DSN:
        raise RuntimeError("Existing restricted trade login is absent")
    secret = secrets.token_urlsafe(38)
    with psycopg.connect(fixture.root_dsn, autocommit=True) as pg:
        assert int(pg.execute("SHOW server_version_num").fetchone()[0]) // 10000 == 17
        for path in ("scripts/ci_v106_auth_support.sql", "migrations/v85_auth_stage.sql"):
            pg.execute((ROOT / path).read_text())
        pg.execute(sql.SQL(
            "CREATE ROLE {} LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER "
            "NOCREATEDB NOCREATEROLE PASSWORD {}"
        ).format(sql.Identifier(LOGIN), sql.Literal(secret)))
        pg.execute(sql.SQL(
            "GRANT jw_auth_stage_v85 TO {} WITH INHERIT FALSE, SET TRUE"
        ).format(sql.Identifier(LOGIN)))
        for who in ("ci-ua", "ci-ub", "ci-uc"):
            pg.execute("UPDATE jw_dev.users SET password_hash=%s WHERE id=%s",
                       (_pbkdf2(PASSWORD), who))
        # The auth role is permitted to run auth RPCs, but can never adopt the
        # trading role. The reverse property is verified in the existing CI.
    auth_dsn = make_conninfo(fixture.root_dsn, user=LOGIN, password=secret)
    auth._connect = lambda: psycopg.connect(auth_dsn, connect_timeout=5)
    with psycopg.connect(auth_dsn) as conn:
        role = conn.execute("""
           SELECT session_user, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb,
                  pg_has_role(session_user,'jw_app_dev','MEMBER'),
                  pg_has_role(session_user,'jw_auth_stage_v85','MEMBER')
           FROM pg_roles WHERE rolname=session_user
        """).fetchone()
        if role != (LOGIN,False,False,False,False,False,True):
            raise AssertionError("Cross-role or privileged auth login")
    print("PASS: actual independent NOINHERIT PostgreSQL17 auth login, "
          "V8.5 RLS auth SQL loaded on disposable DB", flush=True)
