#!/usr/bin/env python3
"""Full isolated PG review factory with auth/business role separation over HTTPS+PG17."""
from __future__ import annotations

import os
import secrets

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from app import pg_cinema_legacy_api_v1 as legacy
from app import pg_auth_v85 as auth
from app import pg_review_integrated_v202 as integrated
from scripts import ci_cinema_pg_https_v223 as https_runner
from scripts import ci_cinema_pg_validated_tls_e2e_v223 as validated

AUTH_ROLE = "jw_ci_v223_tls_auth"


def integrated_build_app():
    validated.prepare()
    password = secrets.token_urlsafe(28)
    with psycopg.connect(dbname="postgres", autocommit=True) as admin:
        admin.execute(sql.SQL(
            "CREATE ROLE {} LOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER "
            "NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD {}"
        ).format(sql.Identifier(AUTH_ROLE), sql.Literal(password)))
        admin.execute(sql.SQL(
            "GRANT jw_auth_stage_v85 TO {} WITH INHERIT FALSE, SET TRUE"
        ).format(sql.Identifier(AUTH_ROLE)))
    business_dsn = os.environ["JW_PG_STAGE_DSN"]
    os.environ.update({
        "JW_PG_AUTH_STAGE_DSN": make_conninfo(business_dsn, user=AUTH_ROLE, password=password),
        "JW_PG_REVIEW_INTEGRATION": "ISOLATED_DEV_PG_REVIEW_INTEGRATION",
        "JW_PG_QUOTE_V92": "ISOLATED_DEV_QUOTE_V92",
        "JW_V223_INTEGRATED_HTTPS": "1",
    })
    actual_auth = os.environ["JW_PG_AUTH_STAGE_DSN"]
    try:
        os.environ["JW_PG_AUTH_STAGE_DSN"] = business_dsn
        try:
            integrated.preflight()
        except RuntimeError as exc:
            if "authentication and business roles must be separated" not in str(exc):
                raise
            print("PASS_V223_INTEGRATED_SHARED_DSN_REJECTED", flush=True)
        else:
            raise AssertionError("FAIL_V223_INTEGRATED_SHARED_DSN_ACCEPTED")
    finally:
        os.environ["JW_PG_AUTH_STAGE_DSN"] = actual_auth

    try:
        os.environ["JW_PG_STAGE_DSN"] = make_conninfo(business_dsn, sslmode="disable")
        try:
            integrated.preflight()
        except RuntimeError as exc:
            if "certificate verification required" not in str(exc):
                raise
            print("PASS_V223_INTEGRATED_INSECURE_TLS_REJECTED", flush=True)
        else:
            raise AssertionError("FAIL_V223_INTEGRATED_INSECURE_TLS_ACCEPTED")
    finally:
        os.environ["JW_PG_STAGE_DSN"] = business_dsn

    integrated.preflight()
    with auth._connect() as conn:
        row = conn.execute(
            "SELECT session_user, s.ssl, "
            "pg_has_role(session_user,'jw_app_dev','MEMBER'), "
            "pg_has_role(session_user,'jw_auth_stage_v85','SET') "
            "FROM pg_stat_ssl s WHERE s.pid=pg_backend_pid()"
        ).fetchone()
        if row != (AUTH_ROLE, True, False, True):
            raise AssertionError("FAIL_V223_INTEGRATED_AUTH_ROLE_TLS_BOUNDARIES")
        print("PASS_V223_INTEGRATED_AUTH_ROLE_SEPARATE_TLS", flush=True)

    # Preserve the integrated factory; supply only the deterministic test clock
    # to the same legacy router seam used in the already-passing V9 E2E.
    original_factory = legacy.create_legacy_router
    def clocked_factory(tx, **kwargs):
        kwargs["today"] = lambda: validated.e2e.Clock.today
        return original_factory(tx, **kwargs)
    legacy.create_legacy_router = clocked_factory
    try:
        app = integrated.create_app()
    finally:
        legacy.create_legacy_router = original_factory
    print("PASS_V223_INTEGRATED_FACTORY_CREATED", flush=True)
    return app


def run() -> int:
    original = validated.real_build_app
    validated.real_build_app = integrated_build_app
    try:
        result = https_runner.run()
        if result == 0:
            print("PASS_V223_INTEGRATED_FACTORY_HTTPS_PG17_74_CASES", flush=True)
        return result
    finally:
        validated.real_build_app = original


if __name__ == "__main__":
    raise SystemExit(run())
