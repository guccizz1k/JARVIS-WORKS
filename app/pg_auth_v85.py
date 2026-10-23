"""V8.5 isolated, default-off PostgreSQL-native auth stage.

Requires a separate dedicated login allowed to SET ROLE jw_auth_stage_v85;
never use it for the V8.4 reader or expose it through the Supabase Data API.
There is no SQLite-to-PG session fallback, login sync or production cutover.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, HTTPException, Response, Request
from pydantic import BaseModel, ConfigDict, Field

from .security_hardening import match_totp, recovery_hash, secret_for_user

AUTH_PREFIX = '/api/pg-stage/v85'
COOKIE = '__Host-jw_session'
FAKE_HASH = 'pbkdf2_sha256$260000$' + ('a1' * 16) + '$' + ('a2' * 32)


class LoginPayload(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=1000)
    otp: str | None = Field(default=None, pattern=r'^\d{6}$')
    recovery_code: str | None = Field(default=None, pattern=r'^[a-fA-F0-9]{32}$')


def auth_stage_enabled() -> bool:
    return (os.getenv('JW_PG_AUTH_V85') == 'ISOLATED_DEV_AUTH_ONLY'
            and os.getenv('JW_ENV', '').lower() not in {'prod', 'production'}
            and os.getenv('JW_INSECURE_LOCAL_DEV') != '1')


def verify_legacy_pbkdf2(password: str, encoded: str) -> bool:
    """Match legacy 260k PBKDF2 SHA-256, reject unsupported parameters."""
    try:
        algo, rounds, salt, digest = encoded.split('$')
        if (algo != 'pbkdf2_sha256' or rounds != '260000'
                or len(salt) != 32 or len(digest) != 64):
            return False
        decoded_salt = bytes.fromhex(salt)
        decoded_digest = bytes.fromhex(digest)
        computed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), decoded_salt, 260_000)
        return hmac.compare_digest(computed, decoded_digest)
    except (TypeError, ValueError, UnicodeError):
        return False


def _connect():
    if not auth_stage_enabled():
        raise RuntimeError('PostgreSQL auth staging is disabled')
    dsn = os.getenv('JW_PG_AUTH_STAGE_DSN', '')
    if not dsn:
        raise RuntimeError('PostgreSQL auth-stage DSN missing')
    # Keep this connection entirely separate from the trading reader DSN.
    if dsn == os.getenv('JW_PG_STAGE_DSN', None):
        raise RuntimeError('Auth-stage login must be separate from the app-reader login')
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError('Install psycopg stage dependency') from exc
    return psycopg.connect(dsn, connect_timeout=5, sslmode='verify-full')


@contextmanager
def _auth_cursor():
    with _connect() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute('''SELECT session_user, r.rolsuper, r.rolbypassrls,
                          r.rolcreaterole, r.rolcreatedb
                          FROM pg_catalog.pg_roles r WHERE r.rolname=session_user''')
                login = cur.fetchone()
                if (not login or login[0] in ('postgres', 'supabase_admin', 'service_role', 'jw_app_dev')
                        or any(login[1:])):
                    raise HTTPException(503, 'Unsafe PostgreSQL auth login')
                # Auth login must not be able to adopt the trading role.
                # Prevent one stolen credential from becoming both auth + data.
                cur.execute("SELECT pg_catalog.pg_has_role(session_user,'jw_app_dev','SET')")
                if cur.fetchone() != (False,):
                    raise HTTPException(503, 'Auth login has unsafe trading-role membership')
                cur.execute('SET LOCAL ROLE jw_auth_stage_v85')
                cur.execute('SELECT current_user')
                if cur.fetchone() != ('jw_auth_stage_v85',):
                    raise HTTPException(503, 'Auth-stage role delegation failed')
                yield cur


def login_session(payload: LoginPayload) -> tuple[str, str, str]:
    """Password, lockout, MFA replay and session insertion are one transaction.

    `v85_auth_candidate` obtains a user row lock until commit, so simultaneous
    authentication attempts for the same user cannot issue the same OTP step.
    """
    email = payload.email.casefold()
    issued = None
    failure = False
    locked_out = False
    with _auth_cursor() as cur:
        cur.execute('''SELECT user_id,org_id,password_hash,mfa_ciphertext,mfa_counter,
                   is_disabled,failure_attempts,failure_first_at
                   FROM jw_dev.v85_auth_candidate(%s)''', (email,))
        user_id, org, encoded, mfa_cipher, last_counter, disabled, attempts, first_failed = cur.fetchone()
        if first_failed:
            try:
                when = datetime.fromisoformat(first_failed)
                if when.tzinfo is None:
                    # Original SQLite stores Asia/Seoul local timestamps.
                    from zoneinfo import ZoneInfo
                    when = when.replace(tzinfo=ZoneInfo('Asia/Seoul'))
                locked_out = bool(attempts >= 5 and when + timedelta(minutes=15) > datetime.now(timezone.utc))
            except ValueError:
                locked_out = True  # suspicious malformed lockout record: fail closed
        pw_ok = verify_legacy_pbkdf2(payload.password, encoded or FAKE_HASH)
        mfa_ok = False
        mfa_step = None
        used_recovery = None
        if pw_ok and user_id and not disabled and not locked_out:
            if mfa_cipher:
                if bool(payload.otp) != bool(payload.recovery_code):
                    if payload.otp:
                        try:
                            secret = secret_for_user(mfa_cipher)
                        except RuntimeError as exc:
                            raise HTTPException(503, 'MFA key unavailable') from exc
                        mfa_step = match_totp(secret, payload.otp, last_counter)
                        mfa_ok = mfa_step is not None
                    else:
                        used_recovery = recovery_hash(user_id, payload.recovery_code)
                        # Let the DB consume the recovery code atomically. A
                        # nonexisting/used code raises and the login fails.
                        mfa_ok = True
            else:
                mfa_ok = not payload.otp and not payload.recovery_code
        if pw_ok and user_id and not disabled and mfa_ok and not locked_out:
            raw_token = secrets.token_urlsafe(48)
            csrf = secrets.token_urlsafe(32)
            try:
                # Savepoint: a bad recovery proof remains a counted login failure.
                with cur.connection.transaction():
                    cur.execute('''SELECT jw_dev.v85_auth_issue_session(%s,%s,%s,%s,%s)''',
                                (user_id, hashlib.sha256(raw_token.encode()).hexdigest(),
                                 csrf, mfa_step, used_recovery))
                    row = cur.fetchone()
            except Exception as exc:
                if used_recovery is None or getattr(exc, 'sqlstate', None) != '23514':
                    raise
                cur.execute('SELECT jw_dev.v85_auth_failed(%s)', (email,))
                failure = True
            else:
                if not row or not row[0]:
                    raise HTTPException(503, 'PostgreSQL session issuance failed')
                issued = (raw_token, csrf, (datetime.now(timezone.utc) + timedelta(hours=12)).isoformat())
        elif not locked_out:
            # Failure count is committed before returning HTTP 401.
            cur.execute('SELECT jw_dev.v85_auth_failed(%s)', (email,))
            failure = True
    if locked_out:
        raise HTTPException(429, '로그인 시도가 많습니다. 15분 후 다시 시도하세요')
    if failure or issued is None:
        raise HTTPException(401, '이메일 또는 비밀번호가 올바르지 않습니다')
    return issued


def make_auth_router() -> APIRouter:
    router = APIRouter(prefix=AUTH_PREFIX, tags=['PostgreSQL auth stage (dev only)'])

    @router.post('/login')
    def login(payload: LoginPayload, response: Response):
        raw, csrf, expiry = login_session(payload)
        response.set_cookie(COOKIE, raw, secure=True, httponly=True, samesite='strict', path='/')
        response.headers['Cache-Control'] = 'no-store'
        return {'csrf_token': csrf, 'expires_at': expiry, 'backend': 'postgresql_auth_stage'}

    @router.post('/logout')
    def logout(request: Request, response: Response):
        cookie = request.cookies.get(COOKIE, '')
        csrf = request.headers.get('X-CSRF-Token', '')
        if len(cookie) < 30 or len(cookie) > 512 or not csrf:
            raise HTTPException(401, 'PostgreSQL session required')
        hashed = hashlib.sha256(cookie.encode()).hexdigest()
        with _auth_cursor() as cur:
            # Verify session's stored CSRF before revoking. The auth writer
            # cannot revoke an arbitrary account without the raw cookie+CSRF.
            cur.execute('''SELECT jw_dev.v85_auth_check_csrf(%s,%s)''', (hashed, csrf))
            if cur.fetchone() != (True,):
                raise HTTPException(403, 'Invalid security token')
            cur.execute('SELECT jw_dev.v85_auth_revoke_session(%s)', (hashed,))
            if cur.fetchone() != (True,):
                raise HTTPException(401, 'PostgreSQL session invalid')
        response.delete_cookie(COOKIE, path='/')
        response.headers['Cache-Control'] = 'no-store'
        return {'ok': True}

    return router


def register_v85_auth(app) -> bool:
    if not auth_stage_enabled():
        return False
    app.include_router(make_auth_router())
    return True
