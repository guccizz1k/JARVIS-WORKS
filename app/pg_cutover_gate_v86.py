"""JARVIS WORKS V8.6: read-only SQLite migration inventory and connection gate.

This module does NOT migrate data, create database credentials, or enable routes.
It cannot certify a production cutover. Never print a DSN or any user data.
"""
from __future__ import annotations

import os
import re
import sqlite3
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

REQUIRED_AUTH_TABLES = (
    'organizations', 'users', 'sessions', 'staff_disabled',
    'mfa_credentials', 'mfa_recovery_codes', 'login_failures',
)
HASH = re.compile(r'^pbkdf2_sha256\$260000\$[0-9a-fA-F]{32}\$[0-9a-fA-F]{64}$')
SESSION_HASH = re.compile(r'^[0-9a-f]{64}$')


@dataclass(frozen=True)
class GateCheck:
    code: str
    status: str  # PASS, BLOCKED, or FAIL; never infer PASS from no data
    detail: str


@dataclass(frozen=True)
class MigrationInventory:
    counts: dict[str, int]
    checks: tuple[GateCheck, ...]

    @property
    def pass_preflight(self) -> bool:
        return all(c.status == 'PASS' for c in self.checks)

    def public_report(self) -> dict:
        # Deliberately excludes emails, user IDs, tokens, hashes, and MFA ciphertexts.
        return {'counts': self.counts, 'checks': [asdict(x) for x in self.checks],
                'preflight': ('FAIL' if any(c.status == 'FAIL' for c in self.checks)
                              else 'BLOCKED' if not self.pass_preflight else 'PASS'),
                'migration_performed': False}


def _check(bad: bool, code: str, explanation: str) -> GateCheck:
    return GateCheck(code, 'FAIL' if bad else 'PASS', explanation)


def audit_sqlite_auth_snapshot(path: str | os.PathLike) -> MigrationInventory:
    """Read only; inspect a *snapshot* created by the user's normal backup flow.

    No UPDATE, migration, copy, or user-visible secret material. Fail closed on
    missing tables/columns, foreign-key corruption, duplicate normalized email,
    PBKDF2 mismatch, invalid session token format, and incorrect org membership.
    """
    p = Path(path).expanduser().resolve(strict=True)
    if not p.is_file() or p.suffix.lower() not in ('.db', '.sqlite', '.sqlite3'):
        raise ValueError('A local SQLite snapshot (.db/.sqlite/.sqlite3) is required')
    # URI mode=ro plus query_only means this process cannot mutate source DB.
    conn = sqlite3.connect(p.as_uri() + '?mode=ro', uri=True)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute('PRAGMA query_only = ON')
        present = {x[0] for x in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        missing = set(REQUIRED_AUTH_TABLES) - present
        checks = [GateCheck('schema', 'FAIL' if missing else 'PASS',
                            'Required auth tables complete' if not missing
                            else 'Missing required tables: ' + ','.join(sorted(missing)))]
        counts = {t: int(conn.execute(f'SELECT count(*) FROM "{t}"').fetchone()[0])
                  for t in REQUIRED_AUTH_TABLES if t in present}
        if missing:
            return MigrationInventory(counts, tuple(checks))
        required_columns = {
            'organizations': {'id'},
            'users': {'id','org_id','email','password_hash','role'},
            'sessions': {'token_hash','user_id','expires_at','csrf_token'},
            'staff_disabled': {'user_id','org_id'},
            'mfa_credentials': {'user_id','secret_encrypted','last_counter'},
            'mfa_recovery_codes': {'user_id','code_hash','consumed_at'},
            'login_failures': {'email','attempts','first_failed_at'},
        }
        columns = {t: {row[1] for row in conn.execute(f'PRAGMA table_info("{t}")')}
                   for t in REQUIRED_AUTH_TABLES}
        invalid = sorted(t for t, cols in required_columns.items() if cols - columns[t])
        checks.append(_check(bool(invalid), 'columns',
                             'Required auth column layouts intact' if not invalid
                             else 'Required columns missing in: ' + ','.join(invalid)))
        if invalid:
            return MigrationInventory(counts, tuple(checks))
        # Foreign keys may have been disabled while SQLite was running.
        fk = conn.execute('PRAGMA foreign_key_check').fetchall()
        checks.append(_check(bool(fk), 'foreign_keys', f'{len(fk)} foreign-key violations'))
        users = conn.execute('SELECT id,org_id,email,password_hash FROM users').fetchall()
        orgs = {r['id'] for r in conn.execute('SELECT id FROM organizations')}
        ids = {u['id']: u['org_id'] for u in users}
        emails = [str(u['email']).strip().casefold() for u in users]
        duplicates = sum(n - 1 for n in Counter(emails).values() if n > 1)
        checks.append(_check(duplicates > 0, 'normalized_emails',
                             f'{duplicates} duplicate normalized addresses'))
        bad_passwords = sum(1 for u in users if not isinstance(u['password_hash'], str)
                            or HASH.fullmatch(u['password_hash']) is None)
        checks.append(_check(bad_passwords > 0, 'password_compatibility',
                             f'{bad_passwords} unsupported legacy password hashes'))
        wrong_users = sum(1 for u in users if u['org_id'] not in orgs)
        disabled = conn.execute('SELECT user_id,org_id FROM staff_disabled').fetchall()
        wrong_disabled = sum(1 for d in disabled if ids.get(d['user_id']) != d['org_id'])
        checks.append(_check(wrong_users + wrong_disabled > 0, 'tenant_relations',
                             f'{wrong_users + wrong_disabled} invalid user/disabled organization relations'))
        bad_sessions = sum(1 for s in conn.execute('SELECT token_hash,user_id FROM sessions')
                           if (not isinstance(s['token_hash'], str) or
                               SESSION_HASH.fullmatch(s['token_hash']) is None or s['user_id'] not in ids))
        checks.append(_check(bad_sessions > 0, 'session_format',
                             f'{bad_sessions} invalid existing session identifiers'))
        bad_recovery = sum(1 for x in conn.execute('SELECT code_hash,user_id FROM mfa_recovery_codes')
                           if (not isinstance(x['code_hash'],str) or
                               SESSION_HASH.fullmatch(x['code_hash']) is None or x['user_id'] not in ids))
        checks.append(_check(bad_recovery > 0, 'recovery_format',
                             f'{bad_recovery} invalid one-way recovery hashes'))
        # Snapshot readiness is necessary but not sufficient: active legacy
        # sessions MUST NOT be copied; forced re-login requires approval.
        checks.append(GateCheck('session_cutover', 'BLOCKED',
                                'Never copy active sessions; re-login/revocation policy requires cutover approval'))
        return MigrationInventory(counts, tuple(checks))
    finally:
        conn.close()


def role_boundary_evidence(row: tuple, *, auth: bool) -> tuple[GateCheck, ...]:
    """Check a live-login capability row without logging role/user identifiers.

    Row: (is_admin, login_can_set_auth, login_can_set_trade,
          login_has_direct_private_tables, ssl_used, server_pg_major).
    """
    admin, can_auth, can_trade, direct_tables, ssl_used, major = row
    selected = can_auth if auth else can_trade
    forbidden = can_trade if auth else can_auth
    return (
        _check(bool(admin), 'not_admin', 'No admin/BYPASSRLS login'),
        _check(not bool(selected), 'expected_role', 'Expected delegated role available'),
        _check(bool(forbidden), 'role_separation', 'No auth/trading role overlap'),
        _check(bool(direct_tables), 'no_direct_table_grants', 'No direct access to protected tables'),
        _check(not bool(ssl_used), 'tls', 'Verified TLS in use'),
        _check(int(major) != 17, 'pg17', 'PostgreSQL 17 supported'),
    )


ROLE_QUERY = """
SELECT (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR
        current_user IN ('postgres','supabase_admin','service_role')) AS unsafe_admin,
 pg_catalog.pg_has_role(session_user,'jw_auth_stage_v85','SET') AS can_auth,
 pg_catalog.pg_has_role(session_user,'jw_app_dev','SET') AS can_trade,
 EXISTS (SELECT 1 FROM pg_catalog.pg_tables t WHERE t.schemaname='jw_dev'
   AND (pg_catalog.has_table_privilege(session_user,format('%I.%I',t.schemaname,t.tablename),'SELECT')
     OR pg_catalog.has_table_privilege(session_user,format('%I.%I',t.schemaname,t.tablename),'INSERT')))
 AS direct_tables,
 (SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_catalog.pg_backend_pid()) AS ssl_used,
 current_setting('server_version_num')::integer / 10000 AS server_major
FROM pg_catalog.pg_roles r WHERE r.rolname=session_user
"""


def preflight_live_connections(*, connector: Callable | None = None, env: dict | None = None) -> dict:
    """Execute two independent read-only TLS connections; no database writes.

    Only call after user configures separate non-admin DSNs locally via secret
    manager. Never echo a DSN or passwords, even on connection errors.
    """
    e = os.environ if env is None else env
    if e.get('JW_ENV', '').lower() in {'prod','production'} or e.get('JW_INSECURE_LOCAL_DEV') == '1':
        return {'result':'BLOCKED','reason':'Production/insecure mode is not eligible for staging'}
    a, t = e.get('JW_PG_AUTH_STAGE_DSN'), e.get('JW_PG_STAGE_DSN')
    if not a or not t:
        return {'result':'BLOCKED','reason':'Independent authentication and trade DSNs not configured'}
    if a == t:
        return {'result':'BLOCKED','reason':'Separate auth and trade DB logins required'}
    if connector is None:
        try:
            import psycopg
        except ImportError:
            return {'result':'BLOCKED','reason':'PostgreSQL client dependency unavailable'}
        connector = psycopg.connect
    def inspect(dsn, is_auth):
        try:
            with connector(dsn, connect_timeout=5, sslmode='verify-full') as conn:
                with conn.cursor() as cur:
                    cur.execute('SET TRANSACTION READ ONLY')
                    cur.execute(ROLE_QUERY)
                    evidence = cur.fetchone()
                    if not evidence:
                        return [GateCheck('db_query','FAIL','Role metadata unavailable')]
                    return list(role_boundary_evidence(evidence, auth=is_auth))
        except Exception:
            return [GateCheck('network','BLOCKED','Connection or TLS verification failed; secrets suppressed')]
    auth_checks, trading_checks = inspect(a, True), inspect(t, False)
    all_checks = auth_checks + trading_checks
    return {'result':'PASS' if all(x.status=='PASS' for x in all_checks) else 'BLOCKED',
            'auth': [asdict(x) for x in auth_checks], 'trading': [asdict(x) for x in trading_checks],
            'production_cutover': False}
