#!/usr/bin/env python3
"""Owner-confirmed, dev-only SCRAM credential repair. Not a backup launcher.

Changes at most ONE catalog property: password of existing NOLOGIN jw_backup_ro.
Requires source SHA manifest, approved time window, PostgreSQL17 dev identity,
expired NOLOGIN, zero sessions, unchanged privileges, matching local verifier.
No DSN, password or SCRAM verifier is ever printed by this module.
"""
from __future__ import annotations
import json
import os
import secrets
import stat
import sys
from datetime import datetime
from zoneinfo import ZoneInfo

from scripts.ci_cinema_pg_q import CREDS, ROLE, decode_salt, make_verifier
from scripts.ci_cinema_pg_v6_credential_probe import (
    CredentialBlocked, SCRAM_PATTERN, verifier_matches,
)
from scripts.ci_cinema_pg_v6_role_expiry import facts
from scripts.ci_cinema_pg_v6_owner_readonly import verify_sources
from scripts.ci_cinema_pg_v223_owner_live_20261117 import check_live_admin_state

DEADLINE = datetime(2026, 11, 23, 1, 0, tzinfo=ZoneInfo('Asia/Seoul'))
START = datetime(2026, 11, 22, 20, 25, tzinfo=ZoneInfo('Asia/Seoul'))
CONFIRM = 'RESET jw_backup_ro'


class SyncBlocked(Exception):
    pass


def check_window(at: datetime | None = None) -> None:
    now = at or datetime.now(ZoneInfo('Asia/Seoul'))
    if not (START <= now.astimezone(START.tzinfo) < DEADLINE):
        raise SyncBlocked('approval_window_closed')


def local_credential() -> tuple[str, str]:
    """Read a single owner-only file descriptor; avoid any local file swap race."""
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(CREDS, flags)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid()
                or st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
                or st.st_nlink != 1 or st.st_size > 4096):
            raise SyncBlocked('local_credential_unsafe')
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            fd = -1
            blob = stream.read(4097)
        if len(blob) > 4096:
            raise SyncBlocked('local_credential_unsafe')
    finally:
        if fd != -1:
            os.close(fd)
    obj = json.loads(blob)
    if not isinstance(obj, dict) or set(obj) != {'role', 'password', 'verifier'}:
        raise SyncBlocked('local_verifier_invalid')
    password, verifier = obj['password'], obj['verifier']
    if obj['role'] != ROLE or not isinstance(verifier, str) or not SCRAM_PATTERN.fullmatch(verifier):
        raise SyncBlocked('local_verifier_invalid')
    try:
        if not secrets.compare_digest(verifier, make_verifier(password, decode_salt(verifier))):
            raise SyncBlocked('local_verifier_invalid')
    except (ValueError, IndexError, TypeError):
        raise SyncBlocked('local_verifier_invalid') from None
    return password, verifier


def confirm_owner(stdin=None, stdout=None) -> None:
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    if not stdin.isatty():
        raise SyncBlocked('owner_tty_required')
    stdout.write('Approval required: change only the dev jw_backup_ro password.\n')
    stdout.write('Type RESET jw_backup_ro to approve: ')
    stdout.flush()
    if stdin.readline().strip() != CONFIRM:
        raise SyncBlocked('owner_confirmation_required')


def verify_baseline(conn) -> None:
    if facts(conn) is not True:
        raise SyncBlocked('not_expired_nologin_zero_sessions')
    tls = conn.execute(
        'SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()'
    ).fetchone()
    if not tls or tls[0] is not True:
        raise SyncBlocked('admin_tls_required')


def apply_password(conn, local_password: str, local_verifier: str, sql_module) -> str:
    """Single transaction caller. Old hash is never logged and rollback is automatic.

    A verifier generated from the local password is already an encrypted SCRAM
    string. PostgreSQL stores a supplied SCRAM verifier as-is (PG17 docs).
    """
    verify_baseline(conn)
    try:
        verifier_matches(conn, local_password)
    except CredentialBlocked as exc:
        if str(exc) != 'server_scram_password_mismatch':
            raise SyncBlocked('server_scram_unusable') from None
    else:
        return 'ALREADY_MATCH'
    # A last role-state check before the password catalog change.
    verify_baseline(conn)
    conn.execute(sql_module.SQL('ALTER ROLE {} PASSWORD {}').format(
        sql_module.Identifier('jw_backup_ro'),
        sql_module.Literal(local_verifier),
    ))
    # Re-read under the SAME transaction; any failure rolls it back.
    if not verifier_matches(conn, local_password):
        raise SyncBlocked('postwrite_verifier_mismatch')
    verify_baseline(conn)
    return 'PASSWORD_SYNCHRONIZED'


def execute_sync(*, input_stream=None, output_stream=None):
    if os.environ.get('CODESPACES') != 'true':
        raise SyncBlocked('approved_codespace_only')
    check_window()
    verify_sources()  # exact clean remote SHA, pinned engine blob, reviewed file list
    check_live_admin_state()  # read-only verification incl. 65 tables, privileges
    local_password, local_verifier = local_credential()
    # Confirm before any mutation, but only AFTER all non-mutation preflights pass.
    confirm_owner(input_stream, output_stream)
    check_window()
    import psycopg
    from psycopg import sql
    with psycopg.connect(os.environ['JW_PG_ADMIN_DSN'], connect_timeout=8) as conn:
        with conn.transaction():
            conn.execute("SET LOCAL lock_timeout='3s'")
            conn.execute("SET LOCAL statement_timeout='12s'")
            check_window()
            result = apply_password(conn, local_password, local_verifier, sql)
    # Independent session post-commit proof (no LOGIN granted).
    from scripts.ci_cinema_pg_v6_credential_probe import check as credential_check
    if not credential_check():
        raise SyncBlocked('independent_proof_failed')
    check_live_admin_state()
    return result


def main():
    try:
        result = execute_sync()
        if result not in ('PASSWORD_SYNCHRONIZED', 'ALREADY_MATCH'):
            raise SyncBlocked('unexpected_result')
        print('V6_DEV_'+result+'_PASS')
        print('NOLOGIN_EXPIRED_ZERO_SESSIONS_PASS')
        print('NO_BACKUP_NO_ROLE_ACTIVATION')
        return 0
    except BaseException as exc:
        safe = {'approval_window_closed', 'owner_tty_required', 'owner_confirmation_required',
                'approved_codespace_only', 'local_verifier_invalid',
                'local_credential_unsafe',
                'not_expired_nologin_zero_sessions', 'admin_tls_required',
                'server_scram_unusable',
                'postwrite_verifier_mismatch', 'independent_proof_failed'}
        label = str(exc) if isinstance(exc, SyncBlocked) else type(exc).__name__
        print('V6_PASSWORD_SYNC_BLOCKED', label if label in safe else type(exc).__name__)
        print('NO_BACKUP_NO_ROLE_ACTIVATION')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
