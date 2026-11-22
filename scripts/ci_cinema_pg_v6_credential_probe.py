#!/usr/bin/env python3
"""Read-only proof that the approved local backup password matches PostgreSQL SCRAM.

PostgreSQL can re-salt the same plaintext password; direct equality of two
SCRAM verifier strings would incorrectly reject a valid credential.
Never prints password, SCRAM verifier, DSN, server salt, or role catalog values.
No login as jw_backup_ro and no remote role/data mutation.
"""
from __future__ import annotations
import os
import re
import secrets

from scripts.ci_cinema_pg_q import decode_salt, make_verifier

class CredentialBlocked(Exception):
    pass

# Only accept SCRAM-SHA-256, reject out-of-policy iterations before deriving.
SCRAM_PATTERN = re.compile(
    r'SCRAM-SHA-256\$(\d{1,7}):[A-Za-z0-9+/]+={0,2}\$'
    r'[A-Za-z0-9+/]+={0,2}:[A-Za-z0-9+/]+={0,2}\Z'
)

def verifier_matches(conn, local_password: str) -> bool:
    row = conn.execute(
        "SELECT rolpassword FROM pg_authid WHERE rolname='jw_backup_ro'"
    ).fetchone()
    server = row[0] if row else None
    if not isinstance(server, str) or len(server) > 4096:
        raise CredentialBlocked('server_scram_unavailable')
    match = SCRAM_PATTERN.fullmatch(server)
    if not match:
        raise CredentialBlocked('server_scram_unavailable')
    iterations = int(match.group(1))
    if not 4096 <= iterations <= 1000000:
        raise CredentialBlocked('server_scram_iterations_out_of_policy')
    try:
        salt = decode_salt(server)
        derived = make_verifier(local_password, salt, iterations)
    except (ValueError, TypeError, IndexError):
        raise CredentialBlocked('server_scram_invalid') from None
    if not secrets.compare_digest(derived, server):
        raise CredentialBlocked('server_scram_password_mismatch')
    return True

def check():
    if os.environ.get('CODESPACES') != 'true':
        raise CredentialBlocked('codespaces_required')
    from scripts import ci_cinema_pg_v6_owner_readonly as sources
    from scripts.ci_cinema_pg_u import read_password_file
    from scripts.ci_cinema_pg_v6_role_expiry import facts
    import psycopg
    sources.verify_sources()
    password = read_password_file()  # checks the local verifier and 0600 permissions
    with psycopg.connect(os.environ['JW_PG_ADMIN_DSN'],connect_timeout=8) as conn:
        conn.execute('SET TRANSACTION READ ONLY')
        facts(conn)  # requires NOLOGIN and zero sessions
        return verifier_matches(conn, password)

def main():
    try:
        check()
        print('V6_CREDENTIAL_SERVER_SCRAM_PASSWORD_MATCH_PASS')
        return 0
    except BaseException as exc:
        known={
            'server_scram_unavailable',
            'server_scram_iterations_out_of_policy',
            'server_scram_invalid',
            'server_scram_password_mismatch',
            'codespaces_required',
        }
        label = str(exc) if isinstance(exc, CredentialBlocked) else type(exc).__name__
        print('V6_CREDENTIAL_CHECK_BLOCKED', label if label in known else type(exc).__name__)
        return 2
    finally:
        print('NO_ROLE_CHANGE_NO_BACKUP')

if __name__ == '__main__':
    raise SystemExit(main())
