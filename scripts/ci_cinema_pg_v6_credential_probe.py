#!/usr/bin/env python3
"""Read-only SCRAM verifier consistency check for the approved development role.

No verifier/password/DSN is printed or saved. Never attempts to log in as the
restricted role and never modifies authentication settings.
"""
from __future__ import annotations
import os
import secrets

class CredentialBlocked(Exception): pass

def verifier_matches(conn, expected):
    row=conn.execute(
        "SELECT rolpassword FROM pg_authid WHERE rolname='jw_backup_ro'"
    ).fetchone()
    if not row or not isinstance(row[0],str) or not row[0].startswith('SCRAM-SHA-256$'):
        raise CredentialBlocked('server_scram_unavailable')
    if not secrets.compare_digest(row[0],expected):
        raise CredentialBlocked('server_scram_mismatch')
    return True

def check():
    if os.environ.get('CODESPACES')!='true':
        raise CredentialBlocked('codespaces_required')
    from scripts import ci_cinema_pg_v6_owner_readonly as sources
    from scripts.ci_cinema_pg_u import read_password_file
    from scripts.ci_cinema_pg_q import CREDS
    from scripts.ci_cinema_pg_v6_role_expiry import facts
    import json
    import psycopg
    sources.verify_sources()
    read_password_file()  # locally verify SCRAM password against its saved verifier
    expected=json.loads(CREDS.read_text(encoding='utf-8'))['verifier']
    with psycopg.connect(os.environ['JW_PG_ADMIN_DSN'],connect_timeout=8) as conn:
        conn.execute('SET TRANSACTION READ ONLY')
        facts(conn)  # NOLOGIN and zero sessions must hold
        return verifier_matches(conn,expected)

def main():
    try:
        check()
        print('V6_CREDENTIAL_SERVER_SCRAM_MATCH_PASS')
        return 0
    except BaseException as exc:
        known={'server_scram_unavailable','server_scram_mismatch','codespaces_required'}
        msg=str(exc) if isinstance(exc,CredentialBlocked) else type(exc).__name__
        print('V6_CREDENTIAL_CHECK_BLOCKED',msg if msg in known else type(exc).__name__)
        return 2
    finally:
        print('NO_ROLE_CHANGE_NO_BACKUP')

if __name__=='__main__':
    raise SystemExit(main())
