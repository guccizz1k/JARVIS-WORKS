#!/usr/bin/env python3
"""Restore the already revoked development backup role to an expired baseline.

Changes ONLY jw_backup_ro VALID UNTIL on the pinned PG17 development admin DSN.
Requires existing NOLOGIN and zero sessions. No passwords, grants or source rows
are read or modified. The old security contract remains fail-closed.
"""
from __future__ import annotations
import os

PAST_EXPIRY = '2026-11-22 20:00:00+09'

class RoleBlocked(Exception):
    pass

def facts(conn):
    who = conn.execute(
        "SELECT current_user,current_database(),current_setting('server_version_num')::int"
    ).fetchone()
    if not who or who[:2] != ('postgres','postgres') or not (170000 <= who[2] < 180000):
        raise RoleBlocked('admin_identity_mismatch')
    role = conn.execute(
        "SELECT rolcanlogin,rolvaliduntil <= now(),rolbypassrls,rolsuper,"
        "rolcreaterole,rolcreatedb,rolreplication,rolconnlimit "
        "FROM pg_roles WHERE rolname='jw_backup_ro'"
    ).fetchone()
    if role is None or (role[0],*role[2:]) != (False,True,False,False,False,False,2):
        raise RoleBlocked('role_attributes_not_safe')
    sessions=conn.execute(
        "SELECT count(*) FROM pg_stat_activity WHERE usename='jw_backup_ro'"
    ).fetchone()[0]
    if sessions != 0:
        raise RoleBlocked('role_sessions_not_zero')
    return role[1]

def restore_expired():
    """Safe post-run closure repair, only if NOLOGIN/zero sessions are proven."""
    import psycopg
    dsn=os.environ['JW_PG_ADMIN_DSN']
    with psycopg.connect(dsn,connect_timeout=8,autocommit=True) as conn:
        if facts(conn) is True:
            return 'ALREADY_EXPIRED'
        with conn.transaction():
            # Recheck under transaction before changing a security attribute.
            if facts(conn) is not False:
                raise RoleBlocked('role_state_changed')
            conn.execute(
                "ALTER ROLE jw_backup_ro NOLOGIN VALID UNTIL '2026-11-22 20:00:00+09'"
            )
        if facts(conn) is not True:
            raise RoleBlocked('expiry_restore_not_verified')
        return 'EXPIRY_RESTORED'

def main():
    try:
        if os.environ.get('CODESPACES')!='true':
            raise RoleBlocked('codespaces_required')
        from scripts import ci_cinema_pg_v6_owner_readonly as source
        source.verify_sources()
        state=restore_expired()
        print('V6_ROLE_'+state+'_PASS')
        print('NOLOGIN_AND_ZERO_SESSIONS_VERIFIED')
        return 0
    except BaseException as exc:
        safe={'codespaces_required','admin_identity_mismatch','role_attributes_not_safe',
              'role_sessions_not_zero','role_state_changed','expiry_restore_not_verified'}
        message=str(exc) if isinstance(exc,RoleBlocked) else type(exc).__name__
        print('V6_ROLE_EXPIRY_BLOCKED',message if message in safe else type(exc).__name__)
        return 2
    finally:
        print('NO_BACKUP_NO_ROLE_ACTIVATION')

if __name__=='__main__':
    raise SystemExit(main())
