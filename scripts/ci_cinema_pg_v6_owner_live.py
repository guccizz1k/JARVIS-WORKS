#!/usr/bin/env python3
"""Owner-present V6 B2/B3 launcher; isolated target, bounded activation, unconditional revoke.

Requires explicit owner confirmation in a real terminal. Never operates on production.
The original engine, role SQL and revoke/prove-closed functions are unchanged.
"""
from __future__ import annotations
import sys
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from scripts import ci_cinema_pg_v6_preflight as checks
from scripts import ci_cinema_pg_v223_owner_live_20261117 as owner
from scripts import ci_cinema_pg_v223_codespace_run as runner
from scripts import ci_cinema_pg_v6_runner_integration as integration

KST=ZoneInfo('Asia/Seoul')
DEADLINE=datetime(2026,11,23,1,0,tzinfo=KST)
MAX_WINDOW=timedelta(hours=5)

def expiry_value(at=None):
    now=(at or datetime.now(timezone.utc)).astimezone(KST)
    if now>=DEADLINE or now<datetime(2026,11,22,20,25,tzinfo=KST):
        raise checks.v6.Blocked('approval_window_invalid')
    return min(now+MAX_WINDOW,DEADLINE).strftime('%Y-%m-%d %H:%M:%S+09')

def preflight():
    expiry_value()
    checks.check()
    return True

def main():
    # All patches are process-local; no files or environment are modified.
    # Source pin is replaced by the stronger exact V6 manifest in checks.check().
    import psycopg
    from scripts import pg_backup_v223 as engine
    integration.install(runner,psycopg,engine)
    original_preflight=owner.preflight
    original_expiry=owner.expiry_value
    original_sql=owner.ROLE_SQL
    owner.preflight=preflight
    owner.expiry_value=expiry_value
    owner.ROLE_SQL=checks.v6.ROOT / 'scripts/review/cinema_pg_v6_backup_role_20261123.sql'
    try:
        return owner.run_live()
    finally:
        owner.preflight=original_preflight
        owner.expiry_value=original_expiry
        owner.ROLE_SQL=original_sql

if __name__=='__main__':
    raise SystemExit(main())
