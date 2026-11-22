#!/usr/bin/env python3
"""V6 read-only integration acceptance; no role activation or backup.

The 2026-11-22 owner approval is NOT transferred to this branch.
Never use this module as a live B2/B3 launcher.
"""
from __future__ import annotations
import os
import subprocess
from pathlib import Path

from scripts import ci_cinema_pg_v223_owner_live_20261122 as owner
from scripts import ci_cinema_pg_v223_owner_live_20261117 as old
from scripts import ci_cinema_pg_v223_codespace_run as runner
from scripts import ci_cinema_pg_v6_runner_integration as v6

ROOT=Path(__file__).resolve().parents[1]
BASE='11cb1d6464eefbcaf29e84c302d44c02d25586cc'
BRANCH='review/jw-b2b3-v6-target-adapter-20261122'
ALLOWED=frozenset({
 'scripts/ci_cinema_pg_v6_target_adapter.py',
 'scripts/ci_cinema_pg_v6_target_binding.py',
 'scripts/ci_cinema_pg_v6_runner_integration.py',
 'scripts/ci_cinema_pg_v6_owner_readonly.py',
 'scripts/ci_cinema_pg_v6_preflight.py',
 'scripts/ci_cinema_pg_v6_owner_live.py',
 'scripts/review/cinema_pg_v6_backup_role_20261123.sql',
 'tests/test_ci_cinema_pg_v6_target_adapter.py',
 'tests/test_ci_cinema_pg_v6_target_binding.py',
 'tests/test_ci_cinema_pg_v6_runner_integration.py',
 'tests/test_ci_cinema_pg_v6_owner_readonly.py',
 'tests/test_ci_cinema_pg_v6_preflight.py',
 'tests/test_ci_cinema_pg_v6_owner_live.py',
})

class Blocked(Exception):pass

def git(*args):
    p=subprocess.run(['git',*args],cwd=ROOT,capture_output=True,text=True,timeout=30)
    if p.returncode:raise Blocked('git_integrity')
    return p.stdout.strip()

def verify_sources():
    if os.environ.get('CODESPACES')!='true':raise Blocked('codespace_required')
    if git('branch','--show-current') not in ('',BRANCH):
        raise Blocked('branch_mismatch')
    head=git('rev-parse','HEAD')
    if head!=git('rev-parse','refs/remotes/origin/'+BRANCH):
        raise Blocked('remote_sha_mismatch')
    git('merge-base','--is-ancestor',BASE,'HEAD')
    changed=set(git('diff','--name-only',BASE,'HEAD').splitlines())
    if changed!=ALLOWED:raise Blocked('review_manifest_mismatch')
    if git('status','--porcelain','--untracked-files=all'):
        raise Blocked('dirty_worktree')
    for path in old.SOURCE_PINNED:
        if git('rev-parse','HEAD:'+path)!=git('rev-parse',BASE+':'+path):
            raise Blocked('protected_engine_changed')
    for path in ALLOWED:
        if git('hash-object',path)!=git('rev-parse','HEAD:'+path):
            raise Blocked('review_file_changed')
    return head

def check():
    verify_sources()
    # This action intentionally makes no contact with the remote development DB.
    # Approval expiry must be checked for any future live launcher, not bypassed.
    import psycopg
    from scripts import pg_backup_v223 as engine
    v6.install(runner,psycopg,engine)
    result=runner.stage_target()
    env=runner.backup_env()
    from scripts.pg_backup_v223 import parse_dsn
    p=parse_dsn(env['JW_PG_TARGET_ADMIN_DSN'])
    if (p['host'],p['port'],p['dbname'],p['user'])!=(
        '127.0.0.1','55433','postgres','postgres'):
        raise Blocked('child_target_not_55433')
    if result['restore_target']!='v6_verified_isolated_55433':
        raise Blocked('target_stage_mismatch')
    return True

def main():
    try:
        check()
        print('V6_SOURCE_PIN_AND_REAL_TARGET_PASS')
        print('NO_ROLE_CHANGE_NO_BACKUP')
        return 0
    except BaseException as e:
        print('BLOCKED_V6_READONLY_'+type(e).__name__)
        print('NO_ROLE_CHANGE_NO_BACKUP')
        return 2

if __name__=='__main__':
    raise SystemExit(main())
