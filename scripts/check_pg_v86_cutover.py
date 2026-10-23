#!/usr/bin/env python3
"""V8.6 non-destructive cutover preflight. Sensitive data never printed."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.pg_cutover_gate_v86 import audit_sqlite_auth_snapshot, preflight_live_connections


def main(argv=None):
    p=argparse.ArgumentParser(description='JARVIS V8.6 read-only migration/connection preflight')
    p.add_argument('--sqlite-snapshot',help='Explicit read-only SQLite snapshot, never the live database')
    p.add_argument('--check-connections',action='store_true',help='Read only; uses process environment DSNs')
    args=p.parse_args(argv)
    result={'version':'V8.6', 'migration_performed':False, 'cutover_performed':False,
            'sqlite':{'result':'BLOCKED','reason':'No user-provided snapshot'}}
    if args.sqlite_snapshot:
        try:
            result['sqlite']=audit_sqlite_auth_snapshot(args.sqlite_snapshot).public_report()
        except (OSError,ValueError,RuntimeError,Exception) as exc:
            # No paths, SQL contents, DB messages, credentials, hashes or PII.
            result['sqlite']={'result':'BLOCKED','reason':'SQLite snapshot unreadable or unsuitable'}
    if args.check_connections:
        result['network']=preflight_live_connections()
    else:
        result['network']={'result':'BLOCKED','reason':'Independent TLS/role connections not tested'}
    result['overall']='BLOCKED'  # An automation cannot authorize production cutover.
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True))
    return 2


if __name__=='__main__':
    sys.exit(main())
