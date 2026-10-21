"""Run V5.0 and all preceding PG17 historical stages BEFORE V5.2 relay."""
from __future__ import annotations
import os


def main() -> int:
    if (os.getenv('JW_ENV','').casefold()=='production'
            or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
            or os.getenv('JW_PG_LAB_V52')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_RELAY_V52')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_OUTBOX_V51')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_LAB_V50')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V5.2 historical PG17/relay gate not authorized')
        return 2
    from scripts import run_postgres_isolation_ci_v50 as supervisor
    from scripts import test_postgres_identity_audit_v50 as previous
    from scripts import test_postgres_outbox_relay_v52 as current
    original = previous.run
    def previous_then_relay():
        rc=original()
        return rc if rc != 0 else current.run()
    previous.run = previous_then_relay
    try:
        return supervisor.main()
    finally:
        previous.run=original

if __name__=='__main__':
    raise SystemExit(main())
