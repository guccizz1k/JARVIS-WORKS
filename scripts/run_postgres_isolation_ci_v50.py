"""Append V5.0 synthetic actor audit after the unchanged complete V4.8 PG17 chain."""
from __future__ import annotations
import os


def main() -> int:
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{n}')!='ONLY_DISPOSABLE_LAB' for n in range(35,49))
        or os.getenv('JW_PG_LAB_V50')!='ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: V5.0 prior gates or disposable lab not authorized')
        return 2
    from scripts import test_postgres_semantic_envelopes_v48 as previous
    from scripts import test_postgres_identity_audit_v50 as current
    from scripts import run_postgres_isolation_ci_v48 as supervisor
    original=previous.run
    def prior_then_v50():
        rc=original()
        return rc if rc!=0 else current.run()
    previous.run=prior_then_v50
    try:
        return supervisor.main()
    finally:
        previous.run=original

if __name__=='__main__':
    raise SystemExit(main())
