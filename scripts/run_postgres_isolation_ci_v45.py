"""Run ALL historical disposable PG17 gates before V4.5 evidence review.

Runtime callback extension is restored on every return path; no source edits.
"""
from __future__ import annotations
import os


def main():
    if (os.environ.get('JW_ENV','').casefold()=='production'
        or os.environ.get('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.environ.get('JW_PG_LAB_V'+str(v))!='ONLY_DISPOSABLE_LAB'
               for v in range(35,46))):
        print('NOT RUN: V4.5 disposable PostgreSQL lab flags missing')
        return 2
    from scripts import test_postgres_cookie_shadow_v44 as baseline
    from scripts import test_postgres_evidence_shadow_v45 as new_gate
    from scripts import run_postgres_isolation_ci_v44 as supervisor
    original=baseline.run
    def previous_then_v45():
        rc=original()
        return rc if rc!=0 else new_gate.run()
    baseline.run=previous_then_v45
    try:
        return supervisor.main()
    finally:
        baseline.run=original


if __name__=='__main__':
    raise SystemExit(main())
