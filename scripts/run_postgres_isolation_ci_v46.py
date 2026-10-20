"""Append the V4.6 catalog audit to the entire existing V4.5 PG17 gate."""
from __future__ import annotations
import os


def main() -> int:
    if (os.environ.get('JW_ENV', '').casefold() == 'production'
        or os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.environ.get(f'JW_PG_LAB_V{v}') != 'ONLY_DISPOSABLE_LAB'
               for v in range(35, 47))):
        print('NOT RUN: V4.6 historical gate authorization absent')
        return 2
    from scripts import test_postgres_evidence_shadow_v45 as prior
    from scripts import test_postgres_cutover_readiness_v46 as next_gate
    from scripts import run_postgres_isolation_ci_v45 as supervisor
    original = prior.run
    def previous_then_v46():
        rc = original()
        return rc if rc != 0 else next_gate.run()
    prior.run = previous_then_v46
    try:
        return supervisor.main()
    finally:
        prior.run = original

if __name__ == '__main__':
    raise SystemExit(main())
