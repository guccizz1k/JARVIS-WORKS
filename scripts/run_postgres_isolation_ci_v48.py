"""Run V4.8 only after all historical PG17 gates including V4.7 PASS."""
from __future__ import annotations
import os


def main() -> int:
    if (os.environ.get('JW_ENV', '').casefold() == 'production'
        or os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.environ.get(f'JW_PG_LAB_V{v}') != 'ONLY_DISPOSABLE_LAB'
               for v in range(35,49))):
        print('NOT RUN: V4.8 prior gates not authorized')
        return 2
    from scripts import test_postgres_lossless_projection_v47 as prior
    from scripts import test_postgres_semantic_envelopes_v48 as latest
    from scripts import run_postgres_isolation_ci_v47 as supervisor
    original = prior.run
    def prior_then_v48():
        rc = original()
        return rc if rc != 0 else latest.run()
    prior.run = prior_then_v48
    try:
        return supervisor.main()
    finally:
        prior.run = original


if __name__ == '__main__':
    raise SystemExit(main())
