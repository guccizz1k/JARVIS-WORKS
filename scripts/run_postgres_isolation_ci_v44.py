"""Add V4.4 real web-cookie shadow gate after the complete V2.8-V4.3 lab chain.

V4.3 source is unmodified. The callback is restored even on exceptions.
"""
from __future__ import annotations
import os


def main() -> int:
    if (os.getenv('JW_ENV','').casefold() == 'production' or
        os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE' or
        os.getenv('JW_PG_LAB_V44') != 'ONLY_DISPOSABLE_LAB'):
        print('NOT RUN: isolated V4.4 lab not authorized')
        return 2
    from scripts import test_postgres_web_v43 as previous
    from scripts import test_postgres_cookie_shadow_v44 as new_gate
    from scripts import run_postgres_isolation_ci_v43 as supervisor
    original = previous.run
    def run_previous_then_new():
        outcome = original()
        if outcome != 0:
            return outcome
        return new_gate.run()
    previous.run = run_previous_then_new
    try:
        return supervisor.main()
    finally:
        previous.run = original


if __name__ == '__main__':
    raise SystemExit(main())
