"""V4.3 opt-in extension of the unmodified, disposable V2.8 -> V4.2 runner.

Imports and wraps only the V4.2 run callback within THIS test process.
Never edits historical code, test manifests, or production application.
"""
from __future__ import annotations

import os


def main() -> int:
    flags = ('JW_PG_LAB_V35','JW_PG_LAB_V36','JW_PG_LAB_V37',
             'JW_PG_LAB_V38','JW_PG_LAB_V39','JW_PG_LAB_V40',
             'JW_PG_LAB_V41','JW_PG_LAB_V42','JW_PG_LAB_V43')
    if (os.getenv('JW_ENV', '').casefold() == 'production'
            or os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
            or any(os.getenv(flag) != 'ONLY_DISPOSABLE_LAB' for flag in flags)):
        print('NOT RUN: V4.3 synthetic-only chain gate not authorized')
        return 2

    from scripts import test_postgres_restore_v42 as baseline
    from scripts import test_postgres_web_v43 as web
    from scripts import run_postgres_isolation_ci_v28 as supervisor

    original_run = baseline.run

    def existing_then_web():
        outcome = original_run()
        if outcome != 0:
            return outcome
        return web.run()

    baseline.run = existing_then_web
    try:
        # Supervisor still exclusively provisions/tears down random local DB.
        return supervisor.main()
    finally:
        baseline.run = original_run


if __name__ == '__main__':
    raise SystemExit(main())
