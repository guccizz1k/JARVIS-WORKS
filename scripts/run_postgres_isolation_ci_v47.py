"""Append V4.7 on top of the unchanged V4.6 database supervisor."""
from __future__ import annotations
import os


def main() -> int:
    if (os.getenv('JW_ENV', '').casefold() == 'production'
        or os.getenv('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{n}') != 'ONLY_DISPOSABLE_LAB'
               for n in range(35, 48))):
        print('NOT RUN: V4.7 historical PostgreSQL gate authorization missing')
        return 2
    from scripts import test_postgres_cutover_readiness_v46 as previous
    from scripts import test_postgres_lossless_projection_v47 as current
    from scripts import run_postgres_isolation_ci_v46 as supervisor
    original = previous.run

    def previous_then_v47():
        result = original()
        return result if result != 0 else current.run()

    previous.run = previous_then_v47
    try:
        return supervisor.main()
    finally:
        previous.run = original


if __name__ == '__main__':
    raise SystemExit(main())
