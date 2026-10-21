"""After V5.2 PG17 success, add V5.3 durable evidence digest gate."""
from __future__ import annotations
import os

def main() -> int:
    if (os.getenv('JW_ENV','').casefold()=='production'
            or os.getenv('JW_PG_LAB_V53')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_LAB_V52')!='ONLY_DISPOSABLE_LAB'
            or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'):
        print('NOT RUN: V5.3 lab PG chain unauthorized')
        return 2
    from scripts import run_postgres_isolation_ci_v52 as supervisor
    from scripts import test_postgres_outbox_relay_v52 as previous
    from scripts import test_postgres_evidence_digest_v53 as current
    old=previous.run
    def chained():
        rc=old()
        return rc if rc!=0 else current.run()
    previous.run=chained
    try:return supervisor.main()
    finally:previous.run=old

if __name__=='__main__':
    raise SystemExit(main())
