"""Append V5.5 PG test to existing V5.3 supervisor; historical gates first."""
import os


def main():
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_LAB_V53')!='ONLY_DISPOSABLE_LAB'
        or os.getenv('JW_PG_LAB_V54')!='ONLY_DISPOSABLE_LAB'
        or os.getenv('JW_PG_LAB_V55')!='ONLY_DISPOSABLE_LAB'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'):
        print('NOT RUN: V5.5 disposable PG chain not authorized')
        return 2
    from scripts import run_postgres_isolation_ci_v53 as previous
    from scripts import test_postgres_evidence_digest_v53 as historical
    from scripts import test_postgres_message_payload_v55 as new
    original = historical.run
    def chain():
        rc=original()
        return rc if rc != 0 else new.run()
    historical.run=chain
    try:
        return previous.main()
    finally:
        historical.run=original

if __name__=='__main__':
    raise SystemExit(main())
