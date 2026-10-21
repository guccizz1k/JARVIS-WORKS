"""Fail-closed V5.7 PG17 supervisor + V5.8 receipt-only isolated test."""
import os

def main():
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{x}')!='ONLY_DISPOSABLE_LAB' for x in (54,55,56,57,58))):
        print('NOT RUN: V5.8 PG supervisor not authorized')
        return 2
    from scripts import run_postgres_isolation_ci_v57 as supervisor
    from scripts import test_postgres_attachment_payload_v57 as preceding
    from scripts import test_postgres_receipt_identity_v58 as current
    original=preceding.run
    def chain():
        result=original()
        return result if result != 0 else current.run()
    preceding.run=chain
    try:return supervisor.main()
    finally:preceding.run=original

if __name__=='__main__':raise SystemExit(main())
