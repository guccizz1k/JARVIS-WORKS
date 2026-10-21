"""Reuse the V5.6 disposable PG17 supervisor; append V5.7 only on success."""
import os

def main():
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{x}')!='ONLY_DISPOSABLE_LAB' for x in (53,54,55,56,57))):
        print('NOT RUN: V5.7 disposable PG chain authorization missing')
        return 2
    from scripts import run_postgres_isolation_ci_v56 as supervisor
    from scripts import test_postgres_edit_history_v56 as historical
    from scripts import test_postgres_attachment_payload_v57 as added
    old=historical.run
    def chain():
        result=old()
        return result if result!=0 else added.run()
    historical.run=chain
    try:return supervisor.main()
    finally:historical.run=old

if __name__=='__main__':raise SystemExit(main())
