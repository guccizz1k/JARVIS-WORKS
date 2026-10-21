"""Chain to proven V5.5 PG17 supervisor, then run V5.6 in same Docker."""
import os

def main():
    if (os.getenv('JW_ENV','').casefold()=='production'
        or os.getenv('JW_PG_CI_ALLOW')!='ONLY_EPHEMERAL_LOCAL_DATABASE'
        or any(os.getenv(f'JW_PG_LAB_V{x}')!='ONLY_DISPOSABLE_LAB'
               for x in (53,54,55,56))):
        print('NOT RUN: isolated V5.6 chain not authorized')
        return 2
    from scripts import run_postgres_isolation_ci_v55 as supervisor
    from scripts import test_postgres_message_payload_v55 as previous
    from scripts import test_postgres_edit_history_v56 as added
    old=previous.run
    def chained():
        result=old()
        return result if result != 0 else added.run()
    previous.run=chained
    try:
        return supervisor.main()
    finally:
        previous.run=old

if __name__=='__main__':
    raise SystemExit(main())
