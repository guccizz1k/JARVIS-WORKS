import os, sys, hashlib, secrets, getpass, warnings
from pathlib import Path
from contextlib import ExitStack, closing
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
import psycopg

CA = Path.home()/'.naruv-qa-review/ca.crt'
PIN = '3d693669b23c340c57a3457bdc8b6fefe1806cc5'
HOST = 'aws-0-ap-northeast-2.pooler.supabase.com'
USER = 'postgres.scvqtsyxkqddoorcaiqr'

def need(ok, code):
    if not ok:
        raise RuntimeError(code)

def run(pw):
    key = secrets.randbits(62)
    with ExitStack() as stack:
        conns = []
        pids = []
        for _ in range(3):
            c = stack.enter_context(closing(psycopg.connect(
                host=HOST, port=5432, dbname='postgres', user=USER,
                password=pw, sslmode='verify-full', sslrootcert=str(CA),
                gssencmode='disable', connect_timeout=10)))
            c.execute('SET TRANSACTION READ ONLY')
            c.execute("SET LOCAL statement_timeout='10s'")
            c.execute("SET LOCAL idle_in_transaction_session_timeout='30s'")
            row = c.execute("SELECT current_database(),session_user,current_setting('server_version_num')::int,(SELECT count(*) FROM naruv_qa_probe.fixture),pg_backend_pid()").fetchone()
            need(row[:4]==('postgres','postgres',170012,2),'QA_SCOPE')
            pids.append(row[4]); conns.append(c)
        need(len(set(pids))==3,'DISTINCT_BACKENDS')
        barrier = Barrier(3)
        def measure(c):
            barrier.wait(timeout=5)
            return c.execute('WITH s AS MATERIALIZED (SELECT clock_timestamp() AS started), w AS MATERIALIZED (SELECT started, pg_sleep(1) FROM s) SELECT started,clock_timestamp() FROM w').fetchone()
        with ThreadPoolExecutor(max_workers=3) as pool:
            windows = list(pool.map(measure,conns))
        overlap = (min(b for a,b in windows)-max(a for a,b in windows)).total_seconds()
        need(overlap>0,'NO_SERVER_TIME_OVERLAP')
        a,b,c = conns
        def lock(conn,k):
            return conn.execute('SELECT pg_try_advisory_xact_lock(%s)',(k,)).fetchone()==(True,)
        need(lock(a,key),'FIRST_LOCK')
        need(not lock(b,key),'SAME_KEY_NOT_BLOCKED')
        need(lock(c,key+1),'DIFFERENT_KEY_BLOCKED')
        a.rollback()
        need(lock(b,key),'ROLLBACK_DID_NOT_RELEASE')
        b.rollback(); c.rollback()
        print('HOSTED_PARALLEL_SESSIONS_PASS 3')
        print('SERVER_OVERLAP_MS',round(overlap*1000,3))
        print('LOCK_ISOLATION_AND_ROLLBACK_PASS 4/4')
        print('HOSTED_CONCURRENCY_PREFLIGHT_PASS')

def main():
    data=CA.read_bytes()
    need(hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()==PIN,'CA_PIN_MISMATCH')
    for k in list(os.environ):
        if k.startswith('PG'):
            os.environ.pop(k,None)
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        run(getpass.getpass('QA DB Password: '))

if __name__=='__main__':
    try:
        main()
    except psycopg.Error as e:
        m=str(e).lower()
        reason=next((v for k,v in [('econnrefused','BACKEND_REFUSED'),('circuit breaker','PROTECTION_ACTIVE'),('password authentication failed','PASSWORD_ERROR'),('certificate','TLS_ERROR'),('timeout','TIMEOUT')] if k in m),'OTHER_DB_ERROR')
        print('HOSTED_CONCURRENCY_BLOCKED',reason,e.sqlstate)
        sys.exit(1)
    except (RuntimeError,OSError,getpass.GetPassWarning,EOFError) as e:
        print('HOSTED_CONCURRENCY_BLOCKED',str(e) if type(e) is RuntimeError else type(e).__name__)
        sys.exit(1)
