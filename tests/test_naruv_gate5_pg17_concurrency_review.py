"""Actual disposable PG17 concurrency tests. Never targets external DBs."""
import os
import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
import psycopg
from scripts.naruv_pg_error_policy_review import classify

DSN = "host=127.0.0.1 port=55439 dbname=postgres user=postgres password=synthetic_review_only connect_timeout=4"
SCHEMA = "naruv_receipt_concurrency_ci"


def connect():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("GITHUB_REPOSITORY") == "guccizz1k/JARVIS-WORKS"
    assert os.environ.get("NARUV_PG17_CONCURRENCY_CI") == "1"
    c = psycopg.connect(DSN, autocommit=True)
    try:
        assert c.execute("SHOW server_version_num").fetchone()[0].startswith("17")
        c.execute("SET statement_timeout='12s'")
        c.execute("SET idle_in_transaction_session_timeout='20s'")
        c.execute("SET deadlock_timeout='100ms'")
        return c
    except BaseException:
        c.close()
        raise


@pytest.fixture
def db():
    with connect() as c:
        assert c.execute("SELECT to_regnamespace(%s)", (SCHEMA,)).fetchone()[0] is None
        c.execute("CREATE SCHEMA naruv_receipt_concurrency_ci")
        try:
            c.execute("""CREATE TABLE naruv_receipt_concurrency_ci.pair (
              id text PRIMARY KEY, legacy text UNIQUE, staged text UNIQUE,
              CHECK ((legacy IS NULL)=(staged IS NULL)),
              CHECK (legacy IS NULL OR legacy<>staged))""")
            c.execute("""CREATE TABLE naruv_receipt_concurrency_ci.receipt (
              digest text PRIMARY KEY, pair_id text NOT NULL REFERENCES naruv_receipt_concurrency_ci.pair(id),
              scope text NOT NULL CHECK(scope IN ('legacy','staged')), UNIQUE(pair_id,scope))""")
            c.execute("INSERT INTO naruv_receipt_concurrency_ci.pair(id) VALUES ('a'),('b')")
            yield c
        finally:
            c.execute("DROP SCHEMA naruv_receipt_concurrency_ci CASCADE")


def consume(c, pair, legacy, staged):
    """Transaction-owned, preverified synthetic digests only."""
    row = c.execute("SELECT id FROM naruv_receipt_concurrency_ci.pair WHERE id=%s AND legacy IS NULL AND staged IS NULL FOR UPDATE",(pair,)).fetchone()
    if row is None:
        return False
    c.execute("INSERT INTO naruv_receipt_concurrency_ci.receipt VALUES (%s,%s,'legacy'),(%s,%s,'staged')",(legacy,pair,staged,pair))
    assert c.execute("UPDATE naruv_receipt_concurrency_ci.pair SET legacy=%s,staged=%s WHERE id=%s",(legacy,staged,pair)).rowcount==1
    return True


def readback(c, pair):
    row=c.execute("SELECT legacy,staged FROM naruv_receipt_concurrency_ci.pair WHERE id=%s",(pair,)).fetchone()
    receipts=c.execute("SELECT scope,digest FROM naruv_receipt_concurrency_ci.receipt WHERE pair_id=%s ORDER BY scope",(pair,)).fetchall()
    if row == (None,None):
        assert not receipts
        return None
    assert row and all(row) and receipts==[('legacy',row[0]),('staged',row[1])]
    return row


def test_concurrent_single_consumption(db):
    barrier=threading.Barrier(8,timeout=10)
    def worker():
        with connect() as c:
            barrier.wait()
            with c.transaction():
                return consume(c,'a','l','s')
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:worker(),range(8)))
    assert results.count(True)==1 and results.count(False)==7
    assert readback(db,'a')==('l','s')


def test_real_lock_timeout(db):
    with connect() as owner, connect() as contender:
        with owner.transaction():
            owner.execute("SELECT id FROM naruv_receipt_concurrency_ci.pair WHERE id='a' FOR UPDATE")
            with pytest.raises(psycopg.errors.LockNotAvailable) as ex:
                with contender.transaction():
                    contender.execute("SET LOCAL lock_timeout='200ms'")
                    consume(contender,'a','l','s')
            assert ex.value.sqlstate=='55P03'
            assert classify(ex.value.sqlstate,phase='statement',rollback_confirmed=True).action=='READBACK_THEN_RETRY_WHOLE_TRANSACTION'
        with contender.transaction():
            assert consume(contender,'a','l','s')
    assert readback(db,'a')==('l','s')


def test_real_deadlock(db):
    barrier=threading.Barrier(2,timeout=8)
    def worker(first,second):
        with connect() as c:
            try:
                with c.transaction():
                    c.execute("SELECT id FROM naruv_receipt_concurrency_ci.pair WHERE id=%s FOR UPDATE",(first,))
                    barrier.wait()
                    c.execute("SELECT id FROM naruv_receipt_concurrency_ci.pair WHERE id=%s FOR UPDATE",(second,))
                return 'COMMITTED'
            except psycopg.errors.DeadlockDetected as e:
                assert e.sqlstate=='40P01'
                assert classify(e.sqlstate,phase='statement',rollback_confirmed=True).retry_automatically is False
                return e.sqlstate
    with ThreadPoolExecutor(max_workers=2) as pool:
        a=pool.submit(worker,'a','b')
        b=pool.submit(worker,'b','a')
        assert sorted([a.result(timeout=20),b.result(timeout=20)])==['40P01','COMMITTED']
    assert readback(db,'a') is None and readback(db,'b') is None


def test_second_receipt_failure_atomic_rollback(db):
    with db.transaction():
        assert consume(db,'a','l','s')
    with pytest.raises(psycopg.errors.UniqueViolation) as ex:
        with db.transaction():
            consume(db,'b','fresh','l')
    assert ex.value.sqlstate=='23505'
    assert readback(db,'b') is None
    with db.transaction():
        assert consume(db,'b','fresh','new')
    assert readback(db,'b')==('fresh','new')


def test_committed_response_discard_readback(db):
    # Real commit and new connection; intentionally discard app response.
    # Not a network-level fault injected into COMMIT.
    with connect() as c:
        with c.transaction():
            assert consume(c,'a','l','s')
    assert classify(None,phase='commit').action=='READBACK_ON_NEW_CONNECTION'
    with connect() as fresh:
        assert readback(fresh,'a')==('l','s')
        with fresh.transaction():
            assert consume(fresh,'a','l','s') is False


def test_backend_termination_rolls_back(db):
    # CI-only admin terminates its own test connection before commit.
    c=connect()
    try:
        pid=c.info.backend_pid
        c.execute("BEGIN")
        assert consume(c,'a','l','s')
        assert db.execute("SELECT pg_terminate_backend(%s,5000)",(pid,)).fetchone()==(True,)
        with pytest.raises(psycopg.Error):
            c.execute("COMMIT")
    finally:
        c.close()
    with connect() as fresh:
        assert readback(fresh,'a') is None
        with fresh.transaction():
            assert consume(fresh,'a','l','s')
        assert readback(fresh,'a')==('l','s')
