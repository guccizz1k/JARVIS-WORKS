"""Isolated mock-row tests, not a live source-to-Postgres migration proof."""
import hashlib
import os
import sqlite3
import tempfile
import pytest
from migration_integrity_v90 import fingerprint,compare,normalize,audit,TABLES


def test_contract_35_tables():
    assert len(TABLES)==35
    assert 'messenger_messages' in TABLES and 'payments' in TABLES


def test_row_order_does_not_change_digest():
    a=[{'id':'한글','v':3},{'id':'a','v':2}]
    assert fingerprint(a)==fingerprint(a[::-1])


def test_mutation_or_missing_row_mismatch():
    src=[{'id':'a','total':100}]
    assert compare(src,[{'id':'a','total':101}])['status']=='FAIL'
    assert compare(src,[])['status']=='FAIL'


def test_duplicate_row_is_not_lost():
    row={'id':'a'}
    assert compare([row,row],[row])['status']=='FAIL'


def test_binary_consistent_across_drivers():
    a=[{'bytes':b'hello'}]
    b=[{'bytes':memoryview(b'hello')}]
    assert compare(a,b)['status']=='PASS'
    assert compare(a,[{'bytes':b'goodbye'}])['status']=='FAIL'


def test_max_rows_explicit_fail():
    with pytest.raises(ValueError):fingerprint([{'x':1},{'x':2}],limit=1)


def test_sqlite_read_only_and_pg_connection_is_query_only():
    class Cursor:
        def __enter__(self):return self
        def __exit__(self,*x):pass
        def execute(self,q):
            assert q=='SET TRANSACTION READ ONLY' or q=='SELECT * FROM jw_dev."organizations" LIMIT 100001'
        description=[type('D',(),{'name':'id'})(),type('D',(),{'name':'name'})()]
        def fetchmany(self,n):
            assert n==100001
            return [('o1','가온')]
    class DB:
        def cursor(self):return Cursor()
    with tempfile.TemporaryDirectory() as d:
        fn=os.path.join(d,'db.sqlite')
        con=sqlite3.connect(fn);con.execute('CREATE TABLE organizations(id TEXT,name TEXT)')
        con.execute('INSERT INTO organizations VALUES(?,?)',('o1','가온'));con.commit();con.close()
        result=audit(fn,DB(),['organizations'])
        assert result['status']=='PASS'
        con=sqlite3.connect(fn);assert con.execute('SELECT count(*) FROM organizations').fetchone()[0]==1;con.close()


def test_bad_table_blocked_before_any_queries():
    with pytest.raises(ValueError):audit('fake.db',object(),['organizations;DROP TABLE users'])
