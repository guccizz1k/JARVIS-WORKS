"""Fake psycopg implicit transaction model: tests that would fail a real DB lock probe.

A SELECT opens a transaction on psycopg connections when autocommit=False.
A nested conn.transaction() then creates a SAVEPOINT rather than committing
that outer transaction. The advisory lock does not release at savepoint exit.
"""
from contextlib import contextmanager
import pytest
from pg_advisory_probe_v90 import probe, assert_nonprivileged

class ImplicitTransactionFake:
    holders={}

    def __init__(self, key, *, admin=False):
        self.key=key
        self.autocommit=False
        self.transaction_depth=0
        self.implicit=False
        self.held=set()
        self.closed=False
        self.admin=admin

    @contextmanager
    def cursor(self):
        yield self

    def execute(self, sql, args=()):
        if not self.autocommit and not self.transaction_depth:
            self.implicit=True
        if 'rolsuper, rolbypassrls' in sql:
            self.result=(self.admin, False)
        else:
            assert 'pg_try_advisory_xact_lock' in sql
            chat=args[0]
            owner=self.holders.get(chat)
            acquired= owner is None or owner==self.key
            if acquired:
                self.holders[chat]=self.key
                self.held.add(chat)
            self.result=(acquired,)
            if self.autocommit and self.transaction_depth==0:
                self.release()

    def fetchone(self):
        return self.result

    def release(self):
        for key in list(self.held):
            if self.holders.get(key)==self.key:self.holders.pop(key)
        self.held.clear()

    @contextmanager
    def transaction(self):
        nested=self.implicit or self.transaction_depth>0
        self.transaction_depth+=1
        try:yield self
        finally:
            self.transaction_depth-=1
            if not nested and self.transaction_depth==0:self.release()

    def close(self):
        self.release();self.closed=True


def make_factory(*,admin=False):
    ImplicitTransactionFake.holders={}
    conns=[]
    def connect():
        c=ImplicitTransactionFake('connection-'+str(len(conns)),admin=admin)
        conns.append(c)
        return c
    return connect,conns


def test_probe_does_not_keep_implicit_transaction_open_after_role_query():
    factory,conns=make_factory()
    result=probe(factory)
    assert result['second_connection_blocked']
    assert result['other_chat_unblocked']
    assert result['commit_releases_lock']
    assert len(conns)==2
    assert all(conn.closed for conn in conns)


def test_probe_does_not_use_privileged_postgres_user():
    factory,conns=make_factory(admin=True)
    with pytest.raises(PermissionError):probe(factory)
    assert all(conn.closed for conn in conns)


def test_probe_sets_autocommit_before_any_security_lookup():
    factory,conns=make_factory()
    probe(factory)
    assert all(conn.autocommit for conn in conns)
