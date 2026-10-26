from contextlib import contextmanager
from datetime import date, datetime

import pytest
from app import pg_finance_v83 as stage


class Cursor:
    def __init__(self, result):
        self.result=result
        self.query=None
        self.params=None
    def execute(self, sql, values):
        self.query=sql
        self.params=values
    def fetchone(self):
        return self.result


@pytest.fixture
def test_conn(monkeypatch):
    instances=[]
    @contextmanager
    def gate(connection, **kw):
        assert connection is not None
        assert kw == {'raw_session_token': 'some-token', 'actor_id':'u1', 'org_id':'org1'}
        cursor=Cursor(('p123',))
        instances.append(cursor)
        yield cursor
    monkeypatch.setattr(stage, 'validated_pg_session', gate)
    return instances


def details():
    return dict(token='some-token', actor_id='u1',org_id='org1')


def test_payment_bound_arguments(test_conn):
    receipt=stage.record_payment_stage(test_conn, invoice_id='inv1',amount=100,paid_at=date(2026,10,23),reference='pay-ref-123',note='cash',**details())
    assert receipt=='p123'
    c=test_conn[-1]
    assert c.params==('inv1',100,date(2026,10,23),'pay-ref-123','cash')
    assert '%s' in c.query and 'record_payment_v83' in c.query


@pytest.mark.parametrize('changed', [
    {'amount':0}, {'amount':-1}, {'amount':True}, {'amount':10**16+1},
    {'paid_at':'2026-10-23'}, {'paid_at':datetime(2026,10,23)},
    {'reference':'short'}, {'reference':'x'*101},
    {'note':'x'*301}, {'invoice_id':''}, {'invoice_id':None},
])
def test_invalid_payment_does_not_open_transaction(test_conn,changed):
    kw={**details(),'invoice_id':'inv1','amount':100,'paid_at':date(2026,10,23),'reference':'reference123'}
    kw.update(changed)
    with pytest.raises(stage.FinanceInputError): stage.record_payment_stage(test_conn,**kw)
    assert not test_conn


def test_reverse_rpc_requires_success(test_conn,monkeypatch):
    @contextmanager
    def ok_gate(connection,**kw):
        c=Cursor((True,));test_conn.append(c);yield c
    monkeypatch.setattr(stage,'validated_pg_session',ok_gate)
    stage.reverse_payment_stage(test_conn, invoice_id='inv1',payment_id='p1', **details())
    assert test_conn[-1].params==('inv1','p1')


def test_reverse_failure_raises(test_conn,monkeypatch):
    @contextmanager
    def bad_gate(connection,**kw):yield Cursor((False,))
    monkeypatch.setattr(stage,'validated_pg_session',bad_gate)
    with pytest.raises(RuntimeError,match='did not confirm'):
        stage.reverse_payment_stage(test_conn,invoice_id='inv1',payment_id='p1',**details())


def test_reverse_missing_payment_id_blocked(test_conn):
    with pytest.raises(stage.FinanceInputError):
        stage.reverse_payment_stage(test_conn,invoice_id='inv1',payment_id='',**details())
    assert not test_conn
