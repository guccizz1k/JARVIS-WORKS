"""Isolated schema-level API rehearsal against review/v59-compatible SQLite columns.
NOT a substitute for the existing JARVIS WORKS full regression suite.
"""
import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from app.automation_v60 import install_schema, register_routes


@pytest.fixture
def env(tmp_path):
    db = tmp_path / 'test.db'

    @contextmanager
    def conn():
        c = sqlite3.connect(db, timeout=10, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        try:
            yield c
        finally:
            c.close()

    @contextmanager
    def tx():
        with conn() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                yield c
                c.execute('COMMIT')
            except BaseException:
                c.execute('ROLLBACK')
                raise

    with conn() as c:
        c.executescript('''
        CREATE TABLE organizations (id TEXT PRIMARY KEY,name TEXT NOT NULL);
        CREATE TABLE users(id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id));
        CREATE TABLE quotes(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,doc_no TEXT NOT NULL,
          status TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE orders(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,quote_id TEXT NOT NULL REFERENCES quotes(id),
          customer_id TEXT NOT NULL, customer_name_snapshot TEXT NOT NULL,
          doc_no TEXT NOT NULL,title TEXT NOT NULL,status TEXT NOT NULL,review_state TEXT NOT NULL,
          vat_mode TEXT NOT NULL,due_date TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE order_items(id TEXT PRIMARY KEY,order_id TEXT NOT NULL REFERENCES orders(id),
          name TEXT NOT NULL,quantity INTEGER NOT NULL,unit_price INTEGER NOT NULL,position INTEGER NOT NULL);
        CREATE TABLE invoices(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,order_id TEXT NOT NULL REFERENCES orders(id),
          doc_no TEXT NOT NULL,status TEXT NOT NULL,vat_mode TEXT NOT NULL,created_at TEXT NOT NULL);
        CREATE TABLE invoice_items(id TEXT PRIMARY KEY,invoice_id TEXT NOT NULL REFERENCES invoices(id),
          name TEXT NOT NULL,quantity INTEGER NOT NULL,unit_price INTEGER NOT NULL,position INTEGER NOT NULL);
        CREATE TABLE payments(id TEXT PRIMARY KEY,org_id TEXT NOT NULL,invoice_id TEXT NOT NULL REFERENCES invoices(id),
          amount INTEGER NOT NULL,paid_at TEXT NOT NULL,reversed_at TEXT,created_at TEXT NOT NULL);
        INSERT INTO organizations VALUES('a','A기업'),('b','B기업');
        INSERT INTO users VALUES('alice','a'),('bob','b');
        ''')
    install_schema(conn)
    install_schema(conn)  # migration idempotency

    def fake_user(request: Request):
        org = request.headers.get('X-Org', 'a')
        if org not in ('a','b'):
            raise HTTPException(status_code=401,detail='unauthorized')
        return {'org_id': org, 'id': 'alice' if org == 'a' else 'bob'}

    def row(c, table, row_id, org_id):
        data = c.execute(f'SELECT * FROM {table} WHERE id=? AND org_id=?', (row_id,org_id)).fetchone()
        if not data:
            raise HTTPException(status_code=404,detail='not found')
        return dict(data)

    def items(c, kind, pid):
        tbl, col = {'order': ('order_items','order_id'),
                    'invoice': ('invoice_items','invoice_id')}[kind]
        return [dict(x) for x in c.execute(f'SELECT * FROM {tbl} WHERE {col}=? ORDER BY position', (pid,))]

    def money(it, vat_mode):
        subtotal = sum(x['quantity']*x['unit_price'] for x in it)
        vat = (subtotal+5)//10 if vat_mode == 'taxable' else 0
        return {'subtotal':subtotal,'vat':vat,'total':subtotal+vat}

    def fail(msg, status=400):
        raise HTTPException(status_code=status,detail=msg)

    def audit(*args):
        return None

    app = FastAPI()
    register_routes(app, conn=conn, transaction=tx, current_user=fake_user, get_row=row,
                    retrieve_items=items, money=money, audit=audit,
                    ident=lambda:uuid.uuid4().hex, now=lambda:datetime.now(timezone.utc).isoformat(),
                    fail=fail)

    def add_order(order_id, org='a', status='fulfilled', review_state='clean', vat='taxable'):
        now = datetime.now(timezone.utc).isoformat()
        with conn() as c:
            c.execute('INSERT INTO quotes VALUES(?,?,?,?,?)',
                      ('q'+order_id,org,'Q-'+order_id,'accepted',now))
            c.execute('INSERT INTO orders VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
                      (order_id,org,'q'+order_id, 'cust'+org, org+' 거래처',
                       'O-'+order_id,'상품 공급',status,review_state,vat,'2099-12-30',now))
            c.execute('INSERT INTO order_items VALUES(?,?,?,?,?,?)',
                      ('line'+order_id,order_id,'부품',3,101,0))
            c.execute('INSERT INTO order_items VALUES(?,?,?,?,?,?)',
                      ('line2'+order_id,order_id,'서비스',2,503,1))

    with TestClient(app) as client:
        yield {'client':client,'conn':conn,'add_order':add_order,'db':db}


def convert(e, oid, org='a'):
    return e['client'].post('/api/automation/statements/from-order',
                            headers={'X-Org':org},json={'order_id':oid})


def test_document_one_click_and_immutable_snapshot(env):
    e=env;e['add_order']('o1')
    r=convert(e,'o1');assert r.status_code==201,r.text
    d=r.json(); assert d['document']['source_order_no']=='O-o1'
    assert d['document']['customer_name']=='a 거래처'
    assert d['document']['money']=={'subtotal':1309,'vat':131,'total':1440}
    assert d['document']['legal_status']=='internal_business_record_not_tax_invoice'
    assert [x['line_total'] for x in d['document']['items']]==[303,1006]
    r2=convert(e,'o1');assert r2.status_code==200 and r2.json()['reused'] is True
    assert d['id']==r2.json()['id']
    assert e['client'].get(f"/api/automation/statements/{d['id']}").json()['document']==d['document']
    with pytest.raises(sqlite3.DatabaseError):
        with e['conn']() as c:c.execute('DELETE FROM automation_statements_v60 WHERE id=?',(d['id'],))
    with pytest.raises(sqlite3.DatabaseError):
        with e['conn']() as c:c.execute('UPDATE automation_statements_v60 SET doc_no=? WHERE id=?',('bad',d['id']))


def test_status_and_review_gate(env):
    e=env
    e['add_order']('received',status='received')
    e['add_order']('pending',review_state='pending')
    assert convert(e,'received').status_code==409
    assert convert(e,'pending').status_code==409
    with e['conn']() as c:
        assert c.execute('SELECT count(*) FROM automation_statements_v60').fetchone()[0]==0


def test_tenant_isolation_and_direct_sql_trigger(env):
    e=env;e['add_order']('aorder');e['add_order']('border',org='b')
    stmt=convert(e,'aorder').json()
    assert convert(e,'border').status_code==404
    assert e['client'].get('/api/automation/transactions/aorder',headers={'X-Org':'b'}).status_code==404
    assert e['client'].get('/api/automation/statements/'+stmt['id'],headers={'X-Org':'b'}).status_code==404
    with pytest.raises(sqlite3.IntegrityError):
        with e['conn']() as c:
            c.execute('''INSERT INTO automation_statements_v60 VALUES(?,?,?,?,?,?,?)''',
                      ('attacker','b','aorder','bob','T','{}','now'))
    assert convert(e,'border',org='b').status_code==201


def test_transaction_graph_invoice_payments_and_reversal(env):
    e=env;e['add_order']('o1')
    s=convert(e,'o1').json()
    now=datetime.now(timezone.utc).isoformat()
    with e['conn']() as c:
        c.execute('INSERT INTO invoices VALUES(?,?,?,?,?,?,?)',('inv','a','o1','I-1','issued','taxable',now))
        c.execute('INSERT INTO invoice_items VALUES(?,?,?,?,?,?)',('ili','inv','부품',3,101,0))
        c.execute('INSERT INTO invoice_items VALUES(?,?,?,?,?,?)',('il2','inv','서비스',2,503,1))
        c.execute('INSERT INTO payments VALUES(?,?,?,?,?,?,?)',('pay1','a','inv',500,'2026-01-01',None,now))
        c.execute('INSERT INTO payments VALUES(?,?,?,?,?,?,?)',('pay2','a','inv',300,'2026-01-02',now,now))
    d=e['client'].get('/api/automation/transactions/o1').json()
    assert d['quote_id']=='qo1' and d['statement_id']==s['id'] and d['invoice_id']=='inv'
    assert d['active_paid']==500 and d['remaining_balance']==940
    assert {'quote','order','trade_statement','invoice','payment'}=={x['type'] for x in d['events']}
    assert any(x['type']=='payment' and x['status']=='reversed' for x in d['events'])


def backdate_started(e, run_id, ms):
    with e['conn']() as c:
        c.execute('UPDATE automation_task_times_v60 SET started_at=? WHERE id=?',
                  ((datetime.now(timezone.utc)-timedelta(milliseconds=ms)).isoformat(),run_id))


def start(e, mode):
    return e['client'].post('/api/automation/timing/start',
                            json={'workflow':'trade_statement','mode':mode})


def finish(e, task_id, statement_id=None):
    return e['client'].post(f'/api/automation/timing/{task_id}/finish',
                            json={'completed':True,'statement_id':statement_id})


def test_time_savings_not_measured_until_three_each(env):
    e=env
    assert e['client'].get('/api/automation/time-savings').json()['status']=='NOT_MEASURED'
    for idx in range(3):
        task=start(e,'manual');assert task.status_code==201,task.text
        rid=task.json()['id'];backdate_started(e,rid,100000+idx*1000)
        r=finish(e,rid);assert r.status_code==200,r.text
        assert r.json()['task_outcome']=='self_reported_completion'
    report=e['client'].get('/api/automation/time-savings').json()
    assert report['samples']=={'manual':3,'automated':0}
    assert report['observed_difference_ms'] is None
    for idx in range(3):
        oid=f't{idx}';e['add_order'](oid)
        task=start(e,'automated');rid=task.json()['id'];backdate_started(e,rid,10000+idx*1000)
        sid=convert(e,oid).json()['id']
        done=finish(e,rid,sid);assert done.status_code==200,done.text
        assert done.json()['task_outcome']=='linked_document'
    report=e['client'].get('/api/automation/time-savings').json()
    assert report['status']=='COMPARISON_AVAILABLE'
    assert report['samples']=={'manual':3,'automated':3}
    assert 88000<=report['observed_difference_ms']<=92000
    assert '인과적' in report['disclaimer']


def test_timing_input_security_duplicate_and_expiry(env):
    e=env;e['add_order']('a');e['add_order']('b',org='b')
    statement_b=convert(e,'b',org='b').json()['id']
    task=start(e,'automated');rid=task.json()['id']
    assert start(e,'manual').status_code==409
    assert finish(e,rid,statement_b).status_code==409
    assert finish(e,rid).status_code==409
    assert e['client'].post(f'/api/automation/timing/{rid}/finish',json={'completed':False}).status_code==422
    assert e['client'].post(f'/api/automation/timing/{rid}/finish',headers={'X-Org':'b'},json={'completed':True}).status_code==404
    sid=convert(e,'a').json()['id']
    backdate_started(e,rid,3100000)
    assert finish(e,rid,sid).status_code==409
    backdate_started(e,rid,1200)
    assert finish(e,rid,sid).status_code==200
    assert finish(e,rid,sid).status_code==409
    task=start(e,'automated');rid2=task.json()['id']
    assert finish(e,rid2,sid).status_code==409 # same output can't falsely inflate savings
    assert e['client'].post('/api/automation/timing/start',json={'workflow':'made_up','mode':'manual'}).status_code==422
    assert convert(e,'a').status_code==200


def test_manual_mode_does_not_accept_automated_document(env):
    e=env;e['add_order']('a');sid=convert(e,'a').json()['id']
    run=start(e,'manual').json()['id']
    assert finish(e,run,sid).status_code==400
    assert finish(e,run).status_code==200


def test_trace_empty_not_claim_unissued_documents(env):
    e=env;e['add_order']('o')
    data=e['client'].get('/api/automation/transactions/o').json()
    assert data['statement_id'] is None and data['invoice_id'] is None
    assert data['remaining_balance'] is None and data['active_paid']==0
    assert {ev['type'] for ev in data['events']}=={'quote','order'}


def test_automated_time_rejects_preexisting_document(env):
    e=env;e['add_order']('older')
    stmt=convert(e,'older').json()['id']
    run=start(e,'automated').json()['id']
    # Make the statement visibly older than the measurement window without
    # violating its immutable record; move the timer to a future start time.
    with e['conn']() as c:
        c.execute('UPDATE automation_task_times_v60 SET started_at=? WHERE id=?',
                  ((datetime.now(timezone.utc)+timedelta(seconds=5)).isoformat(),run))
    assert finish(e,run,stmt).status_code==409
