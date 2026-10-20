"""No live DB, imports real v3.6/v3.7/v4.4 in Codespaces, stubs locally."""
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
import sqlite3
import re
import os
import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from app import pg_evidence_shadow_v45 as audit
from app.pg_cookie_shadow_v44 import ReviewBinding

T = 'a'*32


def setup_database():
    db = sqlite3.connect(':memory:', check_same_thread=False)
    db.executescript('''
      CREATE TABLE messenger_companies(org_id TEXT PRIMARY KEY);
      CREATE TABLE messenger_connections(id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT,status TEXT);
      CREATE TABLE messenger_messages(id TEXT PRIMARY KEY,connection_id TEXT,sender_org TEXT,
        sender_user TEXT,kind TEXT,body TEXT,order_id TEXT,immutable_order_snapshot TEXT,
        actor_name TEXT,request_id TEXT,version INTEGER,created_at TEXT,edited_at TEXT,message_seq INTEGER);
      CREATE TABLE messenger_edits(id TEXT PRIMARY KEY,message_id TEXT,previous_body TEXT,
        new_body TEXT,actor_user TEXT,edited_at TEXT,version INTEGER);
      CREATE TABLE messenger_attachments(message_id TEXT PRIMARY KEY,filename TEXT,mime TEXT,
        data BLOB,size_bytes INTEGER,content_hash TEXT);
      CREATE TABLE messenger_read_positions(connection_id TEXT,org_id TEXT,last_read_rowid INTEGER,
        updated_at TEXT,last_read_seq INTEGER);
      CREATE TABLE messenger_receipts(message_id TEXT PRIMARY KEY,receiver_org TEXT,
        actor_name TEXT,receiver_user TEXT,received_at TEXT);
    ''')
    blob=b'\x00\xff\x80\x01\x00data'
    for org in ('web_a','web_b'):db.execute('INSERT INTO messenger_companies VALUES(?)',(org,))
    db.execute('INSERT INTO messenger_connections VALUES(?,?,?,?)',(T,'web_a','web_b','active'))
    rows=[('m1',T,'web_a','user_a','text','new text',None,None,'','req1',2,'t1','t2',1),
          ('m2',T,'web_b','user_b','text','첨부파일: 새파일.png',None,None,'','req2',1,'t1',None,2),
          ('m3',T,'web_a','user_a','order','발주서 X','order1','{"items": [{"name": "부품", "qty": 3}]}','담당자','req3',1,'t1',None,3)]
    db.executemany('INSERT INTO messenger_messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',rows)
    db.execute('INSERT INTO messenger_edits VALUES(?,?,?,?,?,?,?)',('e1','m1','old text','new text','user_a','t2',2))
    db.execute('INSERT INTO messenger_attachments VALUES(?,?,?,?,?,?)',('m2','새파일.png','image/png',blob,len(blob),sha256(blob).hexdigest()))
    db.execute('INSERT INTO messenger_read_positions VALUES(?,?,?,?,?)',(T,'web_a',0,'t3',2))
    db.execute('INSERT INTO messenger_receipts VALUES(?,?,?,?,?)',('m3','web_b','담당자 B','user_b','t4'))
    db.commit()
    return db


class PgCursor:
    def __init__(self,db,fail=False,hide=False):self.db=db;self.rows=[];self.fail=fail;self.hide=hide
    def execute(self,sql,values=()):
        if self.fail:raise RuntimeError('password=super-secret postgresql://credential')
        if 'SELECT 1 FROM jw_migration_v37.messenger_connections' in sql:
            self.rows=[(1,)] if not self.hide else []
            return
        assert 'jw_migration_v37.' in sql
        sql=sql.replace('jw_migration_v37.','').replace('%s','?')
        if 'message_id = ANY(?)' in sql:
            ids=values[0];sql=sql.replace('message_id = ANY(?)','message_id IN ('+','.join('?' for _ in ids)+')');values=ids
        self.rows=self.db.execute(sql,tuple(values)).fetchall()
    def fetchone(self):return self.rows[0] if self.rows else None
    def fetchall(self):return list(self.rows)


class Adapter:
    def __init__(self,db):self.db=db;self.fail=False;self.hide=False;self.calls=[]
    def _check_dsn(self):pass
    @contextmanager
    def verified_transaction(self,token,*,readonly=True):
        self.calls.append((token,readonly))
        assert readonly
        yield PgCursor(self.db,self.fail,self.hide),'web_a','user_a'


@pytest.fixture
def context(monkeypatch):
    monkeypatch.setenv('JW_PG_LAB_V44','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)
    # Unit-test seam only: real V4.5 integration uses the untouched V4.4/V4.3
    # DSN + ephemeral PG17 guard against an actual disposable database.
    def fake_gate(dsn):
        if os.environ.get('JW_ENV','').casefold()=='production' or not os.environ.get('JW_PG_LAB_V44'):
            raise RuntimeError('not authorized')
    monkeypatch.setattr(audit,'_gate',fake_gate)
    site=setup_database()
    other=setup_database()
    adapter=Adapter(other)
    binding=ReviewBinding('web_a','user_a','web_a','user_a',T,'x'*42,
       (('web_a','web_a'),('web_b','web_b')),(('user_a','user_a'),('user_b','user_b')))
    state={'binding':binding,'calls':[]}
    @contextmanager
    def sqlite_conn():
        yield site
    def broker(org,user,thread):
        state['calls'].append((org,user,thread))
        return state['binding']
    def auth(req:Request):
        if req.cookies.get('jw_local_dev_session')!='valid':
            from fastapi import HTTPException
            raise HTTPException(401,'No cookie')
        return {'org_id':'web_a','id':'user_a'}
    lab=audit.create_review_app(dsn='synthetic',adapter=adapter,sqlite_conn=sqlite_conn,
           trusted_broker=broker,website_current_user=auth)
    client=TestClient(lab,raise_server_exceptions=False)
    client.cookies.set('jw_local_dev_session','valid')
    yield client,site,other,adapter,state
    client.close();site.close();other.close()


def url(thread=T):return f'/lab45/threads/{thread}/evidence'


def test_all_five_evidence_categories_exact_match(context):
    client,site,other,adapter,state=context
    resp=client.get(url())
    assert resp.status_code==200,resp.text
    obj=resp.json()
    assert obj['status']=='MATCH' and obj['evidence_parity'] and not obj['cutover_approved']
    assert obj['counts']=={'messenger_messages':3,'messenger_edits':1,
       'messenger_attachments':1,'messenger_read_positions':1,'messenger_receipts':1}
    assert state['calls']==[('web_a','user_a',T)]
    assert adapter.calls==[('x'*42,True)]
    assert resp.headers['cache-control']=='no-store'
    assert '새파일' not in resp.text and 'postgresql://' not in resp.text


@pytest.mark.parametrize('table,sql,args',[
    ('file-bytes','UPDATE messenger_attachments SET data=? WHERE message_id=?',(b'garbled','m2')),
    ('file-name','UPDATE messenger_attachments SET filename=? WHERE message_id=?',('altered.png','m2')),
    ('file-hash','UPDATE messenger_attachments SET content_hash=? WHERE message_id=?',('wrong','m2')),
    ('edit-version','UPDATE messenger_edits SET version=? WHERE id=?',(9,'e1')),
    ('edit-prior','UPDATE messenger_edits SET previous_body=? WHERE id=?',('forged','e1')),
    ('order-snapshot','UPDATE messenger_messages SET immutable_order_snapshot=? WHERE id=?',('{}','m3')),
    ('receipt','UPDATE messenger_receipts SET actor_name=? WHERE message_id=?',('wrong','m3')),
    ('read-position','UPDATE messenger_read_positions SET last_read_seq=? WHERE org_id=?',(1,'web_a')),
    ('missing-file','DELETE FROM messenger_attachments WHERE message_id=?',('m2',)),
    ('missing-receipt','DELETE FROM messenger_receipts WHERE message_id=?',('m3',)),
    ('missing-edit','DELETE FROM messenger_edits WHERE id=?',('e1',)),
    ('body','UPDATE messenger_messages SET body=? WHERE id=?',('forged','m1')),
])
def test_tampering_detected(context,table,sql,args):
    client,site,other,*_=context
    other.execute(sql,args);other.commit()
    r=client.get(url())
    assert r.status_code==200 and r.json()['status']=='MISMATCH'
    assert not r.json()['evidence_parity'] and not r.json()['cutover_approved']


def test_missing_cookie_never_calls_broker(context):
    client,site,other,adapter,state=context
    client.cookies.clear()
    r=client.get(url())
    assert r.status_code==401 and state['calls']==[] and adapter.calls==[]


def test_header_spoof_is_not_broker(context):
    client,site,other,adapter,state=context
    client.cookies.clear()
    assert client.get(url(),headers={'X-JW-Lab-Session':'x'*42}).status_code==401
    assert not adapter.calls


def test_unauthorized_other_thread_404(context):
    client,site,other,adapter,state=context
    r=client.get(url('b'*32))
    assert r.status_code==404 and not adapter.calls


def test_invalid_thread_denied_before_read(context):
    client,site,other,adapter,state=context
    for p in ('xx','../secrets','A'*32):
        assert client.get(url(p)).status_code in (404,422)
    assert not adapter.calls


def test_only_get_exposes_evidence(context):
    client,*_=context
    assert client.post(url()).status_code==405
    assert client.put(url()).status_code==405


def test_pg_credentials_never_leak(context):
    client,site,other,adapter,*_=context
    adapter.fail=True
    r=client.get(url())
    assert r.status_code==503 and r.json()['code']=='PG_UNAVAILABLE'
    assert 'postgresql://' not in r.text and 'super-secret' not in r.text


def test_missing_pg_thread_denied(context):
    client,site,other,adapter,*_=context
    adapter.hide=True
    assert client.get(url()).status_code==404


def test_unverified_partner_rejected_before_pg(context):
    client,site,other,adapter,state=context
    site.execute("DELETE FROM messenger_companies WHERE org_id='web_b'");site.commit()
    assert client.get(url()).status_code==404 and adapter.calls==[]


def test_broker_identity_mismatch_denied(context):
    client,site,other,adapter,state=context
    state['binding']=replace(state['binding'],source_org='outsider')
    r=client.get(url())
    assert r.status_code==403 and not r.json().get('evidence_parity')


def test_oversized_rowset_is_incomplete(context):
    client,site,other,adapter,state=context
    for i in range(audit.MAX_MESSAGES):
        site.execute('INSERT INTO messenger_messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
           (f'new{i}',T,'web_a','user_a','text','hi',None,None,'',f'r{i}',1,'t1',None,4+i))
    site.commit()
    r=client.get(url())
    assert r.status_code==200 and r.json()['status']=='INCOMPLETE'
    assert not adapter.calls


def test_limit_no_false_match(monkeypatch,context):
    client,site,other,adapter,state=context
    monkeypatch.setattr(audit,'MAX_TOTAL_BYTES',50)
    r=client.get(url())
    assert r.status_code==200 and r.json()['status']=='INCOMPLETE'


def test_unsupported_mapping_denied(context):
    client,site,other,adapter,state=context
    state['binding']=replace(state['binding'],pg_to_source_user=(('user_a','wrong'),('user_b','user_b')))
    assert client.get(url()).status_code==403


def test_empty_not_evidence_match(context):
    client,site,other,adapter,state=context
    for name in ('messenger_edits','messenger_attachments','messenger_receipts'):
        site.execute(f'DELETE FROM {name}');other.execute(f'DELETE FROM {name}')
    site.commit();other.commit()
    r=client.get(url())
    assert r.json()['status']=='EMPTY_EVIDENCE' and not r.json()['evidence_parity']


def test_synthetic_authority_flag_cannot_be_removed(context,monkeypatch):
    client,site,other,adapter,state=context
    monkeypatch.delenv('JW_PG_LAB_V44')
    assert client.get(url()).status_code==503 and adapter.calls==[]


def test_production_never_constructs_app(context,monkeypatch):
    client,site,other,adapter,state=context
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(RuntimeError):
        audit.create_review_app(dsn='synthetic',adapter=adapter,sqlite_conn=lambda:None,
         trusted_broker=lambda *a: None,website_current_user=lambda r:None)


def test_scope_marker_never_approves_cutover(context):
    r=context[0].get(url()).json()
    assert r['scope']=='single_thread_requester_read_marker'
    assert not r['cutover_approved']
