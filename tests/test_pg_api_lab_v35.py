"""Mocked transport contracts; separate live PG17 suite tests actual RLS."""
import os
import pytest
from fastapi.testclient import TestClient
from app.pg_messenger_lab import create_lab_app
from app.pg_messenger_review import PostgreSQLUnverified

DSN = 'postgresql://jw_app:synthetic@127.0.0.1/jw_v20_test_abcdef123456'
TOKEN = 'x'*48

class Stub:
    dsn = DSN
    def __init__(self):self.calls=[];self.fail=None
    def _check_dsn(self):pass
    def list_messages(self,t,thread,*,after,limit):
        self.calls.append(('list',t,thread,after,limit))
        if self.fail:raise self.fail
        return [('m1',1,'tenant_a','ua','text','hello','2026-01-01')]
    def send_text(self,t,thread,content,request_id):
        self.calls.append(('send',t,thread,content,request_id))
        if self.fail:raise self.fail
        return ('m2',2)
    def mark_read(self,t,thread,seq):
        self.calls.append(('read',t,thread,seq))
        if self.fail:raise self.fail
        return True

@pytest.fixture
def lab(monkeypatch):
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')
    s=Stub()
    return TestClient(create_lab_app(adapter=s)),s

def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv('JW_PG_ALLOW_TEST_WRITES',raising=False)
    with pytest.raises(PostgreSQLUnverified): create_lab_app(dsn=DSN)

def test_nonlocal_dsn_refused_before_server(monkeypatch):
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')
    with pytest.raises(PostgreSQLUnverified):
        create_lab_app(dsn='postgresql://jw_app:pw@db.example.com/production')

def test_no_auth_and_strict_input(lab):
    client,s=lab
    assert client.get('/lab/threads/chat_ab/messages').status_code==401
    assert client.get('/lab/threads/chat_ab/messages',headers={'X-JW-Lab-Session':'short'}).status_code==401
    assert client.get('/lab/threads/a%20b/messages',headers={'X-JW-Lab-Session':TOKEN}).status_code==422
    assert client.get('/lab/threads/chat_ab/messages?limit=101',headers={'X-JW-Lab-Session':TOKEN}).status_code==422
    assert client.put('/lab/threads/chat_ab/read',headers={'X-JW-Lab-Session':TOKEN},json={'last_seq':-1}).status_code==422
    assert not s.calls

def test_list_post_and_read(lab):
    client,s=lab; h={'X-JW-Lab-Session':TOKEN}
    first = client.get('/lab/threads/chat_ab/messages?after=1&limit=10',headers=h).json()['messages'][0]
    assert first['id']=='m1' and first['sender_org']=='tenant_a' and 'sender_user' not in first
    r=client.post('/lab/threads/chat_ab/messages',headers=h,json={'content':'hi','request_id':'f'*32})
    assert r.status_code==201 and r.json()['message_seq']==2
    assert client.put('/lab/threads/chat_ab/read',headers=h,json={'last_seq':1}).json()=={'ok':True}
    assert s.calls==[('list',TOKEN,'chat_ab',1,10),('send',TOKEN,'chat_ab','hi','f'*32),('read',TOKEN,'chat_ab',1)]

def test_error_response_redacts_session_and_dsn(lab):
    client,s=lab; h={'X-JW-Lab-Session':TOKEN};s.fail=RuntimeError('secret '+TOKEN+' db='+DSN)
    r=client.get('/lab/threads/chat_ab/messages',headers=h)
    assert r.status_code==503 and TOKEN not in r.text and DSN not in r.text

def test_unverified_session_fails_closed(lab):
    client,s=lab; s.fail=PostgreSQLUnverified('synthetic denied')
    assert client.post('/lab/threads/chat_ab/messages',headers={'X-JW-Lab-Session':TOKEN},json={'content':'ok','request_id':'f'*32}).status_code==403

def test_not_available_through_main_app():
    from app.main import app
    assert not any(r.path.startswith('/lab/') for r in app.routes)
