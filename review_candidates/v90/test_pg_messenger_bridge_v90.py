import base64
from dataclasses import dataclass
import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from pg_messenger_bridge_v90 import VerifiedSession, create_router, PsycopgGateway

class Stub:
    def __init__(self): self.calls=[]; self.error=None
    def query(self, session_hash, sql, params):
        self.calls.append((session_hash,sql,params))
        if self.error: raise self.error
        if 'v90_start_chat' in sql: return [{'connection_id':'chat-1'}]
        if 'v90_send_text' in sql: return [{'message_id':'message-1','message_cursor':1,'replayed':False}]
        if 'v90_mark_read' in sql: return [{'cursor':1}]
        if 'v90_edit_text' in sql: return [{'version':2}]
        return []

@pytest.fixture
def client():
    gateway=Stub()
    def auth(request):
        if request.headers.get('X-Test-Auth')!='yes': raise HTTPException(401,'Session required')
        return VerifiedSession('a'*64,request.headers.get('X-CSRF-Token')=='server-verified')
    app=FastAPI();app.include_router(create_router(gateway,auth))
    return TestClient(app),gateway

def test_denies_missing_auth(client):
    c,g=client
    assert c.get('/api/pg-stage/v90/companies').status_code==401
    assert not g.calls

def test_denies_csrf(client):
    c,g=client
    r=c.post('/api/pg-stage/v90/chats',json={'other_org_id':'B'},headers={'X-Test-Auth':'yes'})
    assert r.status_code==403
    assert not g.calls

def test_search(client):
    c,g=client
    r=c.get('/api/pg-stage/v90/companies?q=%EA%B0%80%EC%98%A8&limit=10',headers={'X-Test-Auth':'yes'})
    assert r.status_code==200
    assert g.calls[0][2]==('가온',10,0)

def test_send_and_attachment(client):
    c,g=client
    r=c.post('/api/pg-stage/v90/chats/chat-1/messages',headers={'X-Test-Auth':'yes','X-CSRF-Token':'server-verified'},json={'request_id':'request-0001','body':'hi','filename':'hello.txt','mime':'text/plain','data_base64':base64.b64encode(b'hello').decode()})
    assert r.status_code==200
    assert g.calls[0][2][-1]==b'hello'

def test_bad_attachment_rejected(client):
    c,g=client
    r=c.post('/api/pg-stage/v90/chats/chat-1/messages',headers={'X-Test-Auth':'yes','X-CSRF-Token':'server-verified'},json={'request_id':'request-0001','body':'hi','data_base64':'!!bad!!'})
    assert r.status_code==422
    assert not g.calls

def test_large_attachment_rejected(client):
    c,g=client
    r=c.post('/api/pg-stage/v90/chats/chat-1/messages',headers={'X-Test-Auth':'yes','X-CSRF-Token':'server-verified'},json={'request_id':'request-0001','body':'hi','data_base64':base64.b64encode(b'0'*5242881).decode()})
    assert r.status_code==413
    assert not g.calls

def test_start_read_edit_reconnect(client):
    c,g=client
    headers={'X-Test-Auth':'yes','X-CSRF-Token':'server-verified'}
    assert c.post('/api/pg-stage/v90/chats',headers=headers,json={'other_org_id':'B'}).json()['connection_id']=='chat-1'
    assert c.post('/api/pg-stage/v90/chats/chat-1/read',headers=headers,json={'cursor':1}).json()['cursor']==1
    assert c.patch('/api/pg-stage/v90/messages/m1',headers=headers,json={'body':'hello','expected_version':1}).json()['version']==2
    assert c.get('/api/pg-stage/v90/chats/chat-1/messages?after=2',headers=headers).status_code==200
    assert c.get('/api/pg-stage/v90/chats/chat-1/edits',headers=headers).status_code==200
    assert len(g.calls)==5

def test_rejects_cursor_and_paging(client):
    c,g=client
    assert c.get('/api/pg-stage/v90/chats/c/messages?after=-1',headers={'X-Test-Auth':'yes'}).status_code==422
    assert c.get('/api/pg-stage/v90/companies?limit=501',headers={'X-Test-Auth':'yes'}).status_code==422
    assert not g.calls

@pytest.mark.parametrize('sqlstate,status',[('42501',403),('23514',422),('23505',409),('40001',409),(None,503)])
def test_db_errors_sanitized(client,sqlstate,status):
    c,g=client
    class FakeError(Exception): pass
    error=FakeError('Do not leak raw DB errors');error.sqlstate=sqlstate
    g.error=error
    r=c.get('/api/pg-stage/v90/chats/chat-1/messages',headers={'X-Test-Auth':'yes'})
    assert r.status_code==status
    assert 'Do not leak' not in r.text

def test_gateway_session_guc_first():
    statements=[]
    class Cur:
        description=[type('C',(),{'name':'val'})()]
        def __enter__(self): return self
        def __exit__(self,*args):pass
        def execute(self,sql,params):statements.append((sql,params))
        def fetchall(self):return [(1,)]
    class Conn:
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def transaction(self):return self
        def cursor(self):return Cur()
    rows=PsycopgGateway(lambda:Conn()).query('a'*64,'SELECT 1',())
    assert rows==[{'val':1}]
    assert statements[0][0].startswith('SELECT set_config')
    assert statements[1][0]=='SELECT 1'
