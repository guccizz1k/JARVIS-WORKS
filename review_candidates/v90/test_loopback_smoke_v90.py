"""TCP/WS smoke test with a synthetic in-memory gateway. NOT PostgreSQL E2E."""
import socket
import threading
import time
import hashlib
import hmac
import json
from datetime import datetime, timezone
from fastapi import FastAPI
import pytest
import httpx
import uvicorn
from websockets.sync.client import connect as ws_connect
from pg_messenger_bridge_v90 import SQL, VerifiedSession, create_router
from pg_messenger_realtime_v90 import create_realtime_router

KEY=b'V90-STAGING-ONLY-NO-PRODUCTION-SECRETS'
def cookie(org):
    value='synthetic:'+org
    return value+'.'+hmac.new(KEY,value.encode(),'sha256').hexdigest()
def auth(req):
    token=req.cookies.get('jw_session','')
    try:
        name,sig=token.rsplit('.',1)
        if name not in ('synthetic:A','synthetic:B','synthetic:C') or not hmac.compare_digest(sig,hmac.new(KEY,name.encode(),'sha256').hexdigest()):return None
    except ValueError:return None
    csrf=getattr(req,'method','GET')=='GET' or req.headers.get('x-csrf-token')=='synthetic-csrf'
    return VerifiedSession(hashlib.sha256(name.encode()).hexdigest(),csrf)
class AccessDenied(Exception):sqlstate='42501'
class Gateway:
    def __init__(self):self.items=[]
    def query(self,session_hash,sql,params):
        org=next((o for o in 'ABC' if session_hash==hashlib.sha256(('synthetic:'+o).encode()).hexdigest()),None)
        if not org:raise AccessDenied()
        if sql==SQL['directory']:
            return [{'org_id':o,'company_name':o} for o in 'ABC' if o!=org]
        if sql==SQL['messages']:
            if org not in 'AB' or params[0]!='chat-AB':raise AccessDenied()
            return [x for x in self.items if x['message_cursor']>params[1]][:params[2]]
        if sql==SQL['edits']:
            if org not in 'AB' or params[0]!='chat-AB':raise AccessDenied()
            return []
        if sql==SQL['send']:
            if org!='A' or params[0]!='chat-AB':raise AccessDenied()
            row={'message_id':'m'+str(len(self.items)+1),'message_cursor':len(self.items)+1,'sender_org':org,'body':params[2],'version':1,'created_at':datetime.now(timezone.utc).isoformat()}
            self.items.append(row)
            return [{'message_id':row['message_id'],'message_cursor':row['message_cursor'],'replayed':False}]
        raise AccessDenied()
@pytest.fixture
def server():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0));port=s.getsockname()[1]
    app=FastAPI();gw=Gateway();app.include_router(create_router(gw,auth))
    app.include_router(create_realtime_router(gw,auth,allowed_origins=frozenset({f'http://127.0.0.1:{port}'}),poll_seconds=.05,heartbeat_every=10))
    worker=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='error',access_log=False))
    thread=threading.Thread(target=worker.run,daemon=True);thread.start()
    for _ in range(100):
        if worker.started:break
        time.sleep(.03)
    assert worker.started
    try:yield f'http://127.0.0.1:{port}',f'ws://127.0.0.1:{port}'
    finally:worker.should_exit=True;thread.join(timeout=5);assert not thread.is_alive()
def test_real_socket_auth_and_csrf_and_cross_tenant(server):
    base,_=server;uri=base+'/api/pg-stage/v90/chats/chat-AB/messages'
    with httpx.Client(trust_env=False) as c:
        assert c.get(uri).status_code==401
        assert c.get(uri,cookies={'jw_session':'forged'}).status_code==401
        assert c.post(uri,cookies={'jw_session':cookie('A')},json={'request_id':'12345678','body':'hello'}).status_code==403
        r=c.post(uri,cookies={'jw_session':cookie('A')},headers={'x-csrf-token':'synthetic-csrf'},json={'request_id':'12345678','body':'hello'})
        assert r.status_code==200
        assert len(c.get(uri,cookies={'jw_session':cookie('B')}).json())==1
        assert c.get(uri,cookies={'jw_session':cookie('C')}).status_code==403
def test_real_socket_ws_delivery_and_reconnect(server):
    base,wsbase=server;url=wsbase+'/api/pg-stage/v90/chats/chat-AB/stream'
    headers={'Cookie':'jw_session='+cookie('B')}
    with ws_connect(url,origin=base,additional_headers=headers,open_timeout=3,close_timeout=1) as ws:
        assert json.loads(ws.recv(timeout=3))['type']=='ready'
        with httpx.Client(trust_env=False) as c:
            resp=c.post(base+'/api/pg-stage/v90/chats/chat-AB/messages',cookies={'jw_session':cookie('A')},headers={'x-csrf-token':'synthetic-csrf'},json={'request_id':'req-smoke-100','body':'socket proof'})
            assert resp.status_code==200
            after=resp.json()['message_cursor']
        for _ in range(15):
            frame=json.loads(ws.recv(timeout=3))
            if frame['type']=='message' and frame['data']['body']=='socket proof':break
        else:pytest.fail('Websocket message missing')
    with ws_connect(url+'?after='+str(after-1),origin=base,additional_headers=headers,open_timeout=3,close_timeout=1) as ws:
        assert json.loads(ws.recv(timeout=3))['type']=='ready'
        for _ in range(15):
            frame=json.loads(ws.recv(timeout=3))
            if frame['type']=='message':
                assert frame['data']['message_cursor']==after
                break
        else:pytest.fail('Reconnect replay missing')
