"""Isolated WebSocket transport tests; stubbed database != live PostgreSQL E2E."""
from __future__ import annotations

import threading
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI, WebSocket
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from pg_messenger_bridge_v90 import VerifiedSession
from pg_messenger_realtime_v90 import create_realtime_router

ORIGIN = 'https://dev.test.invalid'


class Denied(Exception):
    sqlstate = '42501'


class ChatDB:
    def __init__(self):
        self._lock = threading.Lock()
        self.rows = []
        self.edits = []
        self.revoked = set()
        self.calls = []

    def query(self, session_hash, sql, params):
        with self._lock:
            self.calls.append((session_hash, sql, params))
            if session_hash in self.revoked or session_hash not in ('A'*64, 'B'*64):
                raise Denied('unauthorized')
            if 'v90_sync_messages' in sql:
                cid, after, limit = params
                if cid != 'ab-chat': raise Denied('not member')
                return [dict(x) for x in self.rows if x['message_cursor'] > after][:limit]
            if 'v90_sync_edits' in sql:
                cid, after_dt, after_id, limit = params
                if cid != 'ab-chat': raise Denied('not member')
                return [dict(x) for x in self.edits if (datetime.fromisoformat(x['edited_at']), x['edit_id']) > (after_dt, after_id)][:limit]
            raise AssertionError(sql)

    def post(self, seq, body):
        with self._lock:
            self.rows.append({'message_id': 'm'+str(seq), 'message_cursor': seq, 'sender_org':'A', 'body':body, 'version':1})

    def edit(self, edit_id):
        with self._lock:
            self.edits.append({'edit_id':edit_id, 'message_id':'m1','version':2,
                               'new_body':'changed','edited_at':'2026-10-23T12:00:00+00:00'})


@pytest.fixture
def env():
    db=ChatDB()
    def authorize(ws: WebSocket):
        c = ws.cookies.get('session')
        if c not in ('A', 'B', 'C'):
            raise PermissionError('Missing session')
        return VerifiedSession(c*64, csrf_verified=False)
    app=FastAPI()
    app.include_router(create_realtime_router(db,authorize,allowed_origins=frozenset({ORIGIN}),poll_seconds=.02,heartbeat_every=2))
    return TestClient(app),db


def connect(client, org='A', after=0, **kwargs):
    return client.websocket_connect('/api/pg-stage/v90/chats/ab-chat/stream?after='+str(after),
                                   headers={'Origin':kwargs.get('origin', ORIGIN),'Cookie':'session='+org})


def test_ws_live_relay_a_to_b(env):
    client,db=env
    with connect(client,'B') as ws:
        assert ws.receive_json()['type']=='ready'
        db.post(1, '안녕')
        assert ws.receive_json()['type']=='message'
        # next event may be heartbeat; content transmitted with correct source sequence


def test_ws_reconnect_missed_messages(env):
    client,db=env
    db.post(1,'first')
    with connect(client,'A') as ws:
        assert ws.receive_json()['type']=='ready'
        assert ws.receive_json()['data']['message_cursor']==1
    db.post(2,'offline')
    with connect(client,'A',after=1) as ws:
        assert ws.receive_json()['type']=='ready'
        assert ws.receive_json()['data']['message_cursor']==2


def test_ws_edit_replay(env):
    client,db=env
    db.edit('edit-0001')
    with connect(client,'B') as ws:
        assert ws.receive_json()['type']=='ready'
        received=ws.receive_json()
        assert received['type']=='edit'
        assert received['data']['new_body']=='changed'


def test_ws_cannot_subscribe_foreign_chat(env):
    client,db=env
    with pytest.raises(WebSocketDisconnect) as ex:
        with connect(client,'C') as ws: ws.receive_json()
    assert ex.value.code == 1008


def test_ws_rejects_invalid_origin(env):
    client,db=env
    with pytest.raises(WebSocketDisconnect) as ex:
        with connect(client,'A',origin='https://attacker.invalid') as ws: ws.receive_json()
    assert ex.value.code == 1008
    assert not db.calls


def test_ws_rejects_missing_session(env):
    client,db=env
    with pytest.raises(WebSocketDisconnect) as ex:
        with client.websocket_connect('/api/pg-stage/v90/chats/ab-chat/stream',headers={'Origin':ORIGIN}) as ws: ws.receive_json()
    assert ex.value.code == 1008


def test_ws_rejects_invalid_cursor(env):
    client,db=env
    with pytest.raises(WebSocketDisconnect):
        with connect(client,'A',after=-1) as ws: ws.receive_json()


def test_ws_rejects_invalid_configuration():
    with pytest.raises(ValueError): create_realtime_router(ChatDB(),lambda _: VerifiedSession('A'*64,False),allowed_origins=frozenset())


def test_ws_revoked_during_active_socket(env):
    client,db=env
    with connect(client,'B') as ws:
        assert ws.receive_json()['type']=='ready'
        db.revoked.add('B'*64)
        # authorization failure closes connection on the next DB polling cycle
        with pytest.raises(WebSocketDisconnect) as ex:
            for _ in range(10): ws.receive_json()
        assert ex.value.code == 1008
