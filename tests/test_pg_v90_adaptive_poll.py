"""Failing-first contracts for safe bounded adaptive WS polling.

Uses model gateway and ASGI WebSocket TestClient, not a production database.
"""
from __future__ import annotations

from threading import Lock
from time import monotonic, sleep
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.pg_messenger_bridge_v90 import SQL, VerifiedSession
from app.pg_messenger_realtime_v90 import create_realtime_router, next_poll_delay


def test_idle_backoff_is_bounded_and_no_delay_on_activity():
    assert next_poll_delay(0.3, 0) == pytest.approx(0.3)
    assert next_poll_delay(0.3, 8) == pytest.approx(0.3)
    assert next_poll_delay(0.3, 9) > 0.3
    assert next_poll_delay(0.3, 999) <= 1.2
    assert next_poll_delay(0.02, 999) <= 0.08
    assert next_poll_delay(0.02, 0) == pytest.approx(0.02)


class FakeGateway:
    def __init__(self):
        self.lock=Lock()
        self.message_calls=0
        self.items=[]
        self.deny=False

    def query(self, session_hash, sql, params):
        with self.lock:
            if self.deny:
                raise PermissionError('session revoked')
            if sql==SQL['messages']:
                self.message_calls+=1
                return [x for x in self.items if x['message_cursor']>params[1]]
            if sql==SQL['edits']:
                return []
        raise AssertionError('Unknown SQL')


def open_client(gateway, *, poll_seconds=.02):
    app=FastAPI()
    app.include_router(create_realtime_router(gateway,lambda ws: VerifiedSession('s'*64,True),
                                               allowed_origins=frozenset({'https://testserver'}),
                                               poll_seconds=poll_seconds,heartbeat_every=2000))
    return TestClient(app)


def test_idle_session_reduces_db_reads_without_losing_cursor():
    gateway=FakeGateway()
    with open_client(gateway) as client:
        with client.websocket_connect('/api/pg-stage/v90/chats/a/stream',headers={'Origin':'https://testserver'}) as ws:
            assert ws.receive_json()['type']=='ready'
            sleep(.70)
            # Baseline constant 20-ms polling would execute ~35 queries. Adaptive
            # WS must query notably fewer times after its initial 8 low-latency polls.
            with gateway.lock:
                calls=gateway.message_calls
            assert calls < 27, f'Idle polling did not back off: {calls} queries'
            gateway.items.append({'message_id':'a1','message_cursor':1,'body':'new message'})
            reply=ws.receive_json()
            assert reply['type']=='message' and reply['data']['message_cursor']==1


def test_idle_poll_keeps_session_revocation_fail_closed():
    gateway=FakeGateway()
    with open_client(gateway) as client:
        with client.websocket_connect('/api/pg-stage/v90/chats/a/stream',headers={'Origin':'https://testserver'}) as ws:
            assert ws.receive_json()['type']=='ready'
            sleep(.24)  # ensure it is already in idle backoff
            gateway.deny=True
            with pytest.raises(WebSocketDisconnect) as err:
                ws.receive_json()
            assert err.value.code==1008


def test_idle_backoff_does_not_delay_periodic_heartbeat():
    gateway=FakeGateway()
    app=FastAPI()
    app.include_router(create_realtime_router(
        gateway, lambda _:VerifiedSession('s'*64,True),
        allowed_origins=frozenset({'https://testserver'}),
        poll_seconds=.02, heartbeat_every=5))
    with TestClient(app) as client:
        with client.websocket_connect('/api/pg-stage/v90/chats/a/stream',headers={'Origin':'https://testserver'}) as ws:
            assert ws.receive_json()['type']=='ready'
            for _ in range(4):
                start=monotonic()
                frame=ws.receive_json()
                assert frame['type']=='heartbeat'
                assert monotonic()-start < 0.22, 'Idle backoff delayed proxy keepalive too long'
