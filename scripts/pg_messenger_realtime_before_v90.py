"""V9.0 isolated polling-over-WebSocket bridge (staging only).

HTTP commits are the sole source of truth; WS emits an authorized DB cursor stream.
Not mounted into production. Requires caller-supplied genuine auth verification,
strict browser Origin allowlist, and real non-privileged PostgreSQL connections.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from .pg_messenger_bridge_v90 import SQL, SQLGateway, VerifiedSession


def create_realtime_router(
    gateway: SQLGateway,
    authorize: Callable[[WebSocket], VerifiedSession],
    *,
    allowed_origins: frozenset[str],
    poll_seconds: float = 0.3,
    heartbeat_every: int = 20,
) -> APIRouter:
    """Auth checks are repeated by the Postgres RPC on every cycle.

    Transport never writes to DB and never accepts messages from client over WS:
    edits/sends use CSRF-protected HTTP endpoints. Client stores cursors after
    applying each event and sends them back on reconnect to replay missed rows.
    """
    if not allowed_origins or any(not origin.startswith(('https://', 'http://')) for origin in allowed_origins):
        raise ValueError('Explicit origin allowlist required')
    if not 0.02 <= poll_seconds <= 10 or heartbeat_every < 1:
        raise ValueError('Invalid realtime polling configuration')

    router = APIRouter(prefix='/api/pg-stage/v90', tags=['messenger-stage-realtime'])

    @router.websocket('/chats/{connection_id}/stream')
    async def stream(
        ws: WebSocket,
        connection_id: str,
        after: int = 0,
        edit_after_at: str = '1970-01-01T00:00:00+00:00',
        edit_after_id: str = '',
    ) -> None:
        if ws.headers.get('origin') not in allowed_origins:
            await ws.close(code=1008)
            return
        if after < 0 or len(connection_id) > 128 or not connection_id or len(edit_after_id) > 128:
            await ws.close(code=1008)
            return
        try:
            edt = datetime.fromisoformat(edit_after_at)
            if edt.tzinfo is None:
                raise ValueError('Naive datetime')
            # Session validation performs a PostgreSQL round trip. Never block the ASGI event loop.
            identity = await run_in_threadpool(authorize, ws)
            if not isinstance(identity, VerifiedSession) or len(identity.session_hash) < 16:
                raise PermissionError('Unauthenticated')
            # Authenticate the very first RPC BEFORE accepting the websocket.
            await run_in_threadpool(gateway.query, identity.session_hash, SQL['messages'], (connection_id, after, 1))
            await run_in_threadpool(gateway.query, identity.session_hash, SQL['edits'], (connection_id, edt, edit_after_id, 1))
        except (ValueError, PermissionError, Exception):
            await ws.close(code=1008)
            return

        await ws.accept()
        cursor = after
        edit_dt = edt
        edit_id = edit_after_id
        tick = 0
        try:
            # A checkpoint is always delivered, including to an empty chat.
            await ws.send_json({'type': 'ready', 'after': cursor, 'edit_after_at': edit_dt.isoformat(), 'edit_after_id': edit_id})
            while True:
                # Offload psycopg to the worker pool; a synchronous cursor cannot block ASGI event loop.
                rows = await run_in_threadpool(gateway.query, identity.session_hash, SQL['messages'], (connection_id, cursor, 50))
                for row in rows:
                    seq = int(row['message_cursor'])
                    if seq <= cursor:
                        raise ValueError('Nonmonotonic DB message cursor')
                    await ws.send_json({'type': 'message', 'data': row})
                    cursor = seq
                edits = await run_in_threadpool(gateway.query, identity.session_hash, SQL['edits'], (connection_id, edit_dt, edit_id, 50))
                for row in edits:
                    dt = datetime.fromisoformat(row['edited_at'])
                    if dt.tzinfo is None:
                        raise ValueError('Naive DB edit datetime')
                    new_id = str(row['edit_id'])
                    if (dt, new_id) <= (edit_dt, edit_id):
                        raise ValueError('Nonmonotonic DB edit cursor')
                    await ws.send_json({'type': 'edit', 'data': row})
                    edit_dt, edit_id = dt, new_id
                tick += 1
                if tick % heartbeat_every == 0:
                    await ws.send_json({'type': 'heartbeat', 'after': cursor, 'edit_after_at': edit_dt.isoformat(), 'edit_after_id': edit_id})
                await asyncio.sleep(poll_seconds)
        except WebSocketDisconnect:
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            # Privilege, session revocation, DB failures all fail closed; no SQL detail is sent.
            try:
                await ws.close(code=1008)
            except RuntimeError:
                pass

    return router
