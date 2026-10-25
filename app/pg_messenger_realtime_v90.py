"""V9.0 isolated polling-over-WebSocket bridge (staging only).

HTTP commits are the sole source of truth; WS emits an authorized DB cursor stream.
Not mounted into production. Requires caller-supplied genuine auth verification,
strict browser Origin allowlist, and real non-privileged PostgreSQL connections.
"""
from __future__ import annotations

import asyncio
from time import monotonic
from datetime import datetime, timezone
from typing import Any, Callable

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from starlette.concurrency import run_in_threadpool

from .pg_messenger_bridge_v90 import SQL, SQLGateway, VerifiedSession


def next_poll_delay(poll_seconds: float, idle_rounds: int) -> float:
    """Bound idle read pressure without slowing active conversations.

    After eight empty polling cycles, exponentially back off to at most 4x
    the configured interval, and never increase a long configured interval.
    This is a bounded fallback, not a substitute for DB NOTIFY/realtime E2E.
    """
    if idle_rounds <= 8:
        return poll_seconds
    ceiling = max(poll_seconds, min(poll_seconds * 4, 1.2))
    return min(ceiling, poll_seconds * (1.5 ** min(idle_rounds - 8, 12)))


def create_realtime_router(
    gateway: SQLGateway,
    authorize: Callable[[WebSocket], VerifiedSession],
    *,
    allowed_origins: frozenset[str],
    poll_seconds: float = 0.3,
    heartbeat_every: int = 20,
    wake_hub=None,
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
        subscriber = None
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
            # Subscribe only after real PostgreSQL permission checks. Wake signals
            # never replace tenant-scoped RPC checks or cursor replay.
            if wake_hub is not None:
                subscriber = wake_hub.subscribe(connection_id)
        except Exception:
            await ws.close(code=1008)
            return

        await ws.accept()
        cursor = after
        edit_dt = edt
        edit_id = edit_after_id
        tick = 0
        idle_rounds = 0
        last_heartbeat_at = monotonic()
        try:
            # A checkpoint is always delivered, including to an empty chat.
            await ws.send_json({'type': 'ready', 'after': cursor, 'edit_after_at': edit_dt.isoformat(), 'edit_after_id': edit_id})
            while True:
                # Clear before reading from the DB, not afterwards: a wakeup
                # concurrent with a SELECT stays signaled until the next wait.
                if subscriber is not None:
                    subscriber.clear()
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
                # Backoff must not stretch heartbeat gaps and trigger proxy timeout.
                if tick % heartbeat_every == 0 or monotonic() - last_heartbeat_at >= poll_seconds * heartbeat_every:
                    await ws.send_json({'type': 'heartbeat', 'after': cursor, 'edit_after_at': edit_dt.isoformat(), 'edit_after_id': edit_id})
                    last_heartbeat_at = monotonic()
                idle_rounds = 0 if (rows or edits) else idle_rounds + 1
                if subscriber is None:
                    await asyncio.sleep(next_poll_delay(poll_seconds, idle_rounds))
                else:
                    # In addition to NOTIFY, perform periodic actual DB reads:
                    # NOTIFY is not durable and session revocation must be seen.
                    # On listener failure, bounded fallback polling resumes.
                    reconciliation = 10.0 if wake_hub.connected else 2.0
                    try:
                        await asyncio.wait_for(subscriber.wait(), timeout=reconciliation)
                    except asyncio.TimeoutError:
                        pass
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
        finally:
            if subscriber is not None:
                wake_hub.unsubscribe(connection_id, subscriber)

    return router
