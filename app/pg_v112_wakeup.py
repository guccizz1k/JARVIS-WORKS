"""V11.2 review-only cross-instance messenger wake signal.

One dedicated PostgreSQL LISTEN connection per web *instance* is intended,
not one per WebSocket. Database SQL/RLS remains the only source of messages.
A missing/dropped notification can only add latency: periodic cursor-based
reconciliation is mandatory and business RPCs always revalidate sessions.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import threading
from collections import defaultdict
from typing import Callable

CHANNEL = 'jw_v112_messenger_wake'
_DIGEST = re.compile(r'^[a-f0-9]{64}$')


def digest_connection(connection_id: str) -> str:
    if not isinstance(connection_id, str) or not 1 <= len(connection_id) <= 128:
        raise ValueError('Invalid connection id')
    return hashlib.sha256(connection_id.encode('utf-8')).hexdigest()


class WakeHub:
    """In-process event fanout. Only payload hashes, never message/user data."""

    def __init__(self, *, max_subscribers: int = 5000):
        if type(max_subscribers) is not int or not 1 <= max_subscribers <= 100_000:
            raise ValueError('Invalid subscriber cap')
        self.max_subscribers = max_subscribers
        self._groups: dict[str, set[asyncio.Event]] = defaultdict(set)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._count = 0
        self.connected = False

    def subscribe(self, connection_id: str) -> asyncio.Event:
        loop = asyncio.get_running_loop()
        if self._loop is not None and loop is not self._loop:
            raise RuntimeError('WakeHub cannot cross event loops')
        if self._count >= self.max_subscribers:
            raise RuntimeError('WebSocket wake subscriptions at capacity')
        self._loop = loop
        event = asyncio.Event()
        self._groups[digest_connection(connection_id)].add(event)
        self._count += 1
        return event

    def unsubscribe(self, connection_id: str, event: asyncio.Event) -> None:
        group = self._groups.get(digest_connection(connection_id))
        if group is not None and event in group:
            group.remove(event)
            self._count -= 1
            if not group:
                del self._groups[digest_connection(connection_id)]

    def publish_from_thread(self, payload: str) -> bool:
        """Notifications are hints, never authorization or a message payload."""
        if not isinstance(payload, str) or not _DIGEST.fullmatch(payload):
            return False
        if self._loop is None or self._loop.is_closed():
            return False
        self._loop.call_soon_threadsafe(self._deliver, payload)
        return True

    def _deliver(self, payload: str) -> None:
        for event in tuple(self._groups.get(payload, ())):
            event.set()

    def set_connected_from_thread(self, connected: bool) -> None:
        # Plain boolean status may be updated before any WebSocket subscribes.
        # asyncio.Event state is still touched only by the owning event loop.
        self.connected = bool(connected)

    @property
    def subscriptions(self) -> int:
        return self._count


def listen_forever(connect: Callable, hub: WakeHub, stop: threading.Event, *,
                   reconnect_seconds: float = 2.0) -> None:
    """Dedicated, restricted, autocommit listener; call on a daemon worker thread.

    Real deployment requires separate TLS & PostgreSQL restricted-login
    attestations and an *explicit* operator-approved listener connection. This
    is never invoked by default from the public Render diagnostic server.
    """
    if not 0.5 <= reconnect_seconds <= 30:
        raise ValueError('Invalid reconnection delay')
    while not stop.is_set():
        try:
            with connect() as conn:
                if conn.autocommit is not True:
                    raise RuntimeError('LISTEN requires independent autocommit connection')
                with conn.cursor() as cur:
                    cur.execute('''SELECT session_user, rolsuper, rolbypassrls,
                                     (SELECT ssl FROM pg_catalog.pg_stat_ssl
                                      WHERE pid=pg_catalog.pg_backend_pid())
                                   FROM pg_catalog.pg_roles WHERE rolname=session_user''')
                    row = cur.fetchone()
                    if (not row or row[0] != 'jw_trade_gateway_v90'
                        or row[1] is not False or row[2] is not False
                        or row[3] is not True):
                        raise RuntimeError('Invalid event listener login')
                    cur.execute('LISTEN ' + CHANNEL)
                hub.set_connected_from_thread(True)
                # psycopg3 exposes a timeout-bounded generator. A timeout
                # enables graceful shutdown even without new messages.
                while not stop.is_set():
                    for item in conn.notifies(timeout=1.0):
                        if stop.is_set():
                            break
                        if item.channel == CHANNEL:
                            hub.publish_from_thread(item.payload)
        except Exception:
            # Credential strings and SQL exceptions must never be logged.
            pass
        finally:
            hub.set_connected_from_thread(False)
        stop.wait(reconnect_seconds)

