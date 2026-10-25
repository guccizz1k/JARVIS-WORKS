"""V8.9 + V9 messenger **isolated dev** ASGI composition, OFF by default.

Never import this entrypoint from production app.main. Require the V8.4 reader
and V8.5 auth gates and keep legacy SQLite routes untouched. Database work
executes under SET LOCAL ROLE jw_app_dev with a verified PG session on *every*
request. No SQLite auth fallback, no service/superuser DSN, no Data API bypass.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from contextlib import contextmanager
from typing import Any

from fastapi import HTTPException, Request, Response, WebSocket

from . import pg_api_v84 as stage
from . import pg_auth_v85 as auth
from .pg_messenger_bridge_v90 import VerifiedSession, create_router
from .pg_messenger_realtime_v90 import create_realtime_router


_GATE = 'ISOLATED_DEV_MESSENGER_ONLY'
_COOKIE = '__Host-jw_session'


def v90_enabled() -> bool:
    return (
        os.environ.get('JW_PG_MESSENGER_V90') == _GATE
        and stage.stage_enabled()
        and auth.auth_stage_enabled()
        and os.environ.get('JW_ENV', '').lower() not in ('production', 'prod')
        and os.environ.get('JW_INSECURE_LOCAL_DEV') != '1'
    )


def _origins() -> frozenset[str]:
    source = os.environ.get('JW_V90_ALLOWED_ORIGINS', '')
    values = [x.strip() for x in source.split(',') if x.strip()]
    # __Host cookie is Secure. Do not accept HTTP, pathful origins or wildcard.
    if not values or len(values) != len(set(values)) or any(
        not x.startswith('https://') or x.endswith('/') or '/' in x[8:]
        or '*' in x or ' ' in x for x in values
    ):
        raise RuntimeError('V9 stage requires an explicit HTTPS-only Origin allowlist')
    return frozenset(values)


@contextmanager
def _pg_validated_cursor(session_hash: str):
    """One role-limited PG transaction. Re-check login and session each RPC."""
    if not v90_enabled():
        raise HTTPException(404, 'V9 isolated messenger disabled')
    with stage._connect() as db:
        with db.transaction():
            with db.cursor() as cur:
                cur.execute('''SELECT session_user, r.rolsuper, r.rolbypassrls,
                                     r.rolcreaterole, r.rolcreatedb
                               FROM pg_catalog.pg_roles r WHERE r.rolname=session_user''')
                login = cur.fetchone()
                if (not login or login[0] in ('postgres','supabase_admin','service_role','jw_app_dev')
                        or any(login[1:])):
                    raise HTTPException(503, 'Unsafe PostgreSQL login configured')
                # Both authentication and business credentials must be confined to
                # their own role. The V8.5 auth route checks the reverse side.
                cur.execute("SELECT pg_catalog.pg_has_role(session_user,'jw_auth_stage_v85','MEMBER')")
                if cur.fetchone() != (False,):
                    raise HTTPException(503, 'Business login can adopt authentication role')
                cur.execute('SET LOCAL ROLE jw_app_dev')
                cur.execute("SELECT pg_catalog.set_config('jw.session_hash', %s, true)", (session_hash,))
                cur.execute('''SELECT current_user, actor_id, org_id, actor_role,
                                      csrf_token, org_name
                               FROM jw_dev.stage_identity_v84()''')
                identity = cur.fetchone()
                if (not identity or identity[0] != 'jw_app_dev'
                        or len(identity) != 6 or not all(identity[1:])):
                    raise HTTPException(401, 'PostgreSQL session invalid or expired')
                yield cur, identity


def _session_hash(request: Request | WebSocket) -> str:
    token = request.cookies.get(_COOKIE, '')
    if not 30 <= len(token) <= 512:
        raise HTTPException(401, 'PostgreSQL session cookie required')
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def _authorize(request: Request | WebSocket) -> VerifiedSession:
    session_hash = _session_hash(request)
    with _pg_validated_cursor(session_hash) as (_, identity):
        stored_csrf = identity[4]
    is_http_write = request.scope.get('type') == 'http' and request.method not in ('GET', 'HEAD', 'OPTIONS')
    valid_csrf = (
        not is_http_write
        or hmac.compare_digest(str(stored_csrf), request.headers.get('X-CSRF-Token', ''))
    )
    return VerifiedSession(session_hash=session_hash, csrf_verified=valid_csrf)


class ScopedMessengerGateway:
    """RPC GUC + session identity are not optional even for WS replay."""

    def query(self, session_hash: str, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with _pg_validated_cursor(session_hash) as (cur, _):
            cur.execute(sql, params)
            columns = [col.name for col in cur.description] if cur.description else []
            return [dict(zip(columns, row)) for row in cur.fetchall()] if columns else []


def register_v90_messenger(app) -> bool:
    """Mount both HTTP and WS only after explicit non-production opt-in."""
    if not v90_enabled():
        return False
    origins = _origins()  # fail before creating any routes
    gateway = ScopedMessengerGateway()

    def current_pg_identity(request: Request, response: Response):
        # Legacy /api/me verifies a *SQLite* session; V9 requires the PG session.
        # Never accept a browser-supplied org/actor identifier.
        with _pg_validated_cursor(_session_hash(request)) as (_, identity):
            response.headers['Cache-Control'] = 'no-store'
            return {'org_id': identity[2], 'csrf_token': identity[4]}

    # V11.2 remains disabled by default. Only a separately approved isolated
    # PG17 staging fixture with installed triggers may start the listener.
    wake_hub = None
    if os.getenv('JW_V112_PG_NOTIFY_ACK') == 'ISOLATED_PG17_REVIEW_ONLY':
        if os.getenv('JW_ENV') not in ('dev','development','test'):
            raise RuntimeError('V11.2 notifications prohibited outside review')
        from .pg_v112_wakeup import WakeHub, listen_forever
        import threading
        wake_hub = WakeHub(max_subscribers=3000)
        stop = threading.Event()
        active = []

        def _listener_connect():
            import psycopg
            return psycopg.connect(
                os.environ['JW_PG_STAGE_DSN'],connect_timeout=5,
                sslmode='verify-full',autocommit=True)

        def _start_listener():
            with stage._connect() as conn:
                with conn.transaction():
                    with conn.cursor() as cur:
                        cur.execute("""SELECT count(*) FROM pg_catalog.pg_trigger
                            WHERE tgname IN
                              ('v112_messenger_insert_wakeup','v112_messenger_edit_wakeup')
                              AND NOT tgisinternal AND tgenabled='O'""")
                        if cur.fetchone() != (2,):
                            raise RuntimeError('V11.2 verified message triggers missing')
            daemon = threading.Thread(
                target=listen_forever,args=(_listener_connect,wake_hub,stop),
                name='jw-v112-pg-listener',daemon=True)
            daemon.start()
            active.append(daemon)

        def _stop_listener():
            stop.set()
            for daemon in active:
                daemon.join(timeout=3)

        app.add_event_handler('startup', _start_listener)
        app.add_event_handler('shutdown', _stop_listener)

    app.add_api_route('/api/pg-stage/v90/me', current_pg_identity, methods=['GET'])
    app.include_router(create_router(gateway, _authorize))
    app.include_router(create_realtime_router(
        gateway, _authorize, allowed_origins=origins, wake_hub=wake_hub))
    return True
