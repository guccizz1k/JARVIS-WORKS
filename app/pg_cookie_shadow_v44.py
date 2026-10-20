"""V4.4 *isolated* website-cookie to PG17 shadow audit.

No registration with app.main, no new production route, no PG writes.
This is a proof of the AUTHENTICATED web user's session identity binding,
not a deployable SQLite-to-PostgreSQL migration or an authentication provider.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app.pg_web_bridge_v43 import _check_lab, classify_database_error

THREAD_ID = re.compile(r"[a-f0-9]{32}\Z")
MAX_ROWS = 200


@dataclass(frozen=True)
class ReviewBinding:
    """Trusted server-side mapping from SQLite principal to disposable PG actor.

    Mapping MUST be supplied by an isolated fixture authority, never a user
    header, cookie payload, request body or client-controlled identifier.
    """
    source_org: str
    source_user: str
    pg_org: str
    pg_user: str
    pg_thread: str
    pg_token: str
    # Tenant identifiers cannot be assumed equal across SQLite and PG test data.
    pg_to_source_org: tuple[tuple[str, str], ...]
    pg_to_source_user: tuple[tuple[str, str], ...]


def _gate(dsn: str) -> None:
    if (os.environ.get('JW_ENV', '').casefold() == 'production'
        or os.environ.get('JW_PG_LAB_V44') != 'ONLY_DISPOSABLE_LAB'
        or os.environ.get('JW_PG_CI_ALLOW') != 'ONLY_EPHEMERAL_LOCAL_DATABASE'):
        raise RuntimeError('V4.4 lab not authorized')
    _check_lab(dsn)


def _reject(status: int, code: str):
    text = {
        'THREAD_NOT_FOUND': 'Conversation not found',
        'BINDING_DENIED': 'Verified identity mapping denied',
        'INVALID_THREAD': 'Invalid conversation identifier',
        'PG_UNAVAILABLE': 'Isolated database unavailable',
    }.get(code, 'V4.4 review unavailable')
    raise ReviewFault(status, code, text)


class ReviewFault(HTTPException):
    def __init__(self, status_code: int, code: str, detail: str):
        super().__init__(status_code, detail=detail)
        self.code = code


def _mapping(user: dict, binding: ReviewBinding) -> dict[str, str]:
    if (not isinstance(binding, ReviewBinding)
        or not all(isinstance(x, str) and x for x in (
            binding.source_org, binding.source_user, binding.pg_org,
            binding.pg_user, binding.pg_thread, binding.pg_token))
        or len(binding.pg_token) < 40
        or binding.source_org != user.get('org_id')
        or binding.source_user != user.get('id')
        or not isinstance(binding.pg_to_source_org, tuple)
        or not isinstance(binding.pg_to_source_user, tuple)):
        _reject(403, 'BINDING_DENIED')
    try:
        converted = dict(binding.pg_to_source_org)
        actors = dict(binding.pg_to_source_user)
    except (TypeError, ValueError):
        _reject(403, 'BINDING_DENIED')
    if (len(converted) != len(binding.pg_to_source_org)
        or len(converted) != 2
        or converted.get(binding.pg_org) != user['org_id']
        or len(set(converted.values())) != 2
        or len(actors) != len(binding.pg_to_source_user)
        or actors.get(binding.pg_user) != user['id']):
        _reject(403, 'BINDING_DENIED')
    return converted, actors


def _normalize(rows, convert: tuple[dict[str, str], dict[str, str]] | None):
    normalized = []
    for row in rows:
        if len(row) != 6 or any(not isinstance(v, str) for v in
                                (row[0], row[2], row[3], row[4], row[5])):
            raise ValueError('Unsupported shadow row contract')
        msg_id, sequence, sender_org, kind, body, sender_user = row
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise ValueError('Unsupported message sequence')
        if kind != 'text' or body.startswith('첨부파일: '):
            return None
        if convert is not None:
            org_map, user_map = convert
            if sender_org not in org_map or sender_user not in user_map:
                return None
            sender_org, sender_user = org_map[sender_org], user_map[sender_user]
        normalized.append((msg_id, sequence, sender_org, kind, body, sender_user))
    return normalized


def compare_rows(sqlite_rows, pg_rows, pg_to_source_org):
    """Never certify empty/partial/non-text/mismatched history as parity."""
    if len(sqlite_rows) > MAX_ROWS or len(pg_rows) > MAX_ROWS:
        return 'INCOMPLETE'
    left = _normalize(sqlite_rows, None)
    right = _normalize(pg_rows, pg_to_source_org)
    if left is None or right is None:
        return 'UNSUPPORTED'
    if not left and not right:
        return 'EMPTY_UNVERIFIED'
    return 'MATCH' if left == right else 'MISMATCH'


def create_review_app(*, dsn: str, adapter, sqlite_conn: Callable,
                      trusted_broker: Callable, website_current_user: Callable | None = None):
    """Build a separate TestClient app with the *real* website auth dependency.

    Instantiating this never mounts /lab44 into the public FastAPI application.
    No client can supply the lab PG session token or tenant mapping.
    """
    _gate(dsn)
    adapter._check_dsn()
    if website_current_user is None:
        # Reuse cookie hashing, user-disable, expiry and CSRF logic of the
        # existing website instead of reimplementing authentication.
        from app.main import current_user as website_current_user
    review = FastAPI(title='V4.4 isolated cookie/PG shadow review',
                     docs_url=None, redoc_url=None, openapi_url=None)

    @review.middleware('http')
    async def privacy(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @review.exception_handler(ReviewFault)
    async def review_error(request, exc):
        return JSONResponse(status_code=exc.status_code,
                            content={'detail': exc.detail, 'code': exc.code})

    @review.exception_handler(Exception)
    async def unexpected(request, exc):
        return JSONResponse(status_code=503,
                            content={'detail': 'V4.4 isolated review unavailable',
                                     'code': 'REVIEW_UNAVAILABLE'})

    @review.get('/lab44/threads/{thread}/shadow')
    def shadow(thread: str, user=Depends(website_current_user)):
        # Even if test flags are cleared after app creation, no database access.
        try:
            _gate(dsn)
        except Exception:
            _reject(503, 'PG_UNAVAILABLE')
        if THREAD_ID.fullmatch(thread) is None:
            _reject(422, 'INVALID_THREAD')
        if not isinstance(user, dict) or not user.get('org_id') or not user.get('id'):
            _reject(403, 'BINDING_DENIED')
        # Check first against current SQLite membership / company eligibility.
        # No database identifiers, SQL strings or message bodies are returned.
        try:
            with sqlite_conn() as con:
                found = con.execute('''SELECT 1 FROM messenger_connections t
                   WHERE t.id=? AND (t.org_a=? OR t.org_b=?) AND t.status='active'
                   AND EXISTS(SELECT 1 FROM messenger_companies c WHERE c.org_id=t.org_a)
                   AND EXISTS(SELECT 1 FROM messenger_companies c WHERE c.org_id=t.org_b)''',
                   (thread, user['org_id'], user['org_id'])).fetchone()
                if not found:
                    _reject(404, 'THREAD_NOT_FOUND')
                rows_sqlite = con.execute('''SELECT id,message_seq,sender_org,kind,body,sender_user
                    FROM messenger_messages WHERE connection_id=?
                    ORDER BY message_seq ASC LIMIT ?''', (thread, MAX_ROWS + 1)).fetchall()
        except ReviewFault:
            raise
        except Exception:
            _reject(503, 'PG_UNAVAILABLE')
        try:
            binding = trusted_broker(user['org_id'], user['id'], thread)
            converted = _mapping(user, binding)
            with adapter.verified_transaction(binding.pg_token, readonly=True) as (cur, tenant, actor):
                # Database-side signed context + forced RLS independently proves
                # the broker didn't hand the user somebody else's PG token.
                if tenant != binding.pg_org or actor != binding.pg_user:
                    _reject(403, 'BINDING_DENIED')
                cur.execute('''SELECT 1 FROM public.messenger_connections
                               WHERE id=%s AND status='active' ''', (binding.pg_thread,))
                if cur.fetchone() is None:
                    _reject(404, 'THREAD_NOT_FOUND')
                cur.execute('''SELECT id,message_seq,sender_org,kind,body,sender_user
                     FROM public.messenger_messages WHERE connection_id=%s
                     ORDER BY message_seq ASC LIMIT %s''', (binding.pg_thread, MAX_ROWS + 1))
                rows_pg = cur.fetchall()
            result = compare_rows(rows_sqlite, rows_pg, converted)
        except ReviewFault:
            raise
        except Exception as exc:
            fault = classify_database_error(exc)
            _reject(fault.status if fault.status in (403, 503) else 503,
                    'BINDING_DENIED' if fault.status == 403 else 'PG_UNAVAILABLE')
        return {'status': result, 'text_row_parity': result == 'MATCH', 'cutover_approved': False,
                'sqlite_count': min(len(rows_sqlite), MAX_ROWS),
                'postgres_count': min(len(rows_pg), MAX_ROWS)}

    return review
