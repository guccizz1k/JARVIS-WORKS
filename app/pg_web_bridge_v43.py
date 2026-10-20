"""V4.3 isolated FastAPI -> real PostgreSQL 17 messenger API contract gate.

Only a disposable, loopback jw_v20_test_* database is supported. This module
MUST NOT be mounted into app.main or used as a production auth/provider bridge.
Customer accounts and the existing SQLite runtime are entirely untouched.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.pg_compat_read_api_v38 import LabRefused, check_dsn
from app.pg_messenger_review import MessengerReviewAdapter, PostgreSQLUnverified
from app.pg_write_replay_v40 import LabWriterV40, ReplayConflict

THREAD = re.compile(r"[a-zA-Z0-9_-]{1,100}\Z")
REQUEST = re.compile(r"[a-f0-9]{32}\Z")
LAB = 'ONLY_DISPOSABLE_LAB'


class SendText(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    content: str = Field(min_length=1, max_length=2000)
    request_id: str = Field(pattern=r'^[a-f0-9]{32}$')

    @field_validator('content')
    @classmethod
    def nonblank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError('Blank synthetic message')
        return value


@dataclass(frozen=True)
class HttpFault:
    status: int
    code: str
    detail: str
    retry_after: str | None = None


DENIED = HttpFault(403, 'TENANT_DENIED', 'Synthetic session or thread denied')
TEMPORARY = HttpFault(503, 'PG_UNAVAILABLE', 'Isolated database request failed')
CONFLICT = HttpFault(409, 'IDEMPOTENCY_CONFLICT', 'Request ID conflicts with earlier payload')
INPUT = HttpFault(422, 'INVALID_INPUT', 'Invalid synthetic request')


def classify_database_error(exc: BaseException) -> HttpFault:
    """Never expose SQL, DSNs, tokens or unverified PG driver exception strings."""
    if isinstance(exc, ReplayConflict):
        return CONFLICT
    if isinstance(exc, (PostgreSQLUnverified, LabRefused)):
        return DENIED
    # Route input is validated before DB access. A backend ValueError means
    # an unexpected internal inconsistency, not an end-user 422 error.
    if isinstance(exc, ValueError):
        return TEMPORARY
    state = getattr(exc, 'sqlstate', None)
    if state in ('P0001', '42501'):
        return DENIED
    # 28P01/28000 indicate a broken backend connection credential or role,
    # not a website visitor's identity. Returning 403 conceals outages.
    if state in ('28000', '28P01'):
        return HttpFault(503, 'PG_CONFIGURATION', 'Isolated database authentication unavailable')
    # PostgreSQL 40001/40P01 are retryable only with the SAME idempotency ID.
    if state in ('40001', '40P01', '55P03', '57014', '53300', '57P03'):
        return HttpFault(503, 'PG_RETRYABLE',
                         'Temporary database contention; retry with the same request ID', '2')
    if isinstance(state, str) and state.startswith('08'):
        return HttpFault(503, 'PG_CONNECTION_LOST',
                         'Database connection interrupted; retry with the same request ID', '5')
    if isinstance(exc, (ConnectionError, TimeoutError, OSError)):
        return HttpFault(503, 'PG_CONNECTION_LOST',
                         'Database connection interrupted; retry with the same request ID', '5')
    # Unexpected uniqueness, FK, schema and driver errors are SERVER failures,
    # not authentication denials or silent idempotent replays.
    return TEMPORARY


def _check_lab(dsn: str) -> None:
    if (os.getenv('JW_ENV', '').casefold() == 'production'
            or os.getenv('JW_PG_LAB_V43') != LAB
            or os.getenv('JW_PG_LAB_V42') != LAB
            or os.getenv('JW_PG_LAB_V40') != LAB
            or os.getenv('JW_PG_LAB_V38') != LAB
            or os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'):
        raise LabRefused('V4.3 disposable-only gate refused')
    # Both historical gates remain intact; do not bypass them for a fake writer.
    check_dsn(dsn)
    MessengerReviewAdapter(dsn)._check_dsn()


class LabAPIError(HTTPException):
    def __init__(self, fault: HttpFault):
        headers = {'Retry-After': fault.retry_after} if fault.retry_after else None
        super().__init__(status_code=fault.status, detail=fault.detail, headers=headers)
        self.fault_code = fault.code


def _raise_fault(fault: HttpFault) -> None:
    raise LabAPIError(fault)


def create_lab_app(dsn: str, *, adapter=None, writer=None) -> FastAPI:
    """Expose staging paths matching existing web messenger request semantics.

    This is a separate in-process test app, NOT app.main. Existing web sessions
    are deliberately NOT accepted: there is no trusted cookie-to-PG identity map.
    """
    _check_lab(dsn)
    adapter = adapter if adapter is not None else MessengerReviewAdapter(dsn)
    writer = writer if writer is not None else LabWriterV40(dsn)
    app = FastAPI(title='JARVIS-WORKS V4.3 isolated bridge', docs_url=None,
                  redoc_url=None, openapi_url=None)

    @app.middleware('http')
    async def private_response(request, call_next):
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    @app.exception_handler(HTTPException)
    async def handle_api_error(request, exc):
        # HTTPException deliberately contains only constant synthetic details.
        # Existing app/static/app.js displays result.detail as a string.
        # Separate machine code avoids a '[object Object]' error toast.
        return JSONResponse({'detail': str(exc.detail),
                             'code': getattr(exc, 'fault_code', 'HTTP_ERROR')},
                            status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def handle_input_error(request, exc):
        # Default validation errors may echo user-supplied body/header content.
        return JSONResponse({'detail': INPUT.detail, 'code': INPUT.code},
                            status_code=422)

    def check_input(thread: str, token: str | None) -> str:
        # Refuse requests if flags were removed after TestClient app creation.
        try:
            _check_lab(dsn)
        except (LabRefused, PostgreSQLUnverified):
            _raise_fault(TEMPORARY)
        if THREAD.fullmatch(thread) is None:
            _raise_fault(INPUT)
        if not isinstance(token, str) or not 40 <= len(token) <= 512:
            _raise_fault(HttpFault(401, 'SESSION_REQUIRED', 'Verified synthetic session required'))
        return token

    def assert_member(token: str, thread: str):
        """Do not mistake a missing/nonmember thread for an empty conversation."""
        with adapter.verified_transaction(token, readonly=True) as (cur, tenant, actor):
            cur.execute('''SELECT 1 FROM public.messenger_connections
                           WHERE id=%s AND status='active' ''', (thread,))
            if cur.fetchone() is None:
                _raise_fault(HttpFault(404, 'THREAD_NOT_FOUND', 'Conversation not found'))
            return tenant

    @app.get('/lab43/api/messenger/threads/{thread}/messages')
    def list_messages(thread: str, after: int = Query(default=0, ge=0, le=9223372036854775807),
                      limit: int = Query(default=50, ge=1, le=100),
                      x_jw_lab_session: str | None = Header(default=None)):
        token = check_input(thread, x_jw_lab_session)
        try:
            with adapter.verified_transaction(token, readonly=True) as (cur, tenant, actor):
                cur.execute('''SELECT 1 FROM public.messenger_connections
                               WHERE id=%s AND status='active' ''', (thread,))
                if cur.fetchone() is None:
                    _raise_fault(HttpFault(404, 'THREAD_NOT_FOUND', 'Conversation not found'))
                cur.execute('''SELECT id,message_seq,sender_org,sender_user,kind,body,created_at
                               FROM public.messenger_messages
                               WHERE connection_id=%s AND message_seq>%s
                               ORDER BY message_seq ASC LIMIT %s''',
                            (thread, after, limit+1))
                rows = cur.fetchall()
                entries = [{'id': row[0], 'message_seq': row[1], 'sender_org': row[2],
                            'kind': row[4], 'body': row[5], 'created_at': row[6],
                            'mine': row[2] == tenant} for row in rows[:limit]]
                return {'messages': entries, 'has_more': len(rows)>limit,
                        'next_after': entries[-1]['message_seq'] if entries else after}
        except HTTPException:
            raise
        except Exception as exc:
            _raise_fault(classify_database_error(exc))

    @app.post('/lab43/api/messenger/threads/{thread}/messages')
    def send_text(thread: str, body: SendText,
                  x_jw_lab_session: str | None = Header(default=None)):
        token = check_input(thread, x_jw_lab_session)
        try:
            # Prevent sending to absent/nonmember threads; RLS and the DB
            # trigger still re-authorize inside the WRITE transaction itself.
            assert_member(token, thread)
            result = writer.send_text(token=token, thread=thread,
                                      content=body.content, request_id=body.request_id)
            if not isinstance(result, dict) or not isinstance(result.get('replayed'), bool):
                raise RuntimeError('Unexpected writer contract')
            if (not isinstance(result.get('id'), str)
                    or not isinstance(result.get('message_seq'), int)
                    or isinstance(result['message_seq'], bool) or result['message_seq'] < 1):
                raise RuntimeError('Invalid committed-message evidence')
            # Whitelist the public payload: never reflect incidental adapter
            # keys such as SQL, connection settings or driver diagnostics.
            public = {'id': result['id'], 'message_seq': result['message_seq'],
                      'replayed': result['replayed']}
            return JSONResponse(public, status_code=200 if result['replayed'] else 201)
        except HTTPException:
            raise
        except Exception as exc:
            _raise_fault(classify_database_error(exc))

    return app
