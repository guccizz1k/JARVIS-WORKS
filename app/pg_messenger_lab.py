"""Isolated, TestClient-only FastAPI/PG17 integration laboratory (no public app mount).

Never attach this app to app.main or serve it over TCP. Every call uses a fresh
transaction and PostgreSQL's revocable, MFA-bound synthetic test session.
"""
from __future__ import annotations

import os
import re

from fastapi import FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from .pg_messenger_review import MessengerReviewAdapter, PostgreSQLUnverified

_THREAD = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')


class TextPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    content: str = Field(min_length=1, max_length=2000)
    request_id: str = Field(pattern=r'^[a-f0-9]{32}$')


class ReadPayload(BaseModel):
    model_config = ConfigDict(extra='forbid')
    last_seq: int = Field(ge=0, strict=True)


def create_lab_app(*, adapter: MessengerReviewAdapter | None = None, dsn: str | None = None) -> FastAPI:
    """Opt-in test-only factory. Never trust HTTP tenant/actor fields."""
    if os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE':
        raise PostgreSQLUnverified('PG lab requires explicit isolated gate')
    if adapter is None:
        adapter = MessengerReviewAdapter(dsn or '')
    # Check connection target BEFORE accepting any request; still rechecked by
    # the adapter for each transaction. No production credentials accepted.
    adapter._check_dsn()
    app = FastAPI(title='JARVIS WORKS PG17 synthetic API lab', docs_url=None,
                  redoc_url=None, openapi_url=None)

    def check(token: str | None, thread: str) -> str:
        if not _THREAD.fullmatch(thread):
            raise HTTPException(422, detail='Invalid thread ID')
        if not isinstance(token, str) or not (40 <= len(token) <= 512):
            raise HTTPException(401, detail='Verified synthetic session required')
        return token

    def fail_safe(exc: Exception):
        # Intentionally no SQL diagnostics, tokens, DSNs, or company data in
        # error bodies. Underlying transaction rolls back via adapter context.
        if isinstance(exc, (ValueError, PostgreSQLUnverified)):
            raise HTTPException(403, detail='Review session or request denied') from None
        try:
            import psycopg
            if isinstance(exc, psycopg.Error):
                if exc.sqlstate in {'42501', 'P0001', '23503', '23514'}:
                    raise HTTPException(403, detail='Review request forbidden') from None
                if exc.sqlstate == '23505':
                    raise HTTPException(409, detail='Duplicate request') from None
        except ImportError:
            pass
        raise HTTPException(503, detail='Isolated test database unavailable') from None

    @app.get('/lab/threads/{thread}/messages')
    def list_messages(thread: str, after: int = Query(default=0, ge=0),
                      limit: int = Query(default=50, ge=1, le=100),
                      x_jw_lab_session: str | None = Header(default=None)):
        token = check(x_jw_lab_session, thread)
        try:
            rows = adapter.list_messages(token, thread, after=after, limit=limit)
            # Do not expose employee identifiers to a partner business.
            return {'messages': [dict(zip(('id','message_seq','sender_org',
                      'kind','body','created_at'),
                      (row[0],row[1],row[2],row[4],row[5],row[6]))) for row in rows]}
        except Exception as exc:
            fail_safe(exc)

    @app.post('/lab/threads/{thread}/messages', status_code=201)
    def send_text(thread: str, payload: TextPayload,
                  x_jw_lab_session: str | None = Header(default=None)):
        token = check(x_jw_lab_session, thread)
        try:
            message_id, seq = adapter.send_text(token, thread, payload.content, payload.request_id)
            return {'id': message_id, 'message_seq': seq}
        except Exception as exc:
            fail_safe(exc)

    @app.put('/lab/threads/{thread}/read')
    def mark_read(thread: str, payload: ReadPayload,
                  x_jw_lab_session: str | None = Header(default=None)):
        token = check(x_jw_lab_session, thread)
        try:
            adapter.mark_read(token, thread, payload.last_seq)
            return {'ok': True}
        except Exception as exc:
            fail_safe(exc)

    return app
