"""V9.0 review-only FastAPI adapter; not mounted by production app.

The integrating V8.9 app MUST supply a verified session_hash + CSRF policy;
never trust hashes sent by the browser. A separate non-superuser PostgreSQL
connection is required; current jw_app_dev NOLOGIN blocks live HTTP E2E.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from urllib.parse import quote
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Protocol

from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field


@dataclass(frozen=True)
class VerifiedSession:
    session_hash: str
    csrf_verified: bool


class SQLGateway(Protocol):
    def query(self, session_hash: str, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]: ...


class PsycopgGateway:
    """Request-scoped transaction and GUC; caller owns validated connection factory."""

    def __init__(self, connect: Callable[[], Any]):
        self._connect = connect

    def query(self, session_hash: str, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute("SELECT set_config('jw.session_hash', %s, true)", (session_hash,))
                    cur.execute(sql, params)
                    columns = [col.name for col in cur.description] if cur.description else []
                    return [dict(zip(columns, row)) for row in cur.fetchall()] if columns else []


class StartChat(BaseModel):
    other_org_id: str = Field(min_length=1, max_length=128)


class SendText(BaseModel):
    request_id: str = Field(min_length=8, max_length=128)
    body: str = Field(max_length=5000)
    filename: str | None = Field(default=None, max_length=180)
    mime: str | None = None
    data_base64: str | None = None


class MarkRead(BaseModel):
    cursor: int = Field(ge=0)


class EditText(BaseModel):
    body: str = Field(min_length=1, max_length=5000)
    expected_version: int = Field(ge=1)


SQL = {
    'directory': 'SELECT * FROM jw_dev.search_messenger_companies_v90(%s,%s,%s)',
    'start': 'SELECT jw_dev.v90_start_chat(%s) AS connection_id',
    'send': 'SELECT * FROM jw_dev.v90_send_text(%s,%s,%s,%s,%s,%s)',
    'read': 'SELECT jw_dev.v90_mark_read(%s,%s) AS cursor',
    'edit': 'SELECT jw_dev.v90_edit_text(%s,%s,%s) AS version',
    'messages': 'SELECT * FROM jw_dev.v90_sync_messages(%s,%s,%s)',
    'edits': 'SELECT * FROM jw_dev.v90_sync_edits(%s,%s,%s,%s)',
    'attachment': 'SELECT * FROM jw_dev.v90_download_attachment(%s,%s)',
}


def create_router(gateway: SQLGateway, authorize: Callable[[Request], VerifiedSession]) -> APIRouter:
    """Opt-in router. `authorize` MUST validate signed session and CSRF server-side."""
    router = APIRouter(prefix='/api/pg-stage/v90', tags=['messenger-stage'])

    def invoke(request: Request, function: str, *params: Any) -> list[dict[str, Any]]:
        identity = authorize(request)
        if not isinstance(identity, VerifiedSession) or len(identity.session_hash) < 16:
            raise HTTPException(401, 'Verified session required')
        if request.method not in ('GET', 'HEAD', 'OPTIONS') and not identity.csrf_verified:
            raise HTTPException(403, 'CSRF verification required')
        try:
            return gateway.query(identity.session_hash, SQL[function], params)
        except HTTPException:
            raise
        except Exception as exc:
            code = getattr(exc, 'sqlstate', None)
            if code == '42501':
                raise HTTPException(403, 'Chat access denied') from exc
            if code == '23514':
                raise HTTPException(422, 'Invalid messenger request') from exc
            if code in ('23505', '40001'):
                raise HTTPException(409, 'Message conflict') from exc
            raise HTTPException(503, 'Messenger datastore unavailable') from exc

    @router.get('/companies')
    def companies(request: Request, q: str = Query('', max_length=80),
                  limit: int = Query(30, ge=1, le=50), offset: int = Query(0, ge=0, le=100000)):
        return invoke(request, 'directory', q, limit, offset)

    @router.post('/chats')
    def start(request: Request, body: StartChat):
        return invoke(request, 'start', body.other_org_id)[0]

    @router.post('/chats/{connection_id}/messages')
    def send(request: Request, connection_id: str, body: SendText):
        data = None
        if body.data_base64 is not None:
            if len(body.data_base64) > 6991000:
                raise HTTPException(413, 'Attachment exceeds 5 MB')
            try:
                data = base64.b64decode(body.data_base64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise HTTPException(422, 'Invalid attachment encoding') from exc
            if not 0 < len(data) <= 5242880:
                raise HTTPException(413, 'Attachment exceeds 5 MB')
        return invoke(request, 'send', connection_id, body.request_id,
                      body.body, body.filename, body.mime, data)[0]

    @router.patch('/messages/{message_id}')
    def edit(request: Request, message_id: str, body: EditText):
        return invoke(request, 'edit', message_id, body.body, body.expected_version)[0]

    @router.post('/chats/{connection_id}/read')
    def mark_read(request: Request, connection_id: str, body: MarkRead):
        return invoke(request, 'read', connection_id, body.cursor)[0]

    @router.get('/chats/{connection_id}/messages')
    def messages(request: Request, connection_id: str, after: int = Query(0, ge=0),
                 limit: int = Query(50, ge=1, le=100)):
        return invoke(request, 'messages', connection_id, after, limit)

    @router.get('/chats/{connection_id}/attachments/{message_id}')
    def download(request: Request, connection_id: str, message_id: str):
        items = invoke(request, 'attachment', connection_id, message_id)
        if not items:
            raise HTTPException(404, 'Attachment not found')
        item = items[0]
        data = bytes(item['data'])
        if len(data) != item['size_bytes'] or hashlib.sha256(data).hexdigest() != item['content_hash']:
            raise HTTPException(503, 'Attachment integrity check failed')
        # Prevent header injection / inline HTML, PDF, SVG or script execution.
        basename = str(item['filename']).replace(chr(92),'/').split('/')[-1]
        if not basename or any(ord(ch) < 32 or ord(ch) == 127 for ch in basename):
            raise HTTPException(503, 'Invalid stored attachment name')
        disposition = "attachment; filename=\"download\"; filename*=UTF-8''" + quote(basename, safe='')
        return Response(content=data, media_type='application/octet-stream', headers={
            'Content-Disposition': disposition,
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': 'sandbox',
        })

    @router.get('/chats/{connection_id}/edits')
    def edits(request: Request, connection_id: str, after_at: datetime = Query(default=datetime(1970,1,1,tzinfo=timezone.utc)),
              after_id: str = Query('', max_length=128), limit: int = Query(50, ge=1, le=100)):
        if after_at.tzinfo is None:
            raise HTTPException(422, 'Timezone required')
        return invoke(request, 'edits', connection_id, after_at, after_id, limit)

    return router
