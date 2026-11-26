"""Default-off native PostgreSQL session-bound file preview, isolated review only.

No raw upload persistence, approvals, import, production routes or SQLite fallback.
A separate server-managed source registry is required; it is not the ERP ledger.
"""
import asyncio
import hmac
import hashlib
import json
import os
import re

from fastapi import APIRouter, HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from . import pg_v90_integrated_entry as v90
from .erp_migration_file_stage import prepare_file_stage
from .erp_migration_mapping import MappingBlocked
from .erp_migration_preflight import make_target_snapshot

PREFIX = "/api/naruv-review/v1"
MAX_BYTES = 1024 * 1024
IDENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
FORMATS = {"csv": "text/csv", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}

def enabled():
    return (os.getenv("NARUV_NATIVE_FILE_PREVIEW") == "ISOLATED_READ_ONLY"
            and os.getenv("JW_ENV", "").lower() in ("dev", "development", "test")
            and os.getenv("JW_INSECURE_LOCAL_DEV") != "1"
            and v90.v90_enabled())

def _one_header(request, name, default=None):
    values = request.headers.getlist(name)
    if len(values) > 1:
        raise HTTPException(400, "AMBIGUOUS_HEADER")
    return values[0] if values else default

def _verify_identity(identity, csrf):
    if not identity or len(identity) != 6 or identity[0] != "jw_app_dev" or not all(identity[1:]):
        raise HTTPException(401, "SESSION_INVALID")
    if identity[3] != "admin":
        raise HTTPException(403, "IMPORT_ADMIN_REQUIRED")
    stored = identity[4]
    if (type(stored) is not str or not stored.isascii()
            or not 1 <= len(stored) <= 512 or not csrf
            or not hmac.compare_digest(stored, csrf)):
        raise HTTPException(403, "INVALID_CSRF")
    return identity[1], identity[2]

def _authorize(token_hash, csrf):
    if not enabled():
        raise HTTPException(404, "PREVIEW_DISABLED")
    with v90._pg_validated_cursor(token_hash) as (_, identity):
        return _verify_identity(identity, csrf)

def _preview(token_hash, csrf, prior, source_id, entity, file_format, raw):
    if not enabled():
        raise HTTPException(404, "PREVIEW_DISABLED")
    with v90._pg_validated_cursor(token_hash) as (cur, identity):
        actor, org = _verify_identity(identity, csrf)
        if (actor, org) != prior:
            raise HTTPException(409, "SESSION_SCOPE_CHANGED")
        cur.execute("""SELECT revision, existing_ids FROM jw_dev.naruv_review_sources
                       WHERE org_id=%s AND source_id=%s AND entity=%s AND active""",
                    (org, source_id, entity))
        row = cur.fetchone()
        if row is None:
            raise HTTPException(404, "SOURCE_NOT_FOUND")
        try:
            target = make_target_snapshot(org, source_id, entity, row[0], row[1])
            stage = prepare_file_stage(raw, format=file_format, organization_id=org,
                         source_id=source_id, entity=entity, target=target)
        except MappingBlocked as exc:
            # Existing parser errors are safe reason codes. Never reflect cells.
            reason = str(exc)
            if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,95}", reason):
                reason = "FILE_REJECTED"
            raise HTTPException(422, reason) from None
        rows = [dict(row) for row in stage.canonical_rows]
        canonical = hashlib.sha256(json.dumps(rows,ensure_ascii=False,sort_keys=True,separators=(",",":")).encode('utf-8')).hexdigest()
        return {"source_id": source_id, "entity": entity, "format": file_format,
                "raw_sha256": stage.raw_sha256, "byte_count": stage.byte_count,
                "stage_sha256": stage.stage_sha256, "row_count": stage.preflight.row_count,
                "target_snapshot_sha256": stage.preflight.target_snapshot_sha256,
                "canonical_rows_sha256": canonical, "rows": rows,
                "row_import_authorized": False, "persisted": False}

async def _bounded_body(request):
    length = _one_header(request, "content-length")
    if length is not None:
        if not re.fullmatch(r"[0-9]{1,10}", length):
            raise HTTPException(400, "INVALID_CONTENT_LENGTH")
        if int(length) > MAX_BYTES:
            raise HTTPException(413, "FILE_TOO_LARGE")
    buf = bytearray()
    try:
        async with asyncio.timeout(15):
            async for chunk in request.stream():
                if len(buf) + len(chunk) > MAX_BYTES:
                    raise HTTPException(413, "FILE_TOO_LARGE")
                buf.extend(chunk)
    except TimeoutError:
        raise HTTPException(408, "UPLOAD_TIMEOUT") from None
    except ClientDisconnect:
        raise HTTPException(400, "UPLOAD_INCOMPLETE") from None
    if length is not None and len(buf) != int(length):
        raise HTTPException(400, "UPLOAD_LENGTH_MISMATCH")
    if not buf:
        raise HTTPException(422, "FILE_EMPTY")
    return bytes(buf)

def create_router():
    router = APIRouter(prefix=PREFIX, tags=["NARUV isolated file review"])
    @router.post("/sources/{source_id}/{entity}/{file_format}/preview")
    async def preview(source_id: str, entity: str, file_format: str, request: Request, response: Response):
        if not enabled():
            raise HTTPException(404, "PREVIEW_DISABLED")
        if (not IDENT.fullmatch(source_id) or entity not in ("item", "customer")
                or file_format not in FORMATS or request.query_params):
            raise HTTPException(422, "INVALID_PREVIEW_SCOPE")
        if request.url.scheme != "https" or _one_header(request, "origin") not in v90._origins():
            raise HTTPException(403, "ORIGIN_DENIED")
        csrf = _one_header(request, "x-csrf-token", "")
        if not csrf or len(csrf) > 512 or not csrf.isascii():
            raise HTTPException(403, "INVALID_CSRF")
        if _one_header(request, "content-encoding", "identity") != "identity":
            raise HTTPException(415, "ENCODING_UNSUPPORTED")
        content_type = _one_header(request, "content-type", "")
        if content_type != FORMATS[file_format]:
            raise HTTPException(415, "FILE_CONTENT_TYPE")
        token_hash = v90._session_hash(request)
        # Do not hold a database connection while waiting for client bytes.
        prior = await run_in_threadpool(_authorize, token_hash, csrf)
        raw = await _bounded_body(request)
        result = await run_in_threadpool(_preview, token_hash, csrf, prior,
                                         source_id, entity, file_format, raw)
        response.headers["Cache-Control"] = "no-store"
        return result
    return router

def register_native_file_preview(app):
    if not enabled():
        return False
    v90._origins()
    app.include_router(create_router())
    return True
