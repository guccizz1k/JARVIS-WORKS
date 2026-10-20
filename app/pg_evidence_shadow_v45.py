"""V4.5 disposable-only, read-only full messenger evidence parity audit.

Uses V3.7 *compatibility* schema, not the incompatible production-shaped PG
messenger schema. Must never be registered on app.main or used for cutover.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
from typing import Callable

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import JSONResponse

from app.pg_cookie_shadow_v44 import ReviewBinding, ReviewFault, _mapping, _gate
from app.pg_web_bridge_v43 import classify_database_error

THREAD = re.compile(r"[a-f0-9]{32}\Z")
MAX_MESSAGES = 100
MAX_DEPENDENTS = 500
MAX_TOTAL_BYTES = 16 * 1024 * 1024
KINDS = ('messenger_messages', 'messenger_edits', 'messenger_attachments',
         'messenger_read_positions', 'messenger_receipts')


class EvidenceLimit(ValueError):
    """Oversized or unrepresentable evidence must never become MATCH."""


class AuditFault(HTTPException):
    def __init__(self, status_code, code):
        super().__init__(status_code, detail={
            'AUTH_DENIED': 'Evidence review denied',
            'THREAD_NOT_FOUND': 'Conversation not found',
            'INVALID_THREAD': 'Invalid conversation identifier',
            'PG_UNAVAILABLE': 'Isolated evidence review unavailable',
        }[code])
        self.code = code


def _columns():
    # Reuse the tested V3.7 schema shape. No parallel migration engine.
    from app.pg_migration_compat_v37 import COLUMNS
    return {name: COLUMNS[name] for name in KINDS}


def _read(store, *, pg: bool, thread: str, org: str):
    """Reads one thread's 5 evidence types under a single transaction/snapshot.

    On PostgreSQL this MUST be executed with jw_app and a verified, RLS-bound
    transaction; on SQLite caller holds the website read transaction.
    No user-controlled SQL identifiers are interpolated.
    """
    cols = _columns()
    placeholder = '%s' if pg else '?'
    prefix = 'jw_migration_v37.' if pg else ''
    def fetch(table, where, args, max_rows):
        select = ','.join(cols[table])
        store.execute(f'SELECT {select} FROM {prefix}{table} WHERE {where} LIMIT {max_rows + 1}', tuple(args))
        results = store.fetchall()
        if len(results) > max_rows:
            raise EvidenceLimit('Bounded evidence inspection exceeded')
        return [tuple(bytes(v) if isinstance(v, memoryview) else v for v in row) for row in results]

    messages = fetch('messenger_messages', f'connection_id={placeholder}', (thread,), MAX_MESSAGES)
    result = {'messenger_messages': messages}
    ids = [r[0] for r in messages]
    if len(ids) != len(set(ids)) or any(not isinstance(x, str) or not x for x in ids):
        raise EvidenceLimit('Duplicate/unrepresentable message identifiers')
    for table in ('messenger_edits', 'messenger_attachments', 'messenger_receipts'):
        if not ids:
            result[table] = []
        elif pg:
            result[table] = fetch(table, 'message_id = ANY(%s)', (ids,), MAX_DEPENDENTS)
        else:
            qs = ','.join('?' for _ in ids)
            result[table] = fetch(table, f'message_id IN ({qs})', ids, MAX_DEPENDENTS)
    result['messenger_read_positions'] = fetch('messenger_read_positions',
           f'connection_id={placeholder} AND org_id={placeholder}',
           (thread, org), MAX_DEPENDENTS)
    return result


def _mapped_pg_row(table, cols, row, org_map, user_map):
    if len(row) != len(cols):
        raise EvidenceLimit('Malformed PostgreSQL evidence row')
    updates = {
        'sender_org': org_map, 'receiver_org': org_map, 'org_id': org_map,
        'sender_user': user_map, 'receiver_user': user_map, 'actor_user': user_map,
    }
    vals = list(row)
    for idx, name in enumerate(cols):
        if name in updates:
            if vals[idx] not in updates[name]:
                raise EvidenceLimit('Unmapped database actor or tenant')
            vals[idx] = updates[name][vals[idx]]
    return vals


def compare_evidence(source, target, *, org_map, user_map):
    """Exact values and raw binary bytes; no sensitive payloads in the result.

    Scope is the authorized thread and requesting tenant's read marker only.
    This is NOT a total-site migration approval even when MATCH.
    """
    from app.pg_migration_shadow_v36 import canonical_bytes
    cols = _columns()
    if set(source) != set(KINDS) or set(target) != set(KINDS):
        raise EvidenceLimit('Missing evidence category')
    if not source['messenger_messages'] or not target['messenger_messages']:
        return 'EMPTY_UNVERIFIED', {k:0 for k in KINDS}
    counts = {}
    budget = 0
    mismatch = False
    supported = ('messenger_attachments', 'messenger_edits', 'messenger_receipts')
    if not any(source[k] for k in supported):
        return 'EMPTY_EVIDENCE', {k:len(source[k]) for k in KINDS}
    for name in KINDS:
        schema = cols[name]
        left, right = source[name], target[name]
        counts[name] = len(left)
        if len(left) != len(right):
            mismatch = True
        normalized = []
        for row in right:
            normalized.append(tuple(_mapped_pg_row(name, schema, row, org_map, user_map)))
        for row in list(left) + normalized:
            if len(row) != len(schema):
                raise EvidenceLimit('Unrepresentable evidence schema')
            data = canonical_bytes(name, schema, row)
            budget += len(data)
            if budget > MAX_TOTAL_BYTES:
                raise EvidenceLimit('Evidence byte budget exceeded')
        # Order-independent across different tables but not across individual
        # stored records; canonical byte strings preserve kind/version/blob.
        aa = sorted(canonical_bytes(name, schema, r) for r in left)
        bb = sorted(canonical_bytes(name, schema, r) for r in normalized)
        if aa != bb:
            mismatch = True
    return ('MISMATCH' if mismatch else 'MATCH'), counts


def create_review_app(*, dsn: str, adapter, sqlite_conn: Callable,
                      trusted_broker: Callable,
                      website_current_user: Callable | None = None):
    """A SEPARATE, isolated GET-only app. Never register on public app.main."""
    _gate(dsn)
    adapter._check_dsn()
    if website_current_user is None:
        from app.main import current_user as website_current_user
    lab = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @lab.middleware('http')
    async def no_store(request, call_next):
        result = await call_next(request)
        result.headers['Cache-Control'] = 'no-store'
        result.headers['X-Content-Type-Options'] = 'nosniff'
        return result

    @lab.exception_handler(AuditFault)
    async def fault(request, exc):
        return JSONResponse({'detail':exc.detail,'code':exc.code},status_code=exc.status_code)

    @lab.exception_handler(Exception)
    async def unknown(request, exc):
        return JSONResponse({'detail':'Isolated evidence review unavailable',
                             'code':'PG_UNAVAILABLE'},status_code=503)

    @lab.get('/lab45/threads/{thread}/evidence')
    def evidence(thread: str, user=Depends(website_current_user)):
        try:
            _gate(dsn)
        except Exception:
            raise AuditFault(503, 'PG_UNAVAILABLE') from None
        if not THREAD.fullmatch(thread):
            raise AuditFault(422, 'INVALID_THREAD')
        if not isinstance(user, dict) or not isinstance(user.get('org_id'),str) or not user.get('id'):
            raise AuditFault(403,'AUTH_DENIED')
        try:
            with sqlite_conn() as source:
                # Snapshot-bound consistency within the SQLite side; no writes.
                source.execute('BEGIN')
                try:
                    permitted = source.execute('''SELECT 1 FROM messenger_connections t
                      WHERE t.id=? AND (t.org_a=? OR t.org_b=?) AND t.status='active'
                      AND EXISTS(SELECT 1 FROM messenger_companies c WHERE c.org_id=t.org_a)
                      AND EXISTS(SELECT 1 FROM messenger_companies c WHERE c.org_id=t.org_b)''',
                      (thread, user['org_id'], user['org_id'])).fetchone()
                    if not permitted:
                        raise AuditFault(404,'THREAD_NOT_FOUND')
                    src = _read(source.cursor(), pg=False, thread=thread, org=user['org_id'])
                finally:
                    source.rollback()
        except AuditFault:
            raise
        except EvidenceLimit:
            return {'status':'INCOMPLETE','evidence_parity':False,'cutover_approved':False}
        except Exception:
            raise AuditFault(503,'PG_UNAVAILABLE') from None
        try:
            binding = trusted_broker(user['org_id'],user['id'],thread)
            try:
                org_map, user_map = _mapping(user,binding)
            except ReviewFault:
                raise AuditFault(403,'AUTH_DENIED') from None
            with adapter.verified_transaction(binding.pg_token, readonly=True) as (cur,pg_org,pg_user):
                if (pg_org,pg_user)!=(binding.pg_org,binding.pg_user):
                    raise AuditFault(403,'AUTH_DENIED')
                cur.execute('''SELECT 1 FROM jw_migration_v37.messenger_connections
                               WHERE id=%s AND status='active' ''',(binding.pg_thread,))
                if cur.fetchone() is None:
                    raise AuditFault(404,'THREAD_NOT_FOUND')
                dst = _read(cur,pg=True,thread=binding.pg_thread,org=binding.pg_org)
            status, counts = compare_evidence(src,dst,org_map=org_map,user_map=user_map)
        except AuditFault:
            raise
        except EvidenceLimit:
            status,counts='INCOMPLETE',{}
        except Exception as exc:
            response = classify_database_error(exc)
            raise AuditFault(403 if response.status==403 else 503,
                             'AUTH_DENIED' if response.status==403 else 'PG_UNAVAILABLE') from None
        # Counts have no values, filenames, content, raw hashes, IDs or tokens.
        return {'status':status,'evidence_parity':status=='MATCH',
                'cutover_approved':False,'counts':counts,
                'scope':'single_thread_requester_read_marker'}
    return lab
