"""V8.4 opt-in PostgreSQL *read-only* FastAPI shadow endpoints.

Never replaces legacy SQLite routes or creates/revokes sessions. A prior,
PostgreSQL-native session is required; there is NO SQLite fallback.
Production deployment, writes and auth migration remain blocked.
"""
from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from dataclasses import dataclass

from fastapi import APIRouter, FastAPI, HTTPException, Query, Request

_STAGE_MODE = 'ISOLATED_DEV_READ_ONLY'
_PREFIX = '/api/pg-stage/v84'
_COOKIE = '__Host-jw_session'


@dataclass(frozen=True)
class PgIdentity:
    actor_id: str
    org_id: str
    actor_role: str
    org_name: str


def stage_enabled() -> bool:
    return (os.getenv('JW_PG_STAGE_V84') == _STAGE_MODE
            and os.getenv('JW_ENV', '').lower() not in ('prod', 'production'))


def _connect():
    if not stage_enabled():
        raise RuntimeError('PostgreSQL shadow API is disabled')
    dsn = os.getenv('JW_PG_STAGE_DSN', '')
    if not dsn:
        raise RuntimeError('Stage-only PostgreSQL DSN missing')
    try:
        import psycopg  # optional dependency; never import on legacy runtime
    except ImportError as exc:
        raise RuntimeError('Install psycopg stage dependency to use shadow API') from exc
    # Do not disable TLS verification to accommodate a misconfigured host.
    return psycopg.connect(dsn, connect_timeout=5, sslmode='verify-full')


@contextmanager
def pg_read_session(request: Request):
    """Validate the PG session and delegate a single read-only transaction.

    Caller must own the session cookie. Only the server derives the session
    hash and controls SQL parameters. The DB login must be non-privileged,
    with SET ROLE rights only for jw_app_dev; this is checked every request.
    """
    if not stage_enabled():
        raise HTTPException(404, 'PostgreSQL stage route disabled')
    if request.method not in ('GET', 'HEAD'):
        raise HTTPException(405, 'Stage API is read-only')
    token = request.cookies.get(_COOKIE, '')
    if len(token) < 30 or len(token) > 512:
        raise HTTPException(401, 'PostgreSQL session required')
    session_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
    with _connect() as db:
        with db.transaction():
            with db.cursor() as cur:
                cur.execute('SET TRANSACTION READ ONLY')
                cur.execute('''SELECT session_user,r.rolsuper,r.rolbypassrls,
                             r.rolcreaterole,r.rolcreatedb
                             FROM pg_catalog.pg_roles r
                             WHERE r.rolname=session_user''')
                login = cur.fetchone()
                if (not login or login[0] in ('postgres','supabase_admin','service_role')
                        or any(login[1:])):
                    raise HTTPException(503, 'Unsafe PostgreSQL login configured')
                cur.execute('SET LOCAL ROLE jw_app_dev')
                cur.execute("SELECT pg_catalog.set_config('jw.session_hash', %s, true)",
                            (session_hash,))
                cur.execute('''SELECT current_user, actor_id,org_id,actor_role,csrf_token,org_name
                             FROM jw_dev.stage_identity_v84()''')
                row = cur.fetchone()
                if not row or row[0] != 'jw_app_dev' or not all(row[1:]):
                    raise HTTPException(401, 'PostgreSQL session invalid or expired')
                identity = PgIdentity(actor_id=row[1],org_id=row[2],
                                      actor_role=row[3],org_name=row[5])
                yield cur, identity


def _records(cursor):
    cols = [d.name for d in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def create_stage_router() -> APIRouter:
    router = APIRouter(prefix=_PREFIX, tags=['PostgreSQL shadow (dev only)'])

    @router.get('/me')
    def identity(request: Request):
        with pg_read_session(request) as (_, identity):
            return dict(actor_id=identity.actor_id,org_id=identity.org_id,
                        actor_role=identity.actor_role,org_name=identity.org_name,
                        backend='postgresql_stage_read_only')

    @router.get('/customers')
    def customers(request: Request, limit: int = Query(default=50,ge=1,le=100)):
        with pg_read_session(request) as (cur, _):
            cur.execute('''SELECT id,name,business_number,contact_name,email,phone,created_at
                           FROM jw_dev.customers ORDER BY created_at DESC,id DESC LIMIT %s''',(limit,))
            return _records(cur)

    @router.get('/quotes')
    def quotes(request: Request, limit: int = Query(default=50,ge=1,le=100)):
        with pg_read_session(request) as (cur, _):
            cur.execute('''SELECT id,customer_id,customer_name_snapshot,doc_no,title,
                           status,vat_mode,created_at,updated_at FROM jw_dev.quotes
                           ORDER BY created_at DESC,id DESC LIMIT %s''',(limit,))
            return _records(cur)

    @router.get('/orders')
    def orders(request: Request, limit: int = Query(default=50,ge=1,le=100)):
        with pg_read_session(request) as (cur, _):
            cur.execute('''SELECT id,quote_id,customer_id,doc_no,title,status,review_state,
                           vat_mode,due_date,created_at FROM jw_dev.orders
                           ORDER BY created_at DESC,id DESC LIMIT %s''',(limit,))
            return _records(cur)

    @router.get('/invoices')
    def invoices(request: Request, limit: int = Query(default=50,ge=1,le=100)):
        with pg_read_session(request) as (cur, _):
            cur.execute('''SELECT id,order_id,customer_id,doc_no,status,vat_mode,due_date,
                           created_at FROM jw_dev.invoices
                           ORDER BY created_at DESC,id DESC LIMIT %s''',(limit,))
            return _records(cur)

    @router.get('/invoices/{invoice_id}/payments')
    def payments(invoice_id: str, request: Request,
                 limit: int = Query(default=50,ge=1,le=100)):
        if not invoice_id or len(invoice_id) > 128:
            raise HTTPException(404, 'Invoice not found')
        with pg_read_session(request) as (cur, _):
            cur.execute('SELECT id FROM jw_dev.invoices WHERE id=%s',(invoice_id,))
            if not cur.fetchone():
                raise HTTPException(404, 'Invoice not found')
            cur.execute('''SELECT id,amount,paid_at,note,created_at,reversed_at
                           FROM jw_dev.payments WHERE invoice_id=%s
                           ORDER BY paid_at DESC,created_at DESC,id DESC LIMIT %s''',
                        (invoice_id,limit))
            return _records(cur)
    return router


def register_stage_api(app: FastAPI) -> bool:
    """Mount only on explicit isolated-dev opt-in, never in production."""
    if not stage_enabled():
        return False
    if os.getenv('JW_INSECURE_LOCAL_DEV') == '1':
        raise RuntimeError('PostgreSQL shadow API requires secure cookies')
    app.include_router(create_stage_router())
    return True
