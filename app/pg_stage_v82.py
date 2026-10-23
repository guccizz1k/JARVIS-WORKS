"""V8.2 experimental PostgreSQL write boundary -- NOT mounted on FastAPI.

A caller must inject a trusted DBAPI connection from a dedicated, low-privilege
login with SET ROLE jw_app_dev permission. Never connect as postgres/admin or use
an API service-role key. The active server-side session must already exist in
Postgres. This module deliberately does not migrate auth or switch the app DB.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo
from contextlib import contextmanager


class PgStageBlocked(RuntimeError):
    """The caller or DB session did not meet staging safety requirements."""


@contextmanager
def validated_pg_session(connection, *, raw_session_token: str, actor_id: str, org_id: str):
    if os.environ.get('JW_ENV', '').lower() in ('production', 'prod'):
        raise PgStageBlocked('Production cutover not authorized')
    if os.environ.get('JW_PG_STAGE_V82') != 'DISPOSABLE_PG_STAGE_ONLY':
        raise PgStageBlocked('Explicit staging opt-in required')
    if not isinstance(raw_session_token, str) or len(raw_session_token) < 30:
        raise PgStageBlocked('Invalid session token')
    if not actor_id or not org_id:
        raise PgStageBlocked('Missing trusted authenticated actor')
    session_hash = hashlib.sha256(raw_session_token.encode('utf-8')).hexdigest()
    # The client driver must support PostgreSQL transaction() and cursor().
    # SET LOCAL keeps tenant identity and the delegated role scoped to one tx.
    with connection.transaction():
        with connection.cursor() as cur:
            cur.execute("""SELECT session_user, r.rolsuper, r.rolbypassrls,
                         r.rolcreaterole, r.rolcreatedb
                         FROM pg_catalog.pg_roles r WHERE r.rolname=session_user""")
            row = cur.fetchone()
            if (not row or row[0] in ('postgres', 'supabase_admin', 'service_role')
                    or any(row[1:5])):
                raise PgStageBlocked('Privileged or unverified login rejected')
            cur.execute('SET LOCAL ROLE jw_app_dev')
            cur.execute("SELECT pg_catalog.set_config('jw.session_hash', %s, true)",
                        (session_hash,))
            cur.execute("""SELECT current_user,
                         jw_dev.current_org_from_session(),
                         jw_dev.current_actor_from_session_v82()""")
            identity = cur.fetchone()
            if identity != ('jw_app_dev', org_id, actor_id):
                raise PgStageBlocked('PostgreSQL session and application actor disagree')
            yield cur


def _stamp():
    return datetime.now(ZoneInfo('Asia/Seoul')).isoformat(timespec='seconds')


def create_customer_stage(connection, *, token, actor_id, org_id, name,
                          business_number='', contact_name='', email='', phone=''):
    """One atomic customer + audit write for synthetic pre-production testing.

    No automatic retry: unique conflicts and uncertain commits require explicit
    reconciliation to avoid duplicate customer creation.
    """
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError('Invalid customer name')
    cid = uuid.uuid4().hex
    with validated_pg_session(connection, raw_session_token=token,
                              actor_id=actor_id, org_id=org_id) as cur:
        cur.execute('''INSERT INTO jw_dev.customers
                  (id,org_id,name,business_number,contact_name,email,phone,created_at)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s)''',
                  (cid, org_id, name.strip(), business_number, contact_name,
                   email, phone, _stamp()))
        cur.execute('''INSERT INTO jw_dev.audit_logs
                  (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
                  VALUES (%s,%s,%s,'customer',%s,'create',%s,%s)''',
                  (uuid.uuid4().hex, org_id, actor_id, cid,
                   '{"source":"postgres_stage_v82"}', _stamp()))
    return cid


def create_quote_stage(connection, *, token, actor_id, org_id, customer_id,
                       title, vat_mode, items):
    """Atomic quote + item + audit prototype; not registered as an endpoint."""
    if not isinstance(items, (list, tuple)) or not 1 <= len(items) <= 40:
        raise ValueError('Invalid item count')
    if vat_mode not in ('taxable', 'exempt') or not title or not customer_id:
        raise ValueError('Invalid quote fields')
    checked=[]
    for item in items:
        name, qty, price=item
        if (not isinstance(name,str) or not name.strip() or len(name)>150
            or type(qty) is not int or not (1 <= qty <= 100000)
            or type(price) is not int or not (0 <= price <= 1000000000)):
            raise ValueError('Invalid quote item')
        checked.append((name.strip(),qty,price))
    quote_id=uuid.uuid4().hex
    document_no=f'Q-{datetime.now(ZoneInfo("Asia/Seoul")):%Y%m%d}-{quote_id[:10].upper()}'
    with validated_pg_session(connection, raw_session_token=token,
                              actor_id=actor_id, org_id=org_id) as cur:
        cur.execute('''SELECT name FROM jw_dev.customers
                       WHERE id=%s AND org_id=%s''',(customer_id,org_id))
        customer=cur.fetchone()
        if not customer:
            raise PgStageBlocked('Customer unavailable in tenant')
        stamp=_stamp()
        cur.execute('''INSERT INTO jw_dev.quotes
           (id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at)
           VALUES (%s,%s,%s,%s,%s,%s,'draft',%s,%s,%s)''',
           (quote_id,org_id,customer_id,customer[0],document_no,title,vat_mode,stamp,stamp))
        for pos,(name,qty,price) in enumerate(checked):
            cur.execute('''INSERT INTO jw_dev.quote_items
                       (id,quote_id,name,quantity,unit_price,position)
                       VALUES (%s,%s,%s,%s,%s,%s)''',
                        (uuid.uuid4().hex,quote_id,name,qty,price,pos))
        cur.execute('''INSERT INTO jw_dev.audit_logs
                  (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
                  VALUES (%s,%s,%s,'quote',%s,'create',%s,%s)''',
                  (uuid.uuid4().hex,org_id,actor_id,quote_id,
                   '{"source":"postgres_stage_v82"}',stamp))
    return quote_id
