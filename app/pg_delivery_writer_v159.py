"""V15.9 separate credential for signed-delivery ledger writes.

The ordinary trading DB login MUST NOT be capable of SET ROLE into the
dedicated delivery writer. This adapter is opt-in, nonproduction, and fails
closed. It authenticates the same company session again *inside* the writer
transaction, not via caller-supplied org/actor strings.
"""
from __future__ import annotations

import os
from contextlib import contextmanager

from fastapi import HTTPException

from . import pg_v90_integrated_entry as sessions

_MODE = "ISOLATED_DEV_SEPARATE_REVIEW_WRITER"


def enabled() -> bool:
    return (
        os.getenv("JW_PG_DELIVERY_WRITER_V159") == _MODE
        and sessions.v90_enabled()
        and os.getenv("JW_ENV", "").lower() in ("dev", "development", "test")
        and os.getenv("JW_INSECURE_LOCAL_DEV") != "1"
    )


def _connect():
    if not enabled():
        raise RuntimeError("Separate delivery writer is disabled")
    dsn = os.getenv("JW_PG_DELIVERY_WRITER_DSN", "")
    trade = os.getenv("JW_PG_STAGE_DSN", "")
    auth = os.getenv("JW_PG_AUTH_STAGE_DSN", "")
    if not dsn or not trade or not auth or dsn in (trade, auth):
        raise RuntimeError("Delivery writer credential must be separate")
    try:
        import psycopg
    except ImportError as exc:
        raise RuntimeError("Separate PostgreSQL writer dependency missing") from exc
    return psycopg.connect(dsn,connect_timeout=5,sslmode="verify-full")


@contextmanager
def validated_writer_cursor(session_hash: str):
    if not enabled() or not isinstance(session_hash, str) or len(session_hash) != 64:
        raise HTTPException(503, "Dedicated writer unavailable")
    with _connect() as db:
        with db.transaction():
            with db.cursor() as cur:
                cur.execute("""SELECT session_user,r.rolsuper,r.rolbypassrls,
                                      r.rolcreaterole,r.rolcreatedb
                               FROM pg_catalog.pg_roles r
                               WHERE r.rolname=session_user""")
                login=cur.fetchone()
                if (not login or login[0] in
                        ("postgres","supabase_admin","service_role",
                         "jw_app_dev","jw_delivery_writer_v159")
                    or any(login[1:])):
                    raise HTTPException(503,"Unsafe writer DB login")
                for forbidden in ("jw_app_dev","jw_auth_stage_v85"):
                    cur.execute("SELECT pg_catalog.pg_has_role(session_user,%s,'MEMBER')",
                                (forbidden,))
                    if cur.fetchone() != (False,):
                        raise HTTPException(503, "Unsafe writer role membership")
                cur.execute("SET LOCAL ROLE jw_delivery_writer_v159")
                cur.execute("SELECT pg_catalog.set_config('jw.session_hash',%s,true)",
                            (session_hash,))
                cur.execute("""SELECT current_user,actor_id,org_id,
                                      actor_role,csrf_token,org_name
                               FROM jw_dev.stage_identity_v84()""")
                identity=cur.fetchone()
                if (not identity or len(identity)!=6 or
                    identity[0]!="jw_delivery_writer_v159" or
                    not all(identity[1:])):
                    raise HTTPException(401,"Writer session invalid or expired")
                yield cur,identity
