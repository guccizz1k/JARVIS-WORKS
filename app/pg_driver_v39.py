"""V3.9 verified, request-scoped Psycopg 3 cursor for disposable PG17 reads.

NOT a production connection provider. The existing SQLite runtime never imports
this module. The caller retains the original RLS-controlled SELECT privileges.
Every request gets a fresh connection/transaction and always rolls it back.
"""
from __future__ import annotations

from contextlib import contextmanager

from app.pg_compat_read_api_v38 import LabRefused, check_dsn


@contextmanager
def verified_read_cursor(dsn: str, token: str):
    """Bind one signed actor session; fail shut and close on every return path.

    The database's jw_guard SQL and force-RLS remain the source of authority.
    No caller-supplied company or user ID is accepted. This must never be used
    against persistent databases or with a privileged PostgreSQL role.
    """
    check_dsn(dsn)
    if not isinstance(token, str) or not (40 <= len(token) <= 512):
        raise LabRefused('Verified synthetic session required')
    try:
        import psycopg
    except ImportError as exc:
        raise LabRefused('Psycopg 3 is unavailable in isolated laboratory') from exc

    # Keep this intentionally unpooled until tenant-session bleed and resource
    # exhaustion are tested independently with the selected production schema.
    pg = psycopg.connect(dsn, connect_timeout=5)
    try:
        with pg.cursor() as cur:
            # LOCAL: only this transaction, not subsequent uses of the socket.
            cur.execute("SET LOCAL statement_timeout = '5000ms'")
            cur.execute("SET LOCAL lock_timeout = '2000ms'")
            cur.execute("SET LOCAL idle_in_transaction_session_timeout = '8000ms'")
            cur.execute("""SELECT current_database(),current_user,
                          current_setting('server_version_num'),
                          COALESCE((SELECT rolsuper OR rolbypassrls
                            FROM pg_catalog.pg_roles WHERE rolname=current_user),true)""")
            db, user, version, privileged = cur.fetchone()
            if (db != check_dsn(dsn)['dbname'] or user != 'jw_app'
                    or int(version)//10000 != 17 or privileged):
                raise LabRefused('Refuse unexpected PostgreSQL role or version')
            cur.execute('SELECT jw_guard.bind_session(%s)', (token,))
            cur.execute('SELECT jw_guard.current_tenant(),jw_guard.current_actor()')
            tenant, actor = cur.fetchone()
            if not tenant or not actor:
                raise LabRefused('Session has no verified tenant and actor')
            yield cur
    finally:
        try:
            # Even a successful GET must not leave a bound GUC or commit data.
            pg.rollback()
        finally:
            pg.close()
