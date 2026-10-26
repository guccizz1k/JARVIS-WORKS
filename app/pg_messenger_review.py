"""V3.0 REVIEW-ONLY PostgreSQL messenger adapter. NOT WIRED TO FASTAPI.

The runtime SQLite app and production block remain untouched. This adapter
intentionally refuses all non-ephemeral databases and is not a substitute for
verified provisioning / verified session registry / object storage / RLS audits.
"""
from __future__ import annotations
import re
import uuid
from urllib.parse import urlparse
from contextlib import contextmanager

PG_TEST_DB = re.compile(r'^jw_v20_test_[0-9a-f]{12}$')

class PostgreSQLUnverified(RuntimeError):
    pass

class MessengerReviewAdapter:
    def __init__(self, dsn: str):
        self.dsn = dsn

    def _check_dsn(self):
        # Refuse even to open a TCP connection to real/customer databases.
        # No DSN query overrides, UNIX sockets, superusers or remote hosts.
        try:
            url = urlparse(self.dsn)
            host = url.hostname
            _ = url.port  # Reject malformed port syntax early.
        except (TypeError, ValueError) as exc:
            raise PostgreSQLUnverified('Invalid disposable DSN') from exc
        if (url.scheme not in ('postgres', 'postgresql') or
            host not in ('127.0.0.1','localhost','::1') or
            url.username != 'jw_app' or not url.password or
            not PG_TEST_DB.fullmatch(url.path.removeprefix('/')) or
            url.query or url.fragment or url.params):
            raise PostgreSQLUnverified('Only loopback ephemeral jw_app DSN is permitted')

    @contextmanager
    def verified_transaction(self, bound_token: str, *, readonly: bool = True):
        if not isinstance(bound_token, str) or len(bound_token) < 40:
            raise PostgreSQLUnverified('Verified session token required')
        self._check_dsn()
        try:
            import psycopg
        except ImportError as exc:
            raise PostgreSQLUnverified('psycopg3 not installed: review adapter unavailable') from exc
        # This is a test-only seam, not an arbitrary DSN to a production DB.
        with psycopg.connect(self.dsn, connect_timeout=5) as db:
            with db.cursor() as cur:
                # PostgreSQL requires SET TRANSACTION before any SELECT in a tx.
                if readonly:
                    cur.execute('SET TRANSACTION READ ONLY')
                cur.execute('SELECT current_database(),current_user')
                database, role = cur.fetchone()
                if not PG_TEST_DB.fullmatch(database) or role != 'jw_app':
                    raise PostgreSQLUnverified('Disposable PostgreSQL 17 / jw_app only')
                cur.execute('SHOW server_version_num')
                if int(cur.fetchone()[0]) // 10000 != 17:
                    raise PostgreSQLUnverified('PostgreSQL 17 required')
                # set_config is parameterizable; SET statement values are not.
                cur.execute("SELECT pg_catalog.set_config('statement_timeout',%s,true)",('5s',))
                # bind_session verifies the revocable signed context in jw_guard.
                cur.execute('SELECT jw_guard.bind_session(%s)',(bound_token,))
                cur.execute('SELECT jw_guard.current_tenant(),jw_guard.current_actor()')
                tenant, actor = cur.fetchone()
                if not tenant or not actor:
                    raise PostgreSQLUnverified('Verified employee identity not available')
                yield cur, tenant, actor
                # psycopg context commits only on successful exit.

    def list_messages(self, bound_token: str, thread_id: str, *, after: int = 0, limit: int = 50):
        if not isinstance(after,int) or after<0 or not isinstance(limit,int) or not 1<=limit<=100:
            raise ValueError('Invalid message pagination')
        with self.verified_transaction(bound_token) as (cur,tenant,actor):
            # Security does NOT depend on this filter alone: RLS provides the
            # authoritative second boundary for both org and thread.
            cur.execute('''SELECT id,message_seq,sender_org,sender_user,kind,body,created_at
                FROM public.messenger_messages
                WHERE connection_id=%s AND message_seq>%s
                ORDER BY message_seq ASC LIMIT %s''',(thread_id,after,limit))
            return cur.fetchall()

    def send_text(self, bound_token: str, thread_id: str, content: str, request_id: str):
        if not isinstance(content,str) or not content.strip() or len(content)>2000:
            raise ValueError('Invalid message content')
        if not isinstance(request_id,str) or not re.fullmatch(r'[a-f0-9]{32}',request_id):
            raise ValueError('Request ID must be a canonical 128-bit hex value')
        with self.verified_transaction(bound_token,readonly=False) as (cur,tenant,actor):
            cur.execute('''INSERT INTO public.messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id)
                VALUES (%s,%s,%s,%s,'text',%s,%s)
                RETURNING id,message_seq''',
                (uuid.uuid4().hex,thread_id,tenant,actor,content,request_id))
            return cur.fetchone()

    def mark_read(self, bound_token: str, thread_id: str, last_seq: int):
        if not isinstance(last_seq,int) or last_seq<0:
            raise ValueError('Invalid read position')
        with self.verified_transaction(bound_token,readonly=False) as (cur,tenant,actor):
            # The server-side trigger enforces <= last committed sequence;
            # the SQL is monotonic and scoped to the bound organization.
            cur.execute('''INSERT INTO public.messenger_read_positions
                (connection_id,org_id,last_read_seq) VALUES(%s,%s,%s)
                ON CONFLICT(connection_id,org_id) DO UPDATE
                SET last_read_seq=GREATEST(public.messenger_read_positions.last_read_seq,
                                           EXCLUDED.last_read_seq)''',
                (thread_id,tenant,last_seq))
            return True
