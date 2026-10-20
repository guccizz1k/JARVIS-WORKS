"""V3.8 synthetic-only, read-only FastAPI -> PG17 compatibility bridge.

Never mounted into app.main; no listener, migrations, real accounts or writes.
The DB's jw_guard session binding and forced RLS are the authorization boundary.
"""
from __future__ import annotations

import os
import re
from hashlib import sha256

from fastapi import FastAPI, Header, HTTPException, Query, Response
from shlex import split as shell_split
from urllib.parse import urlsplit, unquote


class LabRefused(RuntimeError):
    pass


def check_dsn(dsn: str):
    # Pure stdlib preflight so this module can be statically tested without
    # shipping a DB driver in the assistant's local sandbox.
    try:
        if dsn.startswith(('postgresql://', 'postgres://')):
            p = urlsplit(dsn)
            if p.query or p.fragment or not p.hostname or not p.username or not p.password:
                raise ValueError('Ambiguous URI')
            info = {'host':p.hostname, 'user':unquote(p.username),
                    'password':unquote(p.password), 'dbname':unquote(p.path.lstrip('/'))}
        else:
            kv = shell_split(dsn)
            if any(x.count('=')!=1 for x in kv):
                raise ValueError('Malformed DSN')
            info = dict(x.split('=',1) for x in kv)
            if len(info)!=len(kv) or set(info)-{'host','dbname','user','password','port'}:
                raise ValueError('Ambiguous DSN')
    except (ValueError, TypeError, AttributeError) as exc:
        raise LabRefused('Invalid isolated lab connection') from exc
    if (os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE' or
            os.getenv('JW_PG_LAB_V38') != 'ONLY_DISPOSABLE_LAB' or
            not re.fullmatch(r'jw_v20_test_[0-9a-f]{12}', info.get('dbname', '')) or
            info.get('host') not in ('127.0.0.1', 'localhost', '::1') or
            info.get('user') != 'jw_app' or not info.get('password')):
        raise LabRefused('Only isolated synthetic PostgreSQL test database allowed')
    return info


def create_lab_app(dsn: str) -> FastAPI:
    check_dsn(dsn)
    app = FastAPI(title='JARVIS WORKS V3.8 disposable read-only trial',
                  docs_url=None, redoc_url=None, openapi_url=None)
    thread_re = re.compile(r'[a-zA-Z0-9_-]{1,100}\Z')
    msg_re = re.compile(r'[a-zA-Z0-9_-]{1,100}\Z')

    def fetch(token: str | None, thread: str, operation, message_id: str | None = None):
        if not thread_re.fullmatch(thread) or (message_id is not None and not msg_re.fullmatch(message_id)):
            raise HTTPException(422, 'Invalid synthetic identifier')
        if not isinstance(token, str) or not (40 <= len(token) <= 512):
            raise HTTPException(401, 'Synthetic session required')
        check_dsn(dsn)
        try:
            from psycopg import connect, Error as PGError
            # A new PostgreSQL session per API request: bind, read, roll back.
            # No HTTP client can submit a claimed organization/actor identity.
            with connect(dsn, connect_timeout=5) as pg:
                with pg.transaction():
                    with pg.cursor() as cur:
                        cur.execute('SELECT jw_guard.bind_session(%s)', (token,))
                        cur.execute('''SELECT 1 FROM jw_migration_v37.messenger_connections
                                       WHERE id=%s AND status='active' ''', (thread,))
                        if cur.fetchone() is None:
                            raise HTTPException(404, 'Conversation not found')
                        return operation(cur)
        except HTTPException:
            raise
        except ImportError:
            raise HTTPException(503, 'Synthetic test driver unavailable') from None
        except (PGError, LabRefused, ValueError):
            # Don't leak schema names, SQL, credentials or token in errors.
            raise HTTPException(403, 'Synthetic session denied') from None

    @app.get('/lab38/threads/{thread}/messages')
    def messages(thread: str, after: int = Query(default=0, ge=0),
                 limit: int = Query(default=50, ge=1, le=100),
                 x_jw_lab_session: str | None = Header(default=None)):
        def load(cur):
            cur.execute('''SELECT id,message_seq,sender_org,kind,body,order_id,
                                  immutable_order_snapshot,version,created_at
                           FROM jw_migration_v37.messenger_messages
                           WHERE connection_id=%s AND message_seq>%s
                           ORDER BY message_seq LIMIT %s''', (thread, after, limit))
            keys=('id','message_seq','sender_org','kind','body','order_id',
                  'immutable_order_snapshot','version','created_at')
            return {'messages':[dict(zip(keys,row)) for row in cur.fetchall()]}
        return fetch(x_jw_lab_session, thread, load)

    @app.get('/lab38/threads/{thread}/attachments/{message_id}')
    def attachment(thread: str, message_id: str,
                   x_jw_lab_session: str | None = Header(default=None)):
        def load(cur):
            cur.execute('''SELECT a.data,a.mime,a.content_hash,a.size_bytes
                           FROM jw_migration_v37.messenger_attachments a
                           JOIN jw_migration_v37.messenger_messages m
                             ON m.id=a.message_id
                           WHERE m.connection_id=%s AND a.message_id=%s''',(thread,message_id))
            row=cur.fetchone()
            if row is None:
                raise HTTPException(404, 'Attachment not found')
            content, mime, digest, size = row
            b=bytes(content)
            if len(b)!=size or sha256(b).hexdigest()!=digest:
                raise HTTPException(503, 'Synthetic evidence mismatch')
            # Never trust a migrated filename or MIME type for HTML execution.
            return Response(content=b, media_type='application/octet-stream',
                            headers={'X-Content-Type-Options':'nosniff',
                                     'Cache-Control':'no-store',
                                     'Content-Disposition':'attachment',
                                     'X-Content-SHA256':digest})
        return fetch(x_jw_lab_session, thread, load, message_id)

    @app.get('/lab38/threads/{thread}/my-read-position')
    def read_position(thread: str, x_jw_lab_session: str | None = Header(default=None)):
        def load(cur):
            cur.execute('''SELECT last_read_seq FROM jw_migration_v37.messenger_read_positions
                           WHERE connection_id=%s AND org_id=jw_guard.current_tenant()''',(thread,))
            row=cur.fetchone()
            return {'last_read_seq':row[0] if row else 0}
        return fetch(x_jw_lab_session, thread, load)

    return app
