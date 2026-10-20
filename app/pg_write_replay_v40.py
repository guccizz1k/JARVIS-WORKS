"""V4.0 disposable-only, tenant-bound, idempotent messenger writes.

Never mounted into app.main. Uses existing V3.5 review adapter and V2.7 PG17
RLS rather than creating another tenant/session authority. This module is not
approved for real organizations or production databases.
"""
from __future__ import annotations

import os
import re
import uuid

from app.pg_messenger_review import MessengerReviewAdapter, PostgreSQLUnverified

_THREAD = re.compile(r'[a-zA-Z0-9_-]{1,100}\Z')
_REQUEST = re.compile(r'[a-f0-9]{32}\Z')
_UNIQUE_REQUEST = 'messenger_messages_sender_org_request_id_key'


class ReplayConflict(ValueError):
    """An idempotency key was already used for a different actor or payload."""


class LabWriterV40:
    """Safe test-only idempotent insertion; database RLS remains authoritative."""

    def __init__(self, dsn: str, *, adapter=None):
        self.adapter = adapter or MessengerReviewAdapter(dsn)
        self.adapter._check_dsn()

    @staticmethod
    def _gate(thread: str, content: str, request_id: str):
        if (os.getenv('JW_PG_LAB_V40') != 'ONLY_DISPOSABLE_LAB' or
                os.getenv('JW_PG_ALLOW_TEST_WRITES') != 'ONLY_EPHEMERAL_DATABASE'):
            raise PostgreSQLUnverified('No disposable V4.0 authorization')
        if not isinstance(thread, str) or _THREAD.fullmatch(thread) is None:
            raise ValueError('Invalid synthetic thread identifier')
        if not isinstance(content, str) or not content.strip() or len(content) > 2000:
            raise ValueError('Invalid message content')
        if not isinstance(request_id, str) or _REQUEST.fullmatch(request_id) is None:
            raise ValueError('Invalid idempotency key')

    @staticmethod
    def _lookup(cur, *, tenant, actor, thread, content, request_id):
        cur.execute('''SELECT id,message_seq,connection_id,sender_user,kind,body
                       FROM public.messenger_messages
                       WHERE sender_org=%s AND request_id=%s''', (tenant, request_id))
        row = cur.fetchone()
        if row is None:
            return None
        msg_id, seq, existing_thread, owner, kind, original = row
        if (existing_thread, owner, kind, original) != (thread, actor, 'text', content):
            raise ReplayConflict('Idempotency key already used for different payload')
        return {'id': msg_id, 'message_seq': seq, 'replayed': True}

    def send_text(self, *, token: str, thread: str, content: str, request_id: str):
        self._gate(thread, content, request_id)
        try:
            # The constraint on (sender_org, request_id), not a client-side
            # cache, resolves concurrent requests. Two attempts never commit
            # duplicate records even with separate HTTP worker processes.
            with self.adapter.verified_transaction(token, readonly=False) as (cur, tenant, actor):
                cur.execute("SET LOCAL lock_timeout = '2000ms'")
                previous = self._lookup(cur, tenant=tenant, actor=actor, thread=thread,
                                        content=content, request_id=request_id)
                if previous:
                    return previous
                cur.execute('''INSERT INTO public.messenger_messages
                         (id,connection_id,sender_org,sender_user,kind,body,request_id)
                         VALUES(%s,%s,%s,%s,'text',%s,%s)
                         RETURNING id,message_seq''',
                         (uuid.uuid4().hex, thread, tenant, actor, content, request_id))
                msg_id, seq = cur.fetchone()
                return {'id': msg_id, 'message_seq': seq, 'replayed': False}
        except Exception as exc:
            # A concurrent insert can win after our initial SELECT. The first
            # transaction is rolled back by the adapter before looking up the
            # winning row in a fresh verified transaction.
            # SQLSTATE 23505 is a unique constraint violation in PostgreSQL.
            # Don't intercept any authorization, session or input error.
            if getattr(exc, 'sqlstate', None) != '23505':
                raise
            if getattr(getattr(exc, 'diag', None), 'constraint_name', None) != _UNIQUE_REQUEST:
                raise
            with self.adapter.verified_transaction(token, readonly=True) as (cur, tenant, actor):
                winner = self._lookup(cur, tenant=tenant, actor=actor, thread=thread,
                                      content=content, request_id=request_id)
                if winner is None:
                    raise PostgreSQLUnverified('Concurrent replay not visible; retry safely') from None
                return winner
