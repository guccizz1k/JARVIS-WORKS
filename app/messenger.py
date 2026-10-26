"""V2.5 organization-to-organization trade messaging (demo/MVP, not production certified).

Registered orgs only. Verification is operator-controlled: no self-approval API exists.
No deletion endpoint; the database rejects ordinary DELETE of message evidence.
"""
from __future__ import annotations

import hashlib
import json
import io
import asyncio
import re
import zipfile
from pathlib import PurePath
import sqlite3
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from typing import Callable

from fastapi import Depends, File, Form, UploadFile, Response, Query, Request
from pydantic import BaseModel, ConfigDict, Field
from fastapi.responses import StreamingResponse

KST = ZoneInfo('Asia/Seoul')
ATTACHMENT_MAX = 5 * 1024 * 1024
ATTACHMENT_ORG_LIMIT = 40 * 1024 * 1024  # Demo-only SQLite quota. Production object storage required.
FILE_MIME = {'.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.webp':'image/webp',
             '.pdf':'application/pdf','.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
             '.docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
             '.txt':'text/plain','.csv':'text/csv'}



class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)


class ConnectBody(Strict):
    recipient_org_id: str = Field(min_length=32, max_length=32, pattern=r'^[a-f0-9]{32}$')


class TextBody(Strict):
    content: str = Field(min_length=1, max_length=2000)
    request_id: str = Field(min_length=16, max_length=64, pattern=r'^[a-fA-F0-9-]+$')


class EditBody(Strict):
    content: str = Field(min_length=1, max_length=2000)
    expected_version: int = Field(ge=1)


class OrderBody(Strict):
    order_id: str = Field(min_length=32, max_length=32, pattern=r'^[a-f0-9]{32}$')
    actor_name: str = Field(min_length=2, max_length=80)
    request_id: str = Field(min_length=16, max_length=64, pattern=r'^[a-fA-F0-9-]+$')


class ReceiptBody(Strict):
    actor_name: str = Field(min_length=2, max_length=80)


class ReadBody(Strict):
    last_message_id: str = Field(min_length=32, max_length=32, pattern=r'^[a-f0-9]{32}$')


def install_schema(c):
    c.executescript('''
    CREATE TABLE IF NOT EXISTS messenger_companies (
      org_id TEXT PRIMARY KEY REFERENCES organizations(id),
      business_number TEXT NOT NULL UNIQUE CHECK(length(business_number)=10 AND business_number NOT GLOB '*[^0-9]*'),
      verified_at TEXT NOT NULL,
      verification_kind TEXT NOT NULL CHECK(verification_kind IN ('demo','operator'))
    );
    CREATE TABLE IF NOT EXISTS messenger_connections (
      id TEXT PRIMARY KEY,
      org_a TEXT NOT NULL REFERENCES organizations(id),
      org_b TEXT NOT NULL REFERENCES organizations(id),
      requester_org TEXT NOT NULL REFERENCES organizations(id),
      status TEXT NOT NULL CHECK(status IN ('pending','active')),
      created_at TEXT NOT NULL, accepted_at TEXT,
      CHECK(org_a < org_b), CHECK(requester_org IN (org_a,org_b)),
      UNIQUE(org_a,org_b)
    );
    CREATE TABLE IF NOT EXISTS messenger_messages (
      id TEXT PRIMARY KEY,
      connection_id TEXT NOT NULL REFERENCES messenger_connections(id),
      sender_org TEXT NOT NULL REFERENCES organizations(id),
      sender_user TEXT NOT NULL REFERENCES users(id),
      kind TEXT NOT NULL CHECK(kind IN ('text','order')),
      body TEXT NOT NULL,
      order_id TEXT REFERENCES orders(id),
      immutable_order_snapshot TEXT,
      actor_name TEXT NOT NULL DEFAULT '',
      request_id TEXT NOT NULL,
      version INTEGER NOT NULL DEFAULT 1 CHECK(version>=1),
      created_at TEXT NOT NULL, edited_at TEXT,
      UNIQUE(sender_org,request_id),
      CHECK ((kind='text' AND order_id IS NULL AND immutable_order_snapshot IS NULL AND actor_name='') OR
             (kind='order' AND order_id IS NOT NULL AND immutable_order_snapshot IS NOT NULL AND length(actor_name)>=2))
    );
    CREATE INDEX IF NOT EXISTS idx_messenger_messages_connection ON messenger_messages(connection_id,created_at,id);
    CREATE TABLE IF NOT EXISTS messenger_edits (
      id TEXT PRIMARY KEY,
      message_id TEXT NOT NULL REFERENCES messenger_messages(id),
      previous_body TEXT NOT NULL,
      new_body TEXT NOT NULL,
      actor_user TEXT NOT NULL REFERENCES users(id),
      edited_at TEXT NOT NULL,
      version INTEGER NOT NULL,
      UNIQUE(message_id,version)
    );
    CREATE TABLE IF NOT EXISTS messenger_attachments (
      message_id TEXT PRIMARY KEY REFERENCES messenger_messages(id),
      filename TEXT NOT NULL,
      mime TEXT NOT NULL,
      data BLOB NOT NULL,
      size_bytes INTEGER NOT NULL CHECK(size_bytes > 0 AND size_bytes <= 5242880),
      content_hash TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS messenger_attachment_no_delete BEFORE DELETE ON messenger_attachments
      BEGIN SELECT RAISE(ABORT,'attachment evidence cannot be deleted'); END;
    CREATE TRIGGER IF NOT EXISTS messenger_attachment_no_update BEFORE UPDATE ON messenger_attachments
      BEGIN SELECT RAISE(ABORT,'attachment evidence cannot be modified'); END;
    CREATE TABLE IF NOT EXISTS messenger_read_positions (
      connection_id TEXT NOT NULL REFERENCES messenger_connections(id),
      org_id TEXT NOT NULL REFERENCES organizations(id),
      last_read_rowid INTEGER NOT NULL DEFAULT 0 CHECK(last_read_rowid >= 0),
      updated_at TEXT NOT NULL,
      PRIMARY KEY(connection_id,org_id)
    );
    CREATE TABLE IF NOT EXISTS messenger_receipts (
      message_id TEXT PRIMARY KEY REFERENCES messenger_messages(id),
      receiver_org TEXT NOT NULL REFERENCES organizations(id),
      actor_name TEXT NOT NULL,
      receiver_user TEXT NOT NULL REFERENCES users(id),
      received_at TEXT NOT NULL
    );
    CREATE TRIGGER IF NOT EXISTS messenger_no_delete BEFORE DELETE ON messenger_messages
      BEGIN SELECT RAISE(ABORT,'message evidence cannot be deleted'); END;
    CREATE TRIGGER IF NOT EXISTS messenger_edit_no_delete BEFORE DELETE ON messenger_edits
      BEGIN SELECT RAISE(ABORT,'edit evidence cannot be deleted'); END;
    CREATE TRIGGER IF NOT EXISTS messenger_edit_no_update BEFORE UPDATE ON messenger_edits
      BEGIN SELECT RAISE(ABORT,'edit evidence cannot be modified'); END;
    CREATE TRIGGER IF NOT EXISTS messenger_no_order_mutation BEFORE UPDATE OF order_id,immutable_order_snapshot,actor_name,kind,sender_org,sender_user,connection_id,created_at,request_id ON messenger_messages
      BEGIN SELECT RAISE(ABORT,'immutable message source cannot be changed'); END;
    ''')
    # TEXT PRIMARY KEY rowids may be reassigned by SQLite VACUUM / dump-restore.
    # Add an immutable, monotonic message sequence without replacing source IDs.
    c.execute('BEGIN IMMEDIATE')
    try:
        conn_cols={r['name'] for r in c.execute('PRAGMA table_info(messenger_connections)')}
        if 'connection_seq' not in conn_cols:
            c.execute('ALTER TABLE messenger_connections ADD COLUMN connection_seq INTEGER')
        max_connection=c.execute('SELECT COALESCE(MAX(connection_seq),0) FROM messenger_connections').fetchone()[0]
        for rec in c.execute('SELECT id FROM messenger_connections WHERE connection_seq IS NULL ORDER BY rowid').fetchall():
            max_connection+=1
            c.execute('UPDATE messenger_connections SET connection_seq=? WHERE id=?',(max_connection,rec['id']))
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_messenger_connection_seq_unique ON messenger_connections(connection_seq)')
        c.execute('''CREATE TRIGGER IF NOT EXISTS messenger_connection_sequence_on_insert
            AFTER INSERT ON messenger_connections WHEN NEW.connection_seq IS NULL
            BEGIN UPDATE messenger_connections
              SET connection_seq=(SELECT COALESCE(MAX(connection_seq),0)+1 FROM messenger_connections)
              WHERE id=NEW.id; END''')
        c.execute('''CREATE TRIGGER IF NOT EXISTS messenger_connection_sequence_immutable
            BEFORE UPDATE OF connection_seq ON messenger_connections WHEN OLD.connection_seq IS NOT NULL
            BEGIN SELECT RAISE(ABORT,'thread sequence cannot be changed'); END''')
        cols={r['name'] for r in c.execute('PRAGMA table_info(messenger_messages)')}
        if 'message_seq' not in cols:
            c.execute('ALTER TABLE messenger_messages ADD COLUMN message_seq INTEGER')
        cols={r['name'] for r in c.execute('PRAGMA table_info(messenger_read_positions)')}
        if 'last_read_seq' not in cols:
            c.execute('ALTER TABLE messenger_read_positions ADD COLUMN last_read_seq INTEGER')
        # Only unsequenced older rows are backfilled, in their original rowid order.
        # Never renumber an already sequenced message on subsequent restarts.
        max_seq=c.execute('SELECT COALESCE(MAX(message_seq),0) FROM messenger_messages').fetchone()[0]
        for rec in c.execute('SELECT id FROM messenger_messages WHERE message_seq IS NULL ORDER BY rowid').fetchall():
            max_seq+=1
            c.execute('UPDATE messenger_messages SET message_seq=? WHERE id=?',(max_seq,rec['id']))
        # Convert old read positions while their historical rowids are still valid.
        # Unknown cursor values fail closed to more unread, never missing unread.
        c.execute('''UPDATE messenger_read_positions
            SET last_read_seq=COALESCE((SELECT message_seq FROM messenger_messages
                WHERE messenger_messages.rowid=messenger_read_positions.last_read_rowid
                  AND messenger_messages.connection_id=messenger_read_positions.connection_id),0)
            WHERE last_read_seq IS NULL''')
        c.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_messenger_message_seq ON messenger_messages(message_seq)')
        c.execute('CREATE INDEX IF NOT EXISTS idx_messenger_connection_seq ON messenger_messages(connection_id,message_seq)')
        # The SQLite writer lock serializes MAX(sequence)+1. An AFTER INSERT trigger
        # also covers the direct SQL legacy paths and fixture-based imports.
        c.execute('''CREATE TRIGGER IF NOT EXISTS messenger_sequence_on_insert AFTER INSERT ON messenger_messages
          WHEN NEW.message_seq IS NULL
          BEGIN
            UPDATE messenger_messages SET message_seq=(SELECT COALESCE(MAX(message_seq),0)+1 FROM messenger_messages)
              WHERE id=NEW.id;
          END''')
        c.execute('''CREATE TRIGGER IF NOT EXISTS messenger_sequence_no_change BEFORE UPDATE OF message_seq ON messenger_messages
          WHEN OLD.message_seq IS NOT NULL
          BEGIN SELECT RAISE(ABORT,'message sequence cannot be changed'); END''')
        c.execute('''CREATE TRIGGER IF NOT EXISTS messenger_sequence_no_null BEFORE UPDATE OF message_seq ON messenger_messages
          WHEN NEW.message_seq IS NULL
          BEGIN SELECT RAISE(ABORT,'message sequence cannot be null'); END''')
        if c.execute('SELECT COUNT(*) FROM messenger_messages WHERE message_seq IS NULL OR message_seq<=0').fetchone()[0]:
            raise RuntimeError('Unsequenced messenger evidence: migration aborted')
        c.execute("UPDATE messenger_connections SET status='active',accepted_at=COALESCE(accepted_at,created_at) WHERE status='pending'")
        c.execute('COMMIT')
    except BaseException:
        if c.in_transaction:c.execute('ROLLBACK')
        raise


def demo_company_profiles(c):
    # Explicitly fictional identifiers; NEVER run for real organization onboarding.
    for email, number in [('demo@hanbit.example','0000000001'),('demo@bada.example','0000000002')]:
        row = c.execute('SELECT org_id FROM users WHERE email=?',(email,)).fetchone()
        if row:
            c.execute('''INSERT OR IGNORE INTO messenger_companies
                        (org_id,business_number,verified_at,verification_kind)
                        VALUES(?,?,?,?)''',(row['org_id'],number,datetime.now(KST).isoformat(),'demo'))


def register_routes(app, *, current_user: Callable, conn: Callable,
                    transaction: Callable, ident: Callable, now: Callable,
                    fail: Callable, need_admin: Callable,
                    detail_doc: Callable):
    """Register routes without circular importing the main authentication module."""

    def message_clock():
        return datetime.now(KST).isoformat(timespec='microseconds')

    def participant(c, connection_id, org, *, active=True):
        row = c.execute('SELECT * FROM messenger_connections WHERE id=? AND (org_a=? OR org_b=?)',
                        (connection_id,org,org)).fetchone()
        if not row:fail('대화를 찾을 수 없습니다',404)
        # A suspended or unverified company must lose messaging access even on
        # previously accepted threads (future revocation is operator controlled).
        if not c.execute('SELECT 1 FROM messenger_companies WHERE org_id=?',(org,)).fetchone():
            fail('기업 메신저 이용 자격이 없습니다',403)
        peer=row['org_b'] if row['org_a']==org else row['org_a']
        if not c.execute('SELECT 1 FROM messenger_companies WHERE org_id=?',(peer,)).fetchone():
            fail('상대 기업의 이용 자격이 정지되었습니다',409)
        if active and row['status']!='active':fail('대화가 활성화되지 않았습니다',409)
        return row

    def company(c,org):
        row=c.execute('''SELECT p.org_id,p.business_number,p.verification_kind,o.name
                         FROM messenger_companies p JOIN organizations o ON o.id=p.org_id
                         WHERE p.org_id=?''',(org,)).fetchone()
        if not row:fail('기업 확인이 완료되지 않아 메신저를 사용할 수 없습니다',403)
        return row

    def display(c,row,org):
        other=row['org_b'] if row['org_a']==org else row['org_a']
        found=c.execute('SELECT name FROM organizations WHERE id=?',(other,)).fetchone()
        return {'id':row['id'],'other_org_id':other,'other_company':found['name'],
                'status':row['status'],'incoming_request':row['requester_org']!=org,
                'created_at':row['created_at'],
                'unread_count':row['unread_count'] if 'unread_count' in row.keys() else 0}

    def message_view(row, org):
        x=dict(row)
        # Sequence is internal ordering evidence, never a public API cursor.
        x.pop('message_seq',None)
        x['company_name']=x.pop('company_name')
        x['mine']=x['sender_org']==org
        # Internal DB IDs are opaque; original line items included only in order snapshot.
        x['order_snapshot']=json.loads(x.pop('immutable_order_snapshot')) if x['kind']=='order' else None
        x['attachment']=({'filename':x.pop('attachment_name'),'mime':x.pop('attachment_mime'),
                          'size_bytes':x.pop('attachment_size'),'url':'/api/messenger/messages/'+x['id']+'/attachment'}
                          if x.get('attachment_name') is not None else None)
        for k in ('attachment_name','attachment_mime','attachment_size'):x.pop(k,None)
        return x

    @app.get('/api/messenger/directory')
    def directory(user=Depends(current_user)):
        with conn() as c:
            company(c,user['org_id'])
            return [dict(r) for r in c.execute('''SELECT p.org_id,o.name AS company_name
                        FROM messenger_companies p JOIN organizations o ON o.id=p.org_id
                        WHERE p.org_id != ? ORDER BY o.name LIMIT 200''',(user['org_id'],))]

    @app.get('/api/messenger/directory/search')
    def directory_search(q:str=Query('',max_length=80),offset:int=Query(0,ge=0,le=1000000),
                         limit:int=Query(30,ge=1,le=50),user=Depends(current_user)):
        # Server-side search + pagination: no 200-company client-side cap.
        with conn() as c:
            company(c,user['org_id'])
            term=q.strip()
            like='%' + term.replace('\\','\\\\').replace('%','\\%').replace('_','\\_') + '%'
            rows=c.execute('''SELECT p.org_id,o.name AS company_name FROM messenger_companies p
                       JOIN organizations o ON o.id=p.org_id WHERE p.org_id != ?
                       AND o.name LIKE ? ESCAPE '\\' ORDER BY o.name,p.org_id LIMIT ? OFFSET ?''',
                       (user['org_id'],like,limit+1,offset)).fetchall()
            return {'items':[dict(x) for x in rows[:limit]],'next_offset':offset+limit if len(rows)>limit else None}

    @app.get('/api/messenger/threads')
    def threads(user=Depends(current_user)):
        with conn() as c:
            company(c,user['org_id'])
            # Cursor is scoped to the authenticated company; outgoing messages never count as unread.
            # Sort by latest activity so long-lived partner threads return to the top.
            sql='''SELECT t.*,
                (SELECT COUNT(*) FROM messenger_messages m WHERE m.connection_id=t.id
                 AND m.sender_org!=? AND m.message_seq>COALESCE(
                    (SELECT r.last_read_seq FROM messenger_read_positions r
                     WHERE r.connection_id=t.id AND r.org_id=?),0)) AS unread_count
                 FROM messenger_connections t WHERE t.org_a=? OR t.org_b=?
                 ORDER BY COALESCE((SELECT MAX(m.created_at) FROM messenger_messages m
                     WHERE m.connection_id=t.id),t.created_at) DESC,
                     t.connection_seq DESC LIMIT 200'''
            return [display(c,r,user['org_id']) for r in c.execute(
                sql,(user['org_id'],user['org_id'],user['org_id'],user['org_id']))]

    @app.post('/api/messenger/threads',status_code=201)
    def connect(body:ConnectBody,user=Depends(current_user)):
        with transaction() as c:
            company(c,user['org_id']);company(c,body.recipient_org_id)
            if body.recipient_org_id==user['org_id']:fail('같은 기업과 대화할 수 없습니다',409)
            a,b=sorted([user['org_id'],body.recipient_org_id])
            prev=c.execute('SELECT * FROM messenger_connections WHERE org_a=? AND org_b=?',(a,b)).fetchone()
            if prev:
                if prev['status']=='pending':
                    c.execute("UPDATE messenger_connections SET status='active', accepted_at=? WHERE id=?",(now(),prev['id']))
                return display(c,c.execute('SELECT * FROM messenger_connections WHERE id=?',(prev['id'],)).fetchone(),user['org_id'])
            key=ident()
            c.execute('''INSERT INTO messenger_connections
                         (id,org_a,org_b,requester_org,status,created_at,accepted_at) VALUES(?,?,?,?,'active',?,?)''',
                         (key,a,b,user['org_id'],message_clock(),message_clock()))
            return display(c,c.execute('SELECT * FROM messenger_connections WHERE id=?',(key,)).fetchone(),user['org_id'])

    @app.post('/api/messenger/threads/{connection_id}/accept')
    def accept_legacy(connection_id:str,user=Depends(current_user)):
        # Backwards-compatible old client; approval is no longer required.
        with conn() as c:
            company(c,user['org_id'])
            row=participant(c,connection_id,user['org_id'])
            return display(c,row,user['org_id'])

    @app.get('/api/messenger/threads/{connection_id}/messages')
    def list_messages(connection_id:str,user=Depends(current_user)):
        with conn() as c:
            participant(c,connection_id,user['org_id'])
            rows=c.execute('''SELECT m.*,o.name AS company_name,r.received_at,r.actor_name AS receipt_actor_name,
                        a.filename AS attachment_name,a.mime AS attachment_mime,a.size_bytes AS attachment_size FROM messenger_messages m
                        JOIN organizations o ON o.id=m.sender_org
                        LEFT JOIN messenger_receipts r ON r.message_id=m.id
                        LEFT JOIN messenger_attachments a ON a.message_id=m.id
                        WHERE m.connection_id=? ORDER BY m.message_seq DESC LIMIT 100''',(connection_id,)).fetchall()
            return [message_view(r,user['org_id']) for r in reversed(rows)]

    @app.get('/api/messenger/threads/{connection_id}/messages/page')
    def paged_messages(connection_id:str, before:str|None=Query(None,pattern=r'^[a-f0-9]{32}$'),
                       after:str|None=Query(None,pattern=r'^[a-f0-9]{32}$'),
                       limit:int=Query(50,ge=1,le=100), user=Depends(current_user)):
        """Stable immutable-sequence cursor paging. Cursor is scoped to this thread.

        `before` loads older history descending from a known message;
        `after` loads newer messages ascending without skipping gaps. The response
        never contains internal database sequences or messages from other tenants.
        """
        if before and after:fail('이전과 이후 커서를 동시에 지정할 수 없습니다',422)
        with conn() as c:
            participant(c,connection_id,user['org_id'])
            cursor=before or after
            last_id=None
            if cursor:
                last=c.execute('SELECT message_seq FROM messenger_messages WHERE id=? AND connection_id=?',
                               (cursor,connection_id)).fetchone()
                if not last:fail('이 대화에 속한 커서가 아닙니다',404)
                last_id=last['message_seq']
            filt=' AND m.message_seq < ?' if before else (' AND m.message_seq > ?' if after else '')
            direction='ASC' if after else 'DESC'
            rows=c.execute("""SELECT m.*,o.name AS company_name,r.received_at,r.actor_name AS receipt_actor_name,
                         a.filename AS attachment_name,a.mime AS attachment_mime,a.size_bytes AS attachment_size
                         FROM messenger_messages m JOIN organizations o ON o.id=m.sender_org
                         LEFT JOIN messenger_receipts r ON r.message_id=m.id
                         LEFT JOIN messenger_attachments a ON a.message_id=m.id
                         WHERE m.connection_id=?""" +filt+
                         ' ORDER BY m.message_seq '+direction+' LIMIT ?',
                         (connection_id,last_id,limit+1) if cursor else (connection_id,limit+1)).fetchall()
            has_more=len(rows)>limit
            items=[message_view(r,user['org_id']) for r in (rows[:limit] if after else reversed(rows[:limit]))]
            return {'items':items,'has_more':has_more,
                    'next_before':items[0]['id'] if has_more and not after and items else None,
                    'next_after':items[-1]['id'] if has_more and after and items else None}

    @app.get('/api/messenger/threads/{connection_id}/events')
    async def message_events(connection_id:str,request:Request,user=Depends(current_user)):
        """Server-Sent Events with cross-worker-safe DB change detection (demo scale).

        Only emits a change signal; message data is fetched via authorized APIs.
        Ordinary polling remains the client fallback, even when SSE is disabled.
        """
        with conn() as c:
            participant(c,connection_id,user['org_id'])
        org=user['org_id']
        def version(c):
            return tuple(c.execute("""SELECT
                 (SELECT COALESCE(MAX(message_seq),0) FROM messenger_messages WHERE connection_id=?),
                 (SELECT COALESCE(MAX(e.rowid),0) FROM messenger_edits e JOIN messenger_messages m ON m.id=e.message_id WHERE m.connection_id=?),
                 (SELECT COALESCE(MAX(r.rowid),0) FROM messenger_receipts r JOIN messenger_messages m ON m.id=r.message_id WHERE m.connection_id=?)""",
                 (connection_id,connection_id,connection_id)).fetchone())
        async def events():
            last=None
            for n in range(100):  # bounded connections, normal EventSource reconnect
                if await request.is_disconnected():return
                try:
                    # Dependency injection authenticates stream setup; a live stream
                    # must ALSO stop when its cookie session expires or is revoked.
                    identity=current_user(request)
                    if identity['id']!=user['id'] or identity['org_id']!=org:
                        fail('메신저 세션이 변경되었습니다',401)
                    with conn() as c:
                        participant(c,connection_id,org)
                        current=version(c)
                except Exception:
                    yield 'event: revoked\ndata: {}\n\n'
                    return
                if last is None:
                    last=current
                    yield 'event: ready\ndata: {}\n\n'
                elif last!=current:
                    last=current
                    yield 'event: change\ndata: {}\n\n'
                elif n%15==0:
                    yield ': heartbeat\n\n'
                await asyncio.sleep(1)
        return StreamingResponse(events(),media_type='text/event-stream',headers={
            'Cache-Control':'no-cache, no-store','X-Accel-Buffering':'no',
            'X-Content-Type-Options':'nosniff'})

    @app.post('/api/messenger/threads/{connection_id}/read')
    def read_messages(connection_id:str,body:ReadBody,user=Depends(current_user)):
        # This never mutates or deletes message evidence: only an org-scoped view cursor.
        with transaction() as c:
            participant(c,connection_id,user['org_id'])
            last=c.execute('''SELECT message_seq FROM messenger_messages
                   WHERE id=? AND connection_id=?''',(body.last_message_id,connection_id)).fetchone()
            if not last:fail('이 대화에 속한 메시지가 아닙니다',404)
            c.execute('''INSERT INTO messenger_read_positions
                    (connection_id,org_id,last_read_rowid,last_read_seq,updated_at) VALUES(?,?,0,?,?)
                    ON CONFLICT(connection_id,org_id) DO UPDATE SET
                    last_read_seq=MAX(COALESCE(messenger_read_positions.last_read_seq,0),excluded.last_read_seq),
                    updated_at=excluded.updated_at''',
                    (connection_id,user['org_id'],last['message_seq'],now()))
            return {'status':'read'}

    @app.post('/api/messenger/threads/{connection_id}/messages',status_code=201)
    def send_text(connection_id:str,body:TextBody,user=Depends(current_user)):
        if not body.content.strip():fail('내용을 입력하세요')
        with transaction() as c:
            company(c,user['org_id']);participant(c,connection_id,user['org_id'])
            prev=c.execute('SELECT * FROM messenger_messages WHERE sender_org=? AND request_id=?',
                           (user['org_id'],body.request_id)).fetchone()
            if prev:
                if prev['connection_id']!=connection_id or prev['kind']!='text' or prev['body']!=body.content:
                    fail('중복 요청 번호가 다른 메시지에 사용되었습니다',409)
                return {'id':prev['id'],'version':prev['version']}
            # Basic per-user flood control; retains all evidence.
            cutoff=(datetime.now(KST)-timedelta(minutes=1)).isoformat()
            count=c.execute('SELECT COUNT(*) FROM messenger_messages WHERE sender_user=? AND created_at>=?',
                            (user['id'],cutoff)).fetchone()[0]
            if count>=20:fail('잠시 후 메시지를 다시 보내세요',429)
            key=ident()
            c.execute('''INSERT INTO messenger_messages
                        (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
                        VALUES(?,?,?,?,'text',?,?,?)''',
                        (key,connection_id,user['org_id'],user['id'],body.content,body.request_id,message_clock()))
            return {'id':key,'version':1}

    @app.post('/api/messenger/threads/{connection_id}/attachments',status_code=201)
    async def send_attachment(connection_id:str, file:UploadFile=File(...),
                              request_id:str=Form(...,min_length=16,max_length=64),
                              user=Depends(current_user)):
        if not re.fullmatch(r'[a-fA-F0-9-]{16,64}',request_id):fail('요청 번호가 올바르지 않습니다')
        raw_name=(file.filename or '').replace('\\','/').split('/')[-1].strip()
        if not raw_name or len(raw_name)>120 or any(ord(ch)<32 for ch in raw_name):
            fail('파일 이름이 올바르지 않습니다')
        ext=PurePath(raw_name).suffix.lower()
        if ext not in FILE_MIME:fail('지원하지 않는 파일 형식입니다',415)
        # No automatic execution, extraction, or document approval. Files are evidence only.
        contents=await file.read(ATTACHMENT_MAX+1)
        if len(contents)>ATTACHMENT_MAX:fail('첨부파일은 5MB 이하만 가능합니다',413)
        if not contents:fail('빈 파일을 전송할 수 없습니다')
        if ext=='.png' and not (contents.startswith(b'\x89PNG\r\n\x1a\n') and contents[12:16]==b'IHDR'):
            fail('이미지 형식이 잘못됐습니다',415)
        if ext in ('.jpg','.jpeg') and not (contents.startswith(b'\xff\xd8\xff') and contents.endswith(b'\xff\xd9')):
            fail('이미지 형식이 잘못됐습니다',415)
        if ext=='.webp' and not (contents[:4]==b'RIFF' and contents[8:12]==b'WEBP'):
            fail('이미지 형식이 잘못됐습니다',415)
        if ext=='.pdf' and not contents.startswith(b'%PDF-'):
            fail('PDF 형식이 잘못됐습니다',415)
        if ext in ('.xlsx','.docx'):
            try:
                with zipfile.ZipFile(io.BytesIO(contents)) as z:
                    names=set(z.namelist())
                    if '[Content_Types].xml' not in names or (ext=='.xlsx' and 'xl/workbook.xml' not in names) or (ext=='.docx' and 'word/document.xml' not in names):
                        fail('문서 형식이 잘못됐습니다',415)
                    if any('/' not in n and n.lower().endswith(('.exe','.js','.vbs')) or 'vbaproject.bin' in n.lower() for n in names):
                        fail('실행 가능한 첨부 요소가 있습니다',415)
            except (zipfile.BadZipFile, OSError, ValueError):fail('압축 문서를 열 수 없습니다',415)
        if ext in ('.txt','.csv'):
            try: contents.decode('utf-8-sig')
            except UnicodeDecodeError:fail('UTF-8 텍스트 파일만 지원합니다',415)
        digest=hashlib.sha256(contents).hexdigest()
        with transaction() as c:
            company(c,user['org_id']);participant(c,connection_id,user['org_id'])
            old=c.execute('''SELECT m.id,m.connection_id,a.content_hash,a.filename
                             FROM messenger_messages m JOIN messenger_attachments a ON a.message_id=m.id
                             WHERE m.sender_org=? AND m.request_id=?''',(user['org_id'],request_id)).fetchone()
            if old:
                if old['connection_id']!=connection_id or old['content_hash']!=digest or old['filename']!=raw_name:
                    fail('중복 요청 번호가 다른 파일에 사용되었습니다',409)
                return {'id':old['id'],'duplicate':True}
            clash=c.execute('SELECT 1 FROM messenger_messages WHERE sender_org=? AND request_id=?',
                            (user['org_id'],request_id)).fetchone()
            if clash:fail('다른 메시지의 요청 번호입니다',409)
            consumed=c.execute('''SELECT COALESCE(SUM(a.size_bytes),0) FROM messenger_attachments a
                         JOIN messenger_messages m ON m.id=a.message_id WHERE m.sender_org=?''',
                         (user['org_id'],)).fetchone()[0]
            if consumed+len(contents)>ATTACHMENT_ORG_LIMIT:fail('기업별 임시 첨부 저장 한도를 초과했습니다',413)
            cutoff=(datetime.now(KST)-timedelta(minutes=1)).isoformat()
            if c.execute('SELECT COUNT(*) FROM messenger_messages WHERE sender_user=? AND created_at>=?',
                         (user['id'],cutoff)).fetchone()[0]>=20:
                fail('잠시 후 다시 전송하세요',429)
            mid=ident()
            c.execute('''INSERT INTO messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
                VALUES(?,?,?,?,'text',?,?,?)''',
                (mid,connection_id,user['org_id'],user['id'],'첨부파일: '+raw_name,request_id,message_clock()))
            c.execute('''INSERT INTO messenger_attachments(message_id,filename,mime,data,size_bytes,content_hash)
                VALUES(?,?,?,?,?,?)''',(mid,raw_name,FILE_MIME[ext],contents,len(contents),digest))
            return {'id':mid,'duplicate':False}

    @app.get('/api/messenger/messages/{message_id}/attachment')
    def download_attachment(message_id:str,user=Depends(current_user)):
        with conn() as c:
            row=c.execute('''SELECT a.*,m.connection_id FROM messenger_attachments a
                       JOIN messenger_messages m ON m.id=a.message_id WHERE a.message_id=?''',(message_id,)).fetchone()
            if not row:fail('첨부파일을 찾을 수 없습니다',404)
            participant(c,row['connection_id'],user['org_id'])
            # Safe download; do not interpret active documents as browser HTML.
            mime=row['mime'] if row['mime'].startswith('image/') else 'application/octet-stream'
            # Filename sent in URL encoded UTF-8 for standards-compliant clients.
            from urllib.parse import quote
            dispo='inline' if mime.startswith('image/') else 'attachment'
            return Response(content=row['data'],media_type=mime,headers={
               'Content-Disposition':f"{dispo}; filename*=UTF-8''{quote(row['filename'],safe='')}",
               'Cache-Control':'no-store','X-Content-Type-Options':'nosniff',
               'Content-Security-Policy':"default-src 'none'; sandbox"})

    @app.patch('/api/messenger/messages/{message_id}')
    def edit_text(message_id:str,body:EditBody,user=Depends(current_user)):
        if not body.content.strip():fail('내용을 입력하세요')
        with transaction() as c:
            row=c.execute('SELECT * FROM messenger_messages WHERE id=? AND sender_org=? AND sender_user=?',
                          (message_id,user['org_id'],user['id'])).fetchone()
            if not row:fail('수정할 메시지가 없습니다',404)
            participant(c,row['connection_id'],user['org_id'])
            if row['kind']!='text' or c.execute('SELECT 1 FROM messenger_attachments WHERE message_id=?',(message_id,)).fetchone():
                fail('첨부파일 또는 거래 증빙 메시지는 수정할 수 없습니다',409)
            if datetime.now(KST) >= datetime.fromisoformat(row['created_at'])+timedelta(minutes=30):
                fail('발송 후 30분이 지나 수정할 수 없습니다',409)
            if row['version']!=body.expected_version:fail('다른 수정본이 존재합니다. 새로고침하세요',409)
            if row['body']==body.content:fail('변경 내용이 없습니다',409)
            ver=row['version']+1
            c.execute('''INSERT INTO messenger_edits
                         (id,message_id,previous_body,new_body,actor_user,edited_at,version)
                         VALUES(?,?,?,?,?,?,?)''',
                      (ident(),message_id,row['body'],body.content,user['id'],now(),ver))
            c.execute('UPDATE messenger_messages SET body=?,version=?,edited_at=? WHERE id=?',
                      (body.content,ver,now(),message_id))
            return {'id':message_id,'version':ver}

    @app.get('/api/messenger/messages/{message_id}/history')
    def edits(message_id:str,user=Depends(current_user)):
        with conn() as c:
            row=c.execute('SELECT * FROM messenger_messages WHERE id=?',(message_id,)).fetchone()
            if not row:fail('메시지를 찾을 수 없습니다',404)
            participant(c,row['connection_id'],user['org_id'])
            return [dict(r) for r in c.execute('''SELECT version,previous_body,new_body,edited_at
                          FROM messenger_edits WHERE message_id=? ORDER BY version''',(message_id,))]

    @app.post('/api/messenger/threads/{connection_id}/orders',status_code=201)
    def send_order(connection_id:str,body:OrderBody,user=Depends(current_user)):
        with transaction() as c:
            company(c,user['org_id'])
            thread=participant(c,connection_id,user['org_id'])
            recipient=thread['org_b'] if thread['org_a']==user['org_id'] else thread['org_a']
            receiver=company(c,recipient)
            prev=c.execute('SELECT * FROM messenger_messages WHERE sender_org=? AND request_id=?',
                           (user['org_id'],body.request_id)).fetchone()
            if prev:
                if prev['connection_id']!=connection_id or prev['kind']!='order' or prev['order_id']!=body.order_id or prev['actor_name']!=body.actor_name:
                    fail('요청 번호가 다른 거래에 사용되었습니다',409)
                return {'id':prev['id'],'version':1}
            order=c.execute('''SELECT o.*,cu.business_number FROM orders o
                  JOIN customers cu ON cu.id=o.customer_id AND cu.org_id=o.org_id
                  WHERE o.id=? AND o.org_id=?''',(body.order_id,user['org_id'])).fetchone()
            if not order:fail('해당 기업의 발주서가 없습니다',404)
            # Never send an order to a company other than the legal target in the order.
            if not order['business_number'] or order['business_number']!=receiver['business_number']:
                fail('발주서의 거래처 사업자번호와 수신 회사가 일치하지 않습니다',409)
            if order['status']=='cancelled' or order['review_state']=='pending':
                fail('취소되거나 변경 검토 중인 발주서는 전송할 수 없습니다',409)
            detail=detail_doc(c,'order',dict(order))
            snapshot={'document_type':'purchase_order','source_order_id':body.order_id,
                      'doc_no':detail['doc_no'],'customer_name':detail['customer_name_snapshot'],
                      'vat_mode':detail['vat_mode'],'due_date':detail['due_date'],
                      'items':[{'name':x['name'],'quantity':x['quantity'],'unit_price':x['unit_price']} for x in detail['items']],
                      'money':detail['money'],'source_status':detail['status'],
                      'notice':'This is an immutable transmitted snapshot, not receiver acceptance.'}
            key=ident()
            c.execute('''INSERT INTO messenger_messages
                  (id,connection_id,sender_org,sender_user,kind,body,order_id,immutable_order_snapshot,
                   actor_name,request_id,created_at) VALUES(?,?,?,?,'order',?,?,?,?,?,?)''',
                  (key,connection_id,user['org_id'],user['id'],f'발주서 {detail["doc_no"]} 전달',body.order_id,
                   json.dumps(snapshot,ensure_ascii=False,sort_keys=True),body.actor_name,body.request_id,message_clock()))
            return {'id':key,'version':1,'order_snapshot':snapshot}

    @app.post('/api/messenger/messages/{message_id}/receipt')
    def acknowledge_document(message_id:str,body:ReceiptBody,user=Depends(current_user)):
        # Receipt is not acceptance, commercial approval, invoice or payment.
        with transaction() as c:
            msg=c.execute('SELECT * FROM messenger_messages WHERE id=?',(message_id,)).fetchone()
            if not msg:fail('문서를 찾을 수 없습니다',404)
            thread=participant(c,msg['connection_id'],user['org_id'])
            if msg['kind']!='order' or msg['sender_org']==user['org_id']:
                fail('수신 기업의 발주서만 확인할 수 있습니다',403)
            prior=c.execute('SELECT * FROM messenger_receipts WHERE message_id=?',(message_id,)).fetchone()
            if prior:
                if prior['receiver_org']!=user['org_id']:fail('다른 기업의 수신 정보입니다',403)
                return {'status':'received','received_at':prior['received_at'],'actor_name':prior['actor_name']}
            c.execute('''INSERT INTO messenger_receipts(message_id,receiver_org,actor_name,receiver_user,received_at)
                         VALUES(?,?,?,?,?)''',(message_id,user['org_id'],body.actor_name,user['id'],now()))
            return {'status':'received','received_at':now(),'actor_name':body.actor_name}
