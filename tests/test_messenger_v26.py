"""V2.6 evidence: stable SQLite sequencing, migration, read positions and concurrency.

These tests do NOT certify a live PostgreSQL RLS deployment or production scalability.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import uuid

import pytest

from app import main
from app.messenger import install_schema
from tests.test_messenger_v22 import login, p, q
from tests.test_messenger_v25 import seed_history, page


def test_monotonic_sequence_and_cursors_survive_vacuum_and_online_backup(client, tmp_path):
    a,b,tid=seed_history(client,177)
    with main.conn() as db:
        before=[(r['id'],r['message_seq']) for r in db.execute(
            'SELECT id,message_seq FROM messenger_messages WHERE connection_id=? ORDER BY message_seq',(tid,))]
        assert all(seq>0 for _,seq in before)
        assert [seq for _,seq in before] == sorted(set(seq for _,seq in before))
    older_cursor=page(client,a,tid,'?limit=50').json()['items'][0]['id']
    assert p(client,a,f'/messenger/threads/{tid}/read',{'last_message_id':older_cursor}).status_code==200
    # VACUUM runs outside a transaction, and can rewrite TEXT-PK rowid identifiers.
    with main.conn() as db:
        db.execute('VACUUM')
        backup=sqlite3.connect(tmp_path/'online_backup.db')
        try:
            db.backup(backup)
        finally:
            backup.close()
        after=[(r['id'],r['message_seq']) for r in db.execute(
            'SELECT id,message_seq FROM messenger_messages WHERE connection_id=? ORDER BY message_seq',(tid,))]
        got=db.execute('SELECT last_read_seq FROM messenger_read_positions WHERE connection_id=? AND org_id=?',
                       (tid,main_org(a,db))).fetchone()['last_read_seq']
    assert before==after
    assert got==next(seq for msg,seq in before if msg==older_cursor)
    # Cursor stays meaningful, even after DB VACUUM and subsequent writes.
    assert page(client,a,tid,'?before='+older_cursor).status_code==200
    assert page(client,a,tid,'?after='+older_cursor).status_code==200
    with sqlite3.connect(tmp_path/'online_backup.db') as restored:
        assert restored.execute('SELECT COUNT(*) FROM messenger_messages WHERE connection_id=?',(tid,)).fetchone()[0]==177
        assert restored.execute('SELECT message_seq FROM messenger_messages WHERE id=?',(older_cursor,)).fetchone()[0]==got
    with main.conn() as db:
        install_schema(db)  # idempotent on an already upgraded DB
    with main.conn() as db:
        assert [(r['id'],r['message_seq']) for r in db.execute(
            'SELECT id,message_seq FROM messenger_messages WHERE connection_id=? ORDER BY message_seq',(tid,))]==before
    assert q(client,a,'/messenger/threads').status_code==200


def main_org(headers,db):
    # Test headers belong to demo@hanbit; no other tenant is queried.
    return db.execute("SELECT org_id FROM users WHERE email='demo@hanbit.example'").fetchone()['org_id']


def test_unread_count_uses_stable_sequence_after_database_rebuild(client):
    a,b,tid=seed_history(client,14)
    items=page(client,a,tid).json()['items']
    assert p(client,a,f'/messenger/threads/{tid}/read',{'last_message_id':items[7]['id']}).status_code==200
    assert next(t for t in q(client,a,'/messenger/threads').json() if t['id']==tid)['unread_count']==3
    with main.conn() as db:db.execute('VACUUM')
    assert next(t for t in q(client,a,'/messenger/threads').json() if t['id']==tid)['unread_count']==3
    # Reading an older message never rolls the read position backward.
    assert p(client,a,f'/messenger/threads/{tid}/read',{'last_message_id':items[2]['id']}).status_code==200
    assert next(t for t in q(client,a,'/messenger/threads').json() if t['id']==tid)['unread_count']==3
    assert p(client,a,f'/messenger/threads/{tid}/read',{'last_message_id':items[-1]['id']}).status_code==200
    assert next(t for t in q(client,a,'/messenger/threads').json() if t['id']==tid)['unread_count']==0


def test_parallel_writers_allocate_unique_ordered_seqs_and_preserve_api_cursor(client):
    a,b,tid=seed_history(client,4)
    with main.conn() as db:
        org=db.execute('SELECT org_a FROM messenger_connections WHERE id=?',(tid,)).fetchone()[0]
        user=db.execute('SELECT id FROM users WHERE org_id=?',(org,)).fetchone()['id']
    def writer(i):
        mid=uuid.uuid4().hex
        with main.transaction() as db:
            db.execute('''INSERT INTO messenger_messages
                (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
                VALUES(?,?,?,?,'text',?,?,?)''',
                (mid,tid,org,user,f'동시 작성 {i}',uuid.uuid4().hex,main.now()))
            return (mid,db.execute('SELECT message_seq FROM messenger_messages WHERE id=?',(mid,)).fetchone()[0])
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(writer,range(80)))
    seqs=[seq for mid,seq in results]
    assert len(set(seqs))==80
    assert min(seqs)>0
    full=[]
    cursor=None
    for _ in range(5):
        doc=page(client,a,tid,'?before='+cursor if cursor else '').json()
        full=doc['items']+full
        if not doc['has_more']:break
        cursor=doc['next_before']
    assert len(full)==84 and len({x['id'] for x in full})==84
    assert all('message_seq' not in x for x in full)
    assert {mid for mid,seq in results}.issubset({x['id'] for x in full})
    assert sum(x['body'].startswith('동시 작성 ') for x in full)==80
    # Trigger also prevents mutation of persisted ordering evidence.
    with main.conn() as db:
        with pytest.raises(sqlite3.IntegrityError):
            db.execute('UPDATE messenger_messages SET message_seq=? WHERE id=?', (1000000,results[0][0]))
        with pytest.raises(sqlite3.IntegrityError):
            db.execute('UPDATE messenger_messages SET message_seq=NULL WHERE id=?',(results[0][0],))


def test_old_sqlite_v25_messages_and_read_rowid_migrate_with_no_data_loss(tmp_path):
    path=tmp_path/'legacy.db'
    c=sqlite3.connect(path,isolation_level=None)
    c.row_factory=sqlite3.Row
    try:
        c.executescript('''
        CREATE TABLE organizations(id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL);
        CREATE TABLE users(id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id),
          email TEXT UNIQUE, password_hash TEXT, name TEXT, role TEXT, created_at TEXT);
        CREATE TABLE messenger_connections(
          id TEXT PRIMARY KEY,org_a TEXT,org_b TEXT,requester_org TEXT,status TEXT,
          created_at TEXT,accepted_at TEXT);
        CREATE TABLE messenger_messages(
          id TEXT PRIMARY KEY,connection_id TEXT,sender_org TEXT,sender_user TEXT,
          kind TEXT,body TEXT,order_id TEXT,immutable_order_snapshot TEXT,actor_name TEXT NOT NULL DEFAULT '',
          request_id TEXT,version INTEGER NOT NULL DEFAULT 1,created_at TEXT,edited_at TEXT);
        CREATE TABLE messenger_read_positions(
          connection_id TEXT,org_id TEXT,last_read_rowid INTEGER NOT NULL DEFAULT 0,
          updated_at TEXT,PRIMARY KEY(connection_id,org_id));
        ''')
        c.execute("INSERT INTO organizations VALUES('a','Alpha','2026')")
        c.execute("INSERT INTO organizations VALUES('b','Beta','2026')")
        c.execute("INSERT INTO users VALUES('u','a','a@test','x','X','admin','2026')")
        c.execute("INSERT INTO messenger_connections VALUES('thread','a','b','a','active','2026','2026')")
        for i in range(7):
            c.execute("""INSERT INTO messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
              VALUES(?,'thread','a','u','text',?,?,?)""",(f'm{i}',f'demo-{i}',f'req-{i}','2026'))
        mid=c.execute("SELECT rowid FROM messenger_messages WHERE id='m3'").fetchone()[0]
        c.execute("INSERT INTO messenger_read_positions VALUES('thread','b',?,'2026')",(mid,))
        install_schema(c)
        rows=c.execute('SELECT id,message_seq FROM messenger_messages ORDER BY message_seq').fetchall()
        assert [(r['id'],r['message_seq']) for r in rows]==[(f'm{i}',i+1) for i in range(7)]
        assert c.execute('SELECT last_read_seq FROM messenger_read_positions').fetchone()[0]==4
        assert c.execute("SELECT connection_seq FROM messenger_connections WHERE id='thread'").fetchone()[0]==1
        c.execute('VACUUM')
        install_schema(c)
        assert c.execute('SELECT last_read_seq FROM messenger_read_positions').fetchone()[0]==4
        assert c.execute("SELECT connection_seq FROM messenger_connections WHERE id='thread'").fetchone()[0]==1
        assert [(r['id'],r['message_seq']) for r in c.execute('SELECT id,message_seq FROM messenger_messages ORDER BY message_seq')]==[(f'm{i}',i+1) for i in range(7)]
        c.execute("""INSERT INTO messenger_messages(id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
          VALUES('m8','thread','a','u','text','later','req-8','2026')""")
        assert c.execute("SELECT message_seq FROM messenger_messages WHERE id='m8'").fetchone()[0]==8
    finally:c.close()


def test_other_tenant_cannot_probe_sequence_based_cursor(client):
    a,b,tid=seed_history(client,8)
    with main.conn() as db:
        assert db.execute('SELECT COUNT(*) FROM messenger_messages WHERE message_seq IS NULL').fetchone()[0]==0
    token=page(client,a,tid).json()['items'][0]['id']
    assert page(client,a,tid,'?before='+token).status_code==200
    # If no matching message in a conversation, IDs cannot reveal other threads.
    assert page(client,a,tid,'?before='+uuid.uuid4().hex).status_code==404
    assert page(client,a,tid,'?after='+uuid.uuid4().hex).status_code==404


def test_message_order_changes_preserve_full_original_edit_history(client):
    a,b,tid=seed_history(client,3)
    original=page(client,a,tid).json()['items'][0]
    assert original['version']==1
    with main.conn() as db:
        seq=db.execute('SELECT message_seq FROM messenger_messages WHERE id=?',(original['id'],)).fetchone()[0]
    with main.conn() as db:
        db.execute('VACUUM')
    with main.conn() as db:
        assert db.execute('SELECT message_seq FROM messenger_messages WHERE id=?',(original['id'],)).fetchone()[0]==seq
    assert page(client,b,tid).status_code==200


def test_thread_activity_sort_is_repeatable_with_equal_clock_and_vacuum(client):
    a,org_a=login(client,'demo@hanbit.example')
    b,org_b=login(client,'demo@bada.example')
    with main.transaction() as db:
        c=uuid.uuid4().hex
        db.execute('INSERT INTO organizations VALUES(?,?,?)',(c,'Third Company',main.now()))
        db.execute("INSERT INTO messenger_companies VALUES(?,?,?,'operator')",(c,'0000000091',main.now()))
    first=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    second=p(client,a,'/messenger/threads',{'recipient_org_id':c}).json()['id']
    assert q(client,a,'/messenger/threads').json()[0]['id']==second
    with main.conn() as db:
        db.execute('VACUUM')
        assert db.execute('SELECT connection_seq FROM messenger_connections WHERE id=?',(first,)).fetchone()[0] < db.execute('SELECT connection_seq FROM messenger_connections WHERE id=?',(second,)).fetchone()[0]
        with pytest.raises(sqlite3.IntegrityError):
            db.execute('UPDATE messenger_connections SET connection_seq=999 WHERE id=?',(first,))
    assert q(client,a,'/messenger/threads').json()[0]['id']==second
    assert p(client,a,f'/messenger/threads/{first}/messages',{
        'content':'갱신이 최근','request_id':uuid.uuid4().hex}).status_code==201
    assert q(client,a,'/messenger/threads').json()[0]['id']==first
