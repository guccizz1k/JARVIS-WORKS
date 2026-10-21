"""Real app.messenger FastAPI route integration (requires full checked-out repo).

These tests intentionally do NOT skip when repository/HTTP modules are missing.
"""
from contextlib import contextmanager
from pathlib import Path
import sqlite3

import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app.messenger import install_schema, register_routes

A = 'a' * 32
B = 'b' * 32
C = 'c' * 32
THREAD = 'd' * 32
M1 = '1' * 32
M2 = '2' * 32


@pytest.fixture
def site(tmp_path):
    db = tmp_path / 'web-read-actor.db'

    @contextmanager
    def conn():
        c = sqlite3.connect(db, isolation_level=None)
        c.row_factory=sqlite3.Row
        c.execute('PRAGMA foreign_keys=ON')
        try:
            yield c
        finally:
            c.close()

    @contextmanager
    def transaction():
        with conn() as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                yield c
                c.execute('COMMIT')
            except BaseException:
                c.execute('ROLLBACK')
                raise

    with conn() as c:
        c.executescript('''
            CREATE TABLE organizations (id TEXT PRIMARY KEY, name TEXT NOT NULL);
            CREATE TABLE users (id TEXT PRIMARY KEY, org_id TEXT REFERENCES organizations(id));
            CREATE TABLE orders (id TEXT PRIMARY KEY);
            INSERT INTO organizations VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','Org A'),
              ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','Org B'),
              ('cccccccccccccccccccccccccccccccc','Org C');
            INSERT INTO users VALUES ('u1','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
              ('u2','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
              ('ub','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'),
              ('uc','cccccccccccccccccccccccccccccccc');
        ''')
        install_schema(c)
        c.execute("INSERT INTO messenger_companies VALUES (?, '0000000001','2026-10-21','demo')",(A,))
        c.execute("INSERT INTO messenger_companies VALUES (?, '0000000002','2026-10-21','demo')",(B,))
        c.execute("INSERT INTO messenger_companies VALUES (?, '0000000003','2026-10-21','demo')",(C,))
        c.execute("""INSERT INTO messenger_connections
          (id,org_a,org_b,requester_org,status,created_at,accepted_at)
          VALUES (?,?,?,?, 'active','2026-10-21','2026-10-21')""",(THREAD,A,B,A))
        for msg_id,request_id in ((M1,'e'*32),(M2,'f'*32)):
            c.execute("""INSERT INTO messenger_messages
               (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
               VALUES (?,?,?,?, 'text','test',?, '2026-10-21')""",
              (msg_id,THREAD,A,'u1',request_id))

    def current_user(request: Request):
        uid = request.headers.get('X-Lab-User','')
        with conn() as c:
            row=c.execute('SELECT id,org_id FROM users WHERE id=?',(uid,)).fetchone()
            if not row:
                raise HTTPException(401,'not authenticated')
            return dict(row)

    def fail(detail, status=400):
        raise HTTPException(status,detail)

    app=FastAPI()
    register_routes(app, current_user=current_user,conn=conn,transaction=transaction,
                    ident=lambda: '9'*32, now=lambda: '2026-10-21T10:11:12Z',
                    fail=fail, need_admin=lambda *_:None, detail_doc=lambda *_: {})
    with TestClient(app,raise_server_exceptions=False) as client:
        yield client,conn


def endpoint():
    return f'/api/messenger/threads/{THREAD}/read'


def evidence(conn):
    with conn() as c:
        journal=c.execute('''SELECT org_id,actor_user,previous_read_seq,next_read_seq
          FROM messenger_read_actor_history_v59 ORDER BY event_id''').fetchall()
        cursor=c.execute('SELECT org_id,last_read_seq FROM messenger_read_positions ORDER BY org_id').fetchall()
        return [tuple(x) for x in journal],[tuple(x) for x in cursor]


def test_real_http_route_records_authentic_employee_and_no_duplicate(site):
    client,conn=site
    for identity, msg_id in [('u1',M1),('u2',M2),('u1',M1),('u2',M2)]:
        resp=client.post(endpoint(),json={'last_message_id':msg_id},headers={'X-Lab-User':identity})
        assert resp.status_code==200,resp.text
        assert resp.json()=={'status':'read'}
    journal,cursor=evidence(conn)
    assert journal==[(A,'u1',0,1),(A,'u2',1,2)]
    assert cursor==[(A,2)]


def test_real_http_cross_tenant_denied_without_side_effect(site):
    client,conn=site
    for uid,expect in [('uc',404),('',401)]:
        x=client.post(endpoint(),json={'last_message_id':M2},headers={'X-Lab-User':uid})
        assert x.status_code==expect,x.text
    assert evidence(conn)==([],[])


def test_real_http_invalid_message_id_denied_without_side_effect(site):
    client,conn=site
    response=client.post(endpoint(),json={'last_message_id':'9'*32},headers={'X-Lab-User':'u1'})
    assert response.status_code==404
    assert evidence(conn)==([],[])


def test_real_http_journal_failure_rolls_back_cursor(site):
    client,conn=site
    with conn() as c:
        c.execute('''CREATE TRIGGER fail_v59_web BEFORE INSERT ON messenger_read_actor_history_v59
           BEGIN SELECT RAISE(ABORT,'injected'); END''')
    result=client.post(endpoint(),json={'last_message_id':M1},headers={'X-Lab-User':'u1'})
    assert result.status_code==500
    assert evidence(conn)==([],[])
