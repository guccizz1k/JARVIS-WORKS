"""V2.5 bounded cursor pagination, full history integrity, and SSE authentication."""
import asyncio
import sqlite3
import uuid

from app import main
from tests.test_messenger_v22 import login, p, q


def seed_history(client, count=153):
    a,org_a=login(client,'demo@hanbit.example')
    b,org_b=login(client,'demo@bada.example')
    tid=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    with main.transaction() as db:
        ua=db.execute('SELECT id FROM users WHERE org_id=? LIMIT 1',(org_a,)).fetchone()['id']
        ub=db.execute('SELECT id FROM users WHERE org_id=? LIMIT 1',(org_b,)).fetchone()['id']
        for i in range(count):
            db.execute('''INSERT INTO messenger_messages
                    (id,connection_id,sender_org,sender_user,kind,body,request_id,created_at)
                    VALUES(?,?,?,?,'text',?,?,?)''',
                    (uuid.uuid4().hex,tid,org_a if i%2 else org_b,
                     ua if i%2 else ub,f'기록 {i:03d}',uuid.uuid4().hex,
                     main.now()))  # identical timestamps allowed; rowid is stable
    return a,b,tid


def page(c,h,tid,query=''):
    return q(c,h,f'/messenger/threads/{tid}/messages/page'+query)


def test_cursor_pages_entire_history_without_skip_or_duplicate(client):
    a,b,tid=seed_history(client,153)
    assert len(q(client,a,f'/messenger/threads/{tid}/messages').json())==100, 'legacy API unchanged'
    first=page(client,a,tid)
    assert first.status_code==200,first.text
    assert len(first.json()['items'])==50
    assert first.json()['has_more'] is True
    expected=[f'기록 {i:03d}' for i in range(153)]
    combined=[]
    cursor=None
    for n in range(5):
        v=page(client,a,tid,'?before='+cursor if cursor else '')
        assert v.status_code==200,v.text
        doc=v.json()
        combined=doc['items']+combined
        cursor=doc['items'][0]['id']
        if not doc['has_more']:
            assert doc['next_before'] is None
            break
    else: assert False,'pagination never ended'
    assert [m['body'] for m in combined]==expected
    assert len({m['id'] for m in combined})==153
    assert page(client,a,tid,'?before='+cursor).json()['items']==[]
    assert combined[0]['mine'] is False
    assert len(page(client,b,tid,'?limit=3').json()['items'])==3


def test_forward_paging_handles_more_than_100_new_messages(client):
    a,b,tid=seed_history(client,164)
    latest=page(client,a,tid,'?limit=50').json()
    old=latest['items'][0]
    all_new=[]
    cur=old['id']
    for n in range(3):
        got=page(client,a,tid,'?after='+cur+'&limit=50').json()
        all_new+=got['items']
        if not got['has_more']: break
        cur=got['next_after']
    assert [i['body'] for i in all_new]==[f'기록 {j:03d}' for j in range(115,164)]
    assert all_new[-1]['body']=='기록 163'
    assert all_new[0]['body']=='기록 115'


def test_cursor_cannot_refer_to_other_thread_or_invalid_query(client):
    a,b,tid=seed_history(client,6)
    recent=page(client,a,tid).json()['items']
    assert page(client,a,tid,'?after='+recent[0]['id']+'&before='+recent[-1]['id']).status_code==422
    assert page(client,a,tid,'?limit=101').status_code==422
    assert page(client,a,tid,'?after='+uuid.uuid4().hex).status_code==404
    assert page(client,a,tid,'?before=malformed').status_code==422
    assert page(client,a,tid,'?after='+recent[-1]['id']).json()['items']==[]
    # Wrong company cannot enumerate message IDs via cursor endpoint.
    with main.transaction() as db:
        org=uuid.uuid4().hex
        db.execute('INSERT INTO organizations VALUES(?,?,?)',(org,'Third Paged Org',main.now()))
        db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                   (uuid.uuid4().hex,org,'third-page@example.test',main.hash_password('StrongThirdPassword42'),
                    'Third','admin',main.now()))
        db.execute("INSERT INTO messenger_companies VALUES(?,?,?,'operator')",(org,'0000000088',main.now()))
    resp=client.post('/api/login',json={'email':'third-page@example.test','password':'StrongThirdPassword42'})
    assert resp.status_code==200
    third={'Cookie':main.SESSION_COOKIE+'='+resp.cookies.get(main.SESSION_COOKIE),'X-CSRF-Token':resp.json()['csrf_token']}
    assert page(client,third,tid).status_code==404
    assert page(client,third,tid,'?before='+recent[0]['id']).status_code==404
    # SSE is not a backdoor to another company's existence.
    assert q(client,third,f'/messenger/threads/{tid}/events').status_code==404


def test_older_pages_include_attachment_and_revision_without_mutation(client):
    a,b,tid=seed_history(client,6)
    message=page(client,a,tid,'?limit=3').json()['items'][0]
    with main.transaction() as db:
        edit_id=uuid.uuid4().hex
        user=db.execute('SELECT sender_user FROM messenger_messages WHERE id=?',(message['id'],)).fetchone()['sender_user']
        db.execute('INSERT INTO messenger_edits VALUES(?,?,?,?,?,?,?)',
                   (edit_id,message['id'],message['body'],'수정 후',user,main.now(),2))
        db.execute('UPDATE messenger_messages SET body=?,version=2,edited_at=? WHERE id=?',
                   ('수정 후',main.now(),message['id']))
    revised=page(client,a,tid,'?limit=4').json()['items']
    assert any(i['id']==message['id'] and i['body']=='수정 후' and i['version']==2 for i in revised)
    assert q(client,b,'/messenger/messages/'+message['id']+'/history').json()[0]['previous_body']==message['body']
    assert all(m['attachment'] is None for m in revised)
    with main.conn() as db:
        assert db.execute('SELECT COUNT(*) FROM messenger_messages').fetchone()[0]==6
        assert db.execute('SELECT COUNT(*) FROM messenger_edits').fetchone()[0]==1


def test_sse_emits_ready_then_change_and_revokes_partner(client):
    a,b,tid=seed_history(client,2)
    endpoint=next(r.endpoint for r in main.app.routes
                  if r.path=='/api/messenger/threads/{connection_id}/events')
    class Connected:
        method='GET'
        headers={}
        cookies={main.SESSION_COOKIE:a['Cookie'].split('=',1)[1]}
        async def is_disconnected(self):return False
    with main.conn() as db:
        row=db.execute('SELECT * FROM users WHERE email=?',('demo@hanbit.example',)).fetchone()
        user=dict(row)
    async def exercise():
        response=await endpoint(connection_id=tid,request=Connected(),user=user)
        generator=response.body_iterator
        ready=await asyncio.wait_for(anext(generator),timeout=2)
        assert ready.startswith('event: ready')
        p(client,a,f'/messenger/threads/{tid}/messages',{'content':'새 SSE 알림','request_id':uuid.uuid4().hex})
        changed=await asyncio.wait_for(anext(generator),timeout=3)
        assert changed.startswith('event: change')
        with main.transaction() as db:
            db.execute('DELETE FROM messenger_companies WHERE org_id=?',
                       (user['org_id'],))
        revoked=await asyncio.wait_for(anext(generator),timeout=3)
        assert revoked.startswith('event: revoked')
        await generator.aclose()
    asyncio.run(exercise())


def test_frontend_history_and_eventsource_fallback_contract():
    source=(main.ROOT/'static'/'app.js').read_text()
    assert 'messengerLoadOlder' in source and 'jw-older-bar' in source
    assert 'box.scrollTop=Math.max(0,box.scrollHeight-height+top)' in source
    assert 'EventSource(' in source and "addEventListener('change'" in source
    assert 'setInterval(messengerReceiveUpdates,4500)' in source
    assert "?after='+encodeURIComponent(cursor)" in source
    assert "?before='+encodeURIComponent(first)" in source


def test_sse_stream_expires_on_logout_without_streaming_more_data(client):
    a,b,tid=seed_history(client,1)
    endpoint=next(r.endpoint for r in main.app.routes
                  if r.path=='/api/messenger/threads/{connection_id}/events')
    class Connected:
        method='GET'
        headers={}
        cookies={main.SESSION_COOKIE:a['Cookie'].split('=',1)[1]}
        async def is_disconnected(self):return False
    with main.conn() as db:
        user=dict(db.execute('SELECT * FROM users WHERE email=?',('demo@hanbit.example',)).fetchone())
    async def exercise():
        response=await endpoint(connection_id=tid,request=Connected(),user=user)
        g=response.body_iterator
        assert (await asyncio.wait_for(anext(g),timeout=2)).startswith('event: ready')
        out=p(client,a,'/logout',{})
        assert out.status_code==200
        assert (await asyncio.wait_for(anext(g),timeout=3)).startswith('event: revoked')
        await g.aclose()
    asyncio.run(exercise())


def test_idle_messenger_discovers_new_company_threads_and_large_history(client):
    a,b,tid=seed_history(client,1103)
    page_one=page(client,a,tid).json()
    bodies=[]
    cursor=None
    while True:
        data=page(client,a,tid,'?before='+cursor if cursor else '').json()
        bodies=data['items']+bodies
        if not data['has_more']:break
        cursor=data['next_before']
    assert len(bodies)==1103
    assert bodies[0]['body']=='기록 000' and bodies[-1]['body']=='기록 1102'
    assert len({x['id'] for x in bodies})==1103
    js=(main.ROOT/'static'/'app.js').read_text()
    assert "if(!tid){" in js and "const threads=await api('/messenger/threads')" in js
