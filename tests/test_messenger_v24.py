"""V2.4 review candidate: unread cursor, authorization, recent activity, and UI controls."""
import uuid

from app import main
from tests.test_messenger_v22 import login, p, q


def test_company_unread_counts_and_read_acknowledgment(client):
    a,org_a=login(client,'demo@hanbit.example')
    b,org_b=login(client,'demo@bada.example')
    tid=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    one=p(client,a,f'/messenger/threads/{tid}/messages',{'content':'첫 메시지','request_id':uuid.uuid4().hex}).json()['id']
    two=p(client,a,f'/messenger/threads/{tid}/messages',{'content':'다음 메시지','request_id':uuid.uuid4().hex}).json()['id']
    assert q(client,b,'/messenger/threads').json()[0]['unread_count']==2
    assert q(client,a,'/messenger/threads').json()[0]['unread_count']==0
    assert q(client,b,f'/messenger/threads/{tid}/messages').status_code==200
    assert q(client,b,'/messenger/threads').json()[0]['unread_count']==2, 'GET alone must not mark read'
    assert p(client,b,f'/messenger/threads/{tid}/read',{'last_message_id':one}).status_code==200
    assert q(client,b,'/messenger/threads').json()[0]['unread_count']==1
    assert p(client,b,f'/messenger/threads/{tid}/read',{'last_message_id':two}).status_code==200
    assert q(client,b,'/messenger/threads').json()[0]['unread_count']==0
    assert p(client,b,f'/messenger/threads/{tid}/read',{'last_message_id':one}).status_code==200
    assert q(client,b,'/messenger/threads').json()[0]['unread_count']==0, 'cursor cannot go backwards'
    p(client,a,f'/messenger/threads/{tid}/messages',{'content':'새 메시지','request_id':uuid.uuid4().hex})
    assert q(client,b,'/messenger/threads').json()[0]['unread_count']==1


def test_read_cursor_does_not_change_message_history_and_requires_csrf(client):
    a,_=login(client,'demo@hanbit.example')
    b,org_b=login(client,'demo@bada.example')
    tid=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    msg=p(client,a,f'/messenger/threads/{tid}/messages',{'content':'원본 증빙','request_id':uuid.uuid4().hex}).json()['id']
    before=q(client,b,f'/messenger/threads/{tid}/messages').json()
    missing_csrf=client.post('/api/messenger/threads/'+tid+'/read',headers={'Cookie':b['Cookie']},json={'last_message_id':msg})
    assert missing_csrf.status_code==403
    assert p(client,b,f'/messenger/threads/{tid}/read',{'last_message_id':uuid.uuid4().hex}).status_code==404
    assert p(client,b,f'/messenger/threads/{uuid.uuid4().hex}/read',{'last_message_id':msg}).status_code==404
    assert p(client,b,f'/messenger/threads/{tid}/read',{'last_message_id':msg}).status_code==200
    assert q(client,b,f'/messenger/threads/{tid}/messages').json()==before
    with main.conn() as db:
        assert db.execute('SELECT COUNT(*) FROM messenger_edits').fetchone()[0]==0
        assert db.execute('SELECT COUNT(*) FROM messenger_messages').fetchone()[0]==1


def test_read_cursor_rejects_foreign_company_even_with_valid_message(client):
    a,_=login(client,'demo@hanbit.example')
    b,org_b=login(client,'demo@bada.example')
    tid=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    mid=p(client,a,f'/messenger/threads/{tid}/messages',{'content':'비밀','request_id':uuid.uuid4().hex}).json()['id']
    with main.transaction() as db:
        third=uuid.uuid4().hex
        db.execute('INSERT INTO organizations VALUES(?,?,?)',(third,'새 회사',main.now()))
        db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(uuid.uuid4().hex,third,'read-third@test.example',main.hash_password('StrongPassword123'),'테스트','admin',main.now()))
        db.execute("INSERT INTO messenger_companies VALUES(?,?,?,'operator')",(third,'0000000033',main.now()))
    res=client.post('/api/login',json={'email':'read-third@test.example','password':'StrongPassword123'})
    assert res.status_code==200
    third_h={'Cookie':main.SESSION_COOKIE+'='+res.cookies.get(main.SESSION_COOKIE),'X-CSRF-Token':res.json()['csrf_token']}
    assert p(client,third_h,f'/messenger/threads/{tid}/read',{'last_message_id':mid}).status_code==404
    assert q(client,b,'/messenger/threads').json()[0]['unread_count']==1


def test_threads_sorted_by_last_activity(client):
    a,_=login(client,'demo@hanbit.example')
    b,org_b=login(client,'demo@bada.example')
    with main.transaction() as db:
        org_c=uuid.uuid4().hex
        db.execute('INSERT INTO organizations VALUES(?,?,?)',(org_c,'추가 회사',main.now()))
        db.execute("INSERT INTO messenger_companies VALUES(?,?,?,'operator')",(org_c,'0000000055',main.now()))
    old=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    newer=p(client,a,'/messenger/threads',{'recipient_org_id':org_c}).json()['id']
    assert q(client,a,'/messenger/threads').json()[0]['id']==newer
    sent=p(client,a,f'/messenger/threads/{old}/messages',{'content':'새 대화','request_id':uuid.uuid4().hex})
    assert sent.status_code==201
    assert q(client,a,'/messenger/threads').json()[0]['id']==old


def test_frontend_unread_and_latest_scroll_contract():
    js=(main.ROOT/'static'/'app.js').read_text()
    css=(main.ROOT/'static'/'style.css').read_text()
    assert 'jw-unread' in js and 'aria-label="읽지 않은 메시지' in js
    assert "out.focus({preventScroll:true});window.scrollTo" in js
    assert "list.scrollTop=list.scrollHeight;messengerMarkReadAtBottom();" in js
    assert "if(ev.target.id==='jw-message-list')messengerMarkReadAtBottom()" in js
    assert 'messengerReadBusy' in js and 'last_message_id:last.id' in js
    assert '.jw-unread' in css
    assert '.sidebar nav{flex:1;min-height:0;overflow-y:auto;' in css
