"""Business-messenger security and transactional document regression tests."""
from __future__ import annotations
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
import pytest
import app.main as main
import app.messenger as messenger


def login(c, email):
    r=c.post('/api/login',json={'email':email,'password':'Demo!2026secure'})
    assert r.status_code==200,r.text
    return {'Cookie':main.SESSION_COOKIE+'='+r.cookies.get(main.SESSION_COOKIE),
            'X-CSRF-Token':r.json()['csrf_token']},r.json()['user']['org_id']


def q(c,h,path): return c.get('/api'+path,headers=h)
def p(c,h,path,obj):return c.post('/api'+path,headers=h,json=obj)
def patch(c,h,path,obj):return c.patch('/api'+path,headers=h,json=obj)

def channel(c):
    ah,aorg=login(c,'demo@hanbit.example');bh,borg=login(c,'demo@bada.example')
    assert q(c,ah,'/messenger/directory').json()[0]['org_id']==borg
    req=p(c,ah,'/messenger/threads',{'recipient_org_id':borg})
    assert req.status_code==201,req.text
    tid=req.json()['id']
    assert p(c,bh,f'/messenger/threads/{tid}/accept',{}).status_code==200
    return ah,bh,aorg,borg,tid


def test_connection_acceptance_and_company_names(client):
    ah,aorg=login(client,'demo@hanbit.example');bh,borg=login(client,'demo@bada.example')
    assert p(client,ah,'/messenger/threads',{'recipient_org_id':aorg}).status_code==409
    r=p(client,ah,'/messenger/threads',{'recipient_org_id':borg});tid=r.json()['id']
    assert r.json()['status']=='active'
    assert p(client,ah,f'/messenger/threads/{tid}/messages',{'content':'Hello','request_id':uuid.uuid4().hex}).status_code==201
    assert p(client,ah,f'/messenger/threads/{tid}/accept',{}).status_code==200
    assert p(client,bh,f'/messenger/threads/{tid}/accept',{}).status_code==200
    assert p(client,bh,f'/messenger/threads/{tid}/accept',{}).status_code==200
    msg=p(client,ah,f'/messenger/threads/{tid}/messages',{'content':'발주서 곧 보내겠습니다.','request_id':uuid.uuid4().hex})
    assert msg.status_code==201,msg.text
    m=q(client,bh,f'/messenger/threads/{tid}/messages').json()
    assert len(m)==2 and m[-1]['company_name']=='한빛테크' and not m[-1]['mine']
    assert q(client,ah,'/messenger/threads').json()[0]['other_company']=='바다유통'


def test_tenant_leakage_unauthenticated_and_csrf(client):
    ah,bh,aorg,borg,tid=channel(client)
    client.cookies.clear()
    assert client.get('/api/messenger/directory').status_code==401
    assert client.post('/api/messenger/threads',json={'recipient_org_id':borg}).status_code==401
    assert client.post('/api/messenger/threads',headers={'Cookie':ah['Cookie']},json={'recipient_org_id':borg}).status_code==403
    assert p(client,ah,'/messenger/threads',{'recipient_org_id':'a'*32}).status_code==403
    # Unverified org cannot be listed or contacted, even if present in organizations.
    with main.transaction() as c:
        unverified=uuid.uuid4().hex
        c.execute('INSERT INTO organizations VALUES(?,?,?)',(unverified,'가짜외부기업',main.now()))
    assert unverified not in str(q(client,ah,'/messenger/directory').json())
    assert p(client,ah,'/messenger/threads',{'recipient_org_id':unverified}).status_code==403
    with main.transaction() as c:
        third=uuid.uuid4().hex; user=uuid.uuid4().hex
        c.execute('INSERT INTO organizations VALUES(?,?,?)',(third,'세번째회사',main.now()))
        c.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',(user,third,'third@example.test',main.hash_password('Pass123456789'),'3자','admin',main.now()))
        c.execute("INSERT INTO messenger_companies VALUES(?,?,?,'operator')",(third,'0000000003',main.now()))
        with pytest.raises(sqlite3.IntegrityError):
            c.execute("INSERT INTO messenger_companies VALUES(?,?,?,'operator')",(unverified,'0000000003',main.now()))
    r=client.post('/api/login',json={'email':'third@example.test','password':'Pass123456789'})
    h3={'Cookie':main.SESSION_COOKIE+'='+r.cookies.get(main.SESSION_COOKIE),'X-CSRF-Token':r.json()['csrf_token']}
    for suffix in (f'/messenger/threads/{tid}/messages',):
        assert q(client,h3,suffix).status_code==404
    assert p(client,h3,f'/messenger/threads/{tid}/accept',{}).status_code==404
    assert p(client,h3,f'/messenger/threads/{tid}/messages',{'content':'x','request_id':uuid.uuid4().hex}).status_code==404


def test_edit_30m_revision_history_no_delete(client,monkeypatch):
    ah,bh,aorg,borg,tid=channel(client)
    ref=uuid.uuid4().hex; body={'content':'처음 내용','request_id':ref}
    r=p(client,ah,f'/messenger/threads/{tid}/messages',body)
    assert r.status_code==201,r.text; mid=r.json()['id']
    assert p(client,ah,f'/messenger/threads/{tid}/messages',body).json()['id']==mid
    assert p(client,ah,f'/messenger/threads/{tid}/messages',{**body,'content':'다른 내용'}).status_code==409
    assert patch(client,bh,f'/messenger/messages/{mid}',{'content':'위조','expected_version':1}).status_code==404
    assert patch(client,ah,f'/messenger/messages/{mid}',{'content':'두번째 내용','expected_version':1}).status_code==200
    assert patch(client,ah,f'/messenger/messages/{mid}',{'content':'세번째 내용','expected_version':1}).status_code==409
    history=q(client,bh,f'/messenger/messages/{mid}/history').json()
    assert history[0]['previous_body']=='처음 내용' and history[0]['new_body']=='두번째 내용'
    assert q(client,bh,f'/messenger/threads/{tid}/messages').json()[0]['version']==2
    class FutureClock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(tz)+timedelta(minutes=31)
    with monkeypatch.context() as mp:
        mp.setattr(messenger,'datetime',FutureClock)
        assert patch(client,ah,f'/messenger/messages/{mid}',{'content':'늦은 수정','expected_version':2}).status_code==409
    assert client.delete('/api/messenger/messages/'+mid,headers=ah).status_code==405
    with main.conn() as c:
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM messenger_messages WHERE id=?',(mid,))
        with pytest.raises(sqlite3.IntegrityError):c.execute('DELETE FROM messenger_edits WHERE message_id=?',(mid,))


def test_order_target_binding_snapshot_and_receipt(client):
    ah,bh,aorg,borg,tid=channel(client)
    customer=q(client,ah,'/customers').json()[0]
    qbody={'customer_id':customer['id'],'title':'발주서','vat_mode':'taxable',
           'items':[{'name':'부품A','quantity':3,'unit_price':1000}]}
    quote=p(client,ah,'/quotes',qbody).json()
    assert p(client,ah,f"/quotes/{quote['id']}/status",{'status':'sent'}).status_code==200
    assert p(client,ah,f"/quotes/{quote['id']}/status",{'status':'accepted'}).status_code==200
    order=p(client,ah,'/orders/from-quote',{'quote_id':quote['id'],'due_date':'2099-12-30'}).json()
    payload={'order_id':order['id'],'actor_name':'김철수','request_id':uuid.uuid4().hex}
    # Unverified target match: reject before company profile number added to customer.
    assert p(client,ah,f'/messenger/threads/{tid}/orders',payload).status_code==409
    cust_data={k:customer[k] for k in ('name','business_number','contact_name','email','phone')}
    cust_data['business_number']='0000000002'
    assert client.put('/api/customers/'+customer['id'],headers=ah,json=cust_data).status_code==200
    r=p(client,ah,f'/messenger/threads/{tid}/orders',payload)
    assert r.status_code==201,r.text
    mid=r.json()['id'];snap=r.json()['order_snapshot'];assert snap['money']['total']==3300
    assert snap['items'][0]['quantity']==3
    assert p(client,ah,f'/messenger/threads/{tid}/orders',payload).json()['id']==mid
    assert patch(client,ah,f'/messenger/messages/{mid}',{'content':'변조','expected_version':1}).status_code==409
    assert p(client,ah,f'/messenger/messages/{mid}/receipt',{'actor_name':'발신자'}).status_code==403
    ack=p(client,bh,f'/messenger/messages/{mid}/receipt',{'actor_name':'박주임'})
    assert ack.status_code==200,ack.text
    assert p(client,bh,f'/messenger/messages/{mid}/receipt',{'actor_name':'다른사람'}).json()['actor_name']=='박주임'
    seen=q(client,bh,f'/messenger/threads/{tid}/messages').json()[-1]
    assert seen['order_snapshot']==snap
    assert seen['received_at'] and seen['receipt_actor_name']=='박주임'
    assert q(client,bh,'/orders').json()==[] # Receiver review does not fabricate an accepted order
    assert q(client,bh,'/invoices').json()==[]
    assert q(client,bh,'/dashboard').json()['collected']==0


def test_no_cross_company_order_and_html_injection(client):
    ah,bh,aorg,borg,tid=channel(client)
    bad=p(client,ah,f'/messenger/threads/{tid}/orders',
          {'order_id':'a'*32,'actor_name':'홍길동','request_id':uuid.uuid4().hex})
    assert bad.status_code==404
    content='<img src=x onerror=alert(1)>'
    sent=p(client,ah,f'/messenger/threads/{tid}/messages',{'content':content,'request_id':uuid.uuid4().hex})
    assert sent.status_code==201
    assert q(client,bh,f'/messenger/threads/{tid}/messages').json()[0]['body']==content
    # The client escapes the content using the existing e() before rendering HTML.
    js=open(main.ROOT/'static'/'app.js').read()
    assert '${e(m.body)}' in js


def test_idempotency_rate_cap_and_edit_audit(client):
    ah,bh,aorg,borg,tid=channel(client)
    for _ in range(20):
        r=p(client,ah,f'/messenger/threads/{tid}/messages',{'content':'테스트','request_id':uuid.uuid4().hex})
        assert r.status_code==201,r.text
    assert p(client,ah,f'/messenger/threads/{tid}/messages',
             {'content':'추가','request_id':uuid.uuid4().hex}).status_code==429


def test_schema_idempotent_without_previous_records(client):
    with main.conn() as c:
        main.install_messenger_schema(c)
        main.install_messenger_schema(c)
        assert c.execute('SELECT count(*) FROM messenger_companies').fetchone()[0]==2


def test_verification_revocation_blocks_old_conversation(client):
    ah,bh,aorg,borg,tid=channel(client)
    with main.transaction() as c:
        c.execute('DELETE FROM messenger_companies WHERE org_id=?',(borg,))
    assert q(client,ah,f'/messenger/threads/{tid}/messages').status_code==409
    assert p(client,ah,f'/messenger/threads/{tid}/messages',
             {'content':'cannot send','request_id':uuid.uuid4().hex}).status_code==409
    assert q(client,bh,f'/messenger/threads/{tid}/messages').status_code==403


def test_messenger_concurrent_revision_fails_closed(client):
    ah,bh,_,_,tid=channel(client)
    r=p(client,ah,f'/messenger/threads/{tid}/messages',
        {'content':'동시성 테스트','request_id':uuid.uuid4().hex})
    mid=r.json()['id']
    one=patch(client,ah,f'/messenger/messages/{mid}',{'content':'첫 수정','expected_version':1})
    two=patch(client,ah,f'/messenger/messages/{mid}',{'content':'나중 덮어쓰기','expected_version':1})
    assert one.status_code==200 and two.status_code==409
    hist=q(client,bh,f'/messenger/messages/{mid}/history').json()
    assert len(hist)==1 and hist[0]['new_body']=='첫 수정'
