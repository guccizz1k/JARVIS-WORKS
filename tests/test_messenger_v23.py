"""V2.3 search, instant chat and attachments regression gates."""
import io
import sqlite3
import uuid
from zipfile import ZipFile
from app import main
from tests.test_messenger_v22 import login, p, q, patch


def setup(c):
    a,org_a=login(c,'demo@hanbit.example')
    b,org_b=login(c,'demo@bada.example')
    return a,b,org_a,org_b


def upload(c,h,tid,filename,data,ref=None):
    return c.post('/api/messenger/threads/'+tid+'/attachments',headers=h,
                  data={'request_id':ref or uuid.uuid4().hex}, files={'file':(filename,data)})


def test_immediate_text_chat_without_acceptance(client):
    a,b,org_a,org_b=setup(client)
    r=p(client,a,'/messenger/threads',{'recipient_org_id':org_b})
    assert r.status_code==201 and r.json()['status']=='active',r.text
    tid=r.json()['id']
    assert p(client,a,f'/messenger/threads/{tid}/messages',{'content':'안녕하세요','request_id':uuid.uuid4().hex}).status_code==201
    assert q(client,b,f'/messenger/threads/{tid}/messages').json()[0]['body']=='안녕하세요'
    assert p(client,b,'/messenger/threads',{'recipient_org_id':org_a}).json()['id']==tid
    assert q(client,b,'/messenger/threads').json()[0]['other_company']=='한빛테크'


def test_search_filter_and_scroll_pagination(client):
    a,b,org_a,org_b=setup(client)
    with main.transaction() as db:
        for i in range(64):
            oid=uuid.uuid4().hex
            db.execute('INSERT INTO organizations(id,name,created_at) VALUES(?,?,?)',(oid,f'가상협력회사{i:03d}',main.now()))
            db.execute('INSERT INTO messenger_companies(org_id,business_number,verified_at,verification_kind) VALUES(?,?,?,?)',
                       (oid,f'{i+100:010d}',main.now(),'operator'))
    one=q(client,a,'/messenger/directory/search?q=%EA%B0%80%EC%83%81&limit=30&offset=0')
    assert one.status_code==200,one.text
    assert len(one.json()['items'])==30 and one.json()['next_offset']==30
    two=q(client,a,'/messenger/directory/search?q=%EA%B0%80%EC%83%81&limit=30&offset=30')
    three=q(client,a,'/messenger/directory/search?q=%EA%B0%80%EC%83%81&limit=30&offset=60')
    assert len(two.json()['items'])==30 and len(three.json()['items'])==4
    assert three.json()['next_offset'] is None
    ids={o['org_id'] for result in (one,two,three) for o in result.json()['items']}
    assert len(ids)==64
    escaped=q(client,a,'/messenger/directory/search?q=%25&offset=0').json()
    assert escaped['items']==[] # percent is a literal, not SQL wildcard
    assert q(client,a,'/messenger/directory/search?q=a&limit=51').status_code==422


def test_photo_upload_download_and_other_company_rejected(client):
    a,b,org_a,org_b=setup(client)
    tid=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    # Small valid PNG header: content is never executed or interpreted server side.
    photo=b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\x0dIHDR' + b'abc'*8
    ref=uuid.uuid4().hex
    sent=upload(client,a,tid,'사진.png',photo,ref)
    assert sent.status_code==201,sent.text
    assert upload(client,a,tid,'사진.png',photo,ref).json()['id']==sent.json()['id']
    assert upload(client,a,tid,'다른.png',photo,ref).status_code==409
    mid=sent.json()['id']
    attached=q(client,b,f'/messenger/threads/{tid}/messages').json()[0]['attachment']
    assert attached['filename']=='사진.png' and attached['size_bytes']==len(photo)
    content=client.get(attached['url'],headers=b)
    assert content.status_code==200 and content.content==photo
    assert 'no-store' in content.headers['cache-control']
    assert patch(client,a,f'/messenger/messages/{mid}',{'content':'위조','expected_version':1}).status_code==409
    assert client.delete('/api/messenger/messages/'+mid,headers=a).status_code==405
    with main.transaction() as db:
        try:db.execute('DELETE FROM messenger_attachments WHERE message_id=?',(mid,))
        except sqlite3.IntegrityError:pass
        else:assert False,'attachment delete should be blocked'
        org_c=uuid.uuid4().hex
        db.execute('INSERT INTO organizations VALUES(?,?,?)',(org_c,'미인가회사',main.now()))
        db.execute('INSERT INTO users VALUES(?,?,?,?,?,?,?)',
                   (uuid.uuid4().hex,org_c,'outsider@ex.test',main.hash_password('SuperSecret123'),'외부','admin',main.now()))
    logged=client.post('/api/login',json={'email':'outsider@ex.test','password':'SuperSecret123'})
    assert logged.status_code==200
    h={'Cookie':main.SESSION_COOKIE+'='+logged.cookies.get(main.SESSION_COOKIE)}
    assert client.get(attached['url'],headers=h).status_code==404


def test_document_download_attachment_not_inline_and_restrictions(client):
    a,b,_,org_b=setup(client)
    tid=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    pdf=b'%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n'
    response=upload(client,a,tid,'order.pdf',pdf)
    assert response.status_code==201,response.text
    mid=response.json()['id']
    got=client.get('/api/messenger/messages/'+mid+'/attachment',headers=b)
    assert got.status_code==200 and got.content==pdf
    assert got.headers['content-type'].startswith('application/octet-stream')
    assert got.headers['content-disposition'].startswith('attachment;')
    assert upload(client,a,tid,'evil.html',b'<html>hello</html>').status_code==415
    assert upload(client,a,tid,'fake.pdf',b'<html>hello</html>').status_code==415
    assert upload(client,a,tid,'too-big.pdf',b'%PDF-'+b'X'*(5*1024*1024)).status_code==413
    assert upload(client,a,tid,'fake.xlsx',b'PKnotzip').status_code==415


def test_previous_pending_connection_is_migrated_without_approval(client):
    a,b,org_a,org_b=setup(client)
    tid=p(client,a,'/messenger/threads',{'recipient_org_id':org_b}).json()['id']
    with main.transaction() as db:
        db.execute('UPDATE messenger_connections SET status=\'pending\',accepted_at=NULL WHERE id=?',(tid,))
    with main.conn() as db:
        main.install_messenger_schema(db)
    assert q(client,b,'/messenger/threads').json()[0]['status']=='active'


def test_public_ui_contains_search_scrolling_plus_and_receive_poll():
    from pathlib import Path
    s=(main.ROOT/'static'/'app.js').read_text()
    t=(main.ROOT/'static'/'style.css').read_text()
    assert all(x in s for x in ('jw-company-query','jw-company-results','jw-plus-menu','messengerReceiveUpdates','messengerSendAttachment','messenger-pick-photo','messenger-pick-file'))
    assert 'overflow-y:auto' in t and 'setInterval(messengerReceiveUpdates' in s
    assert '대화 요청을 보냈습니다' not in s
