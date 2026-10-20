"""Network-free security/regression contract for V4.0 lab writer."""
from pathlib import Path
import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.pg_messenger_review import PostgreSQLUnverified
from app.pg_write_replay_v40 import LabWriterV40, ReplayConflict
from app.pg_write_api_v40 import create_lab_app

GOOD='postgresql://jw_app:synthetic@127.0.0.1/jw_v20_test_abcdef123456'
TOKEN='t'*48
ID='a'*32


class Cursor:
    def __init__(self, record=None):
        self.record=record
        self.calls=[]
    def execute(self, sql, values=None):
        self.calls.append((sql,values))
        if 'INSERT INTO public.messenger_messages' in sql:
            self.record=('newid',3)
    def fetchone(self):
        return self.record


class Adapter:
    def __init__(self,record=None, tenant='tenant_a',actor='ua'):
        self.record=record
        self.tenant=tenant
        self.actor=actor
        self.calls=[]
    def _check_dsn(self): return True
    def verified_transaction(self, token, readonly=True):
        from contextlib import contextmanager
        @contextmanager
        def tx():
            self.calls.append((token,readonly))
            cur=Cursor(self.record)
            yield cur,self.tenant,self.actor
            self.last=cur
        return tx()


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv('JW_PG_LAB_V40','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')


def test_lack_of_authorization_blocks_before_connect():
    adapter=Adapter()
    w=LabWriterV40(GOOD,adapter=adapter)
    with pytest.raises(PostgreSQLUnverified): w.send_text(token=TOKEN,thread='chat_ab',content='hello',request_id=ID)
    assert adapter.calls==[]


@pytest.mark.parametrize('thread,content,key', [
    ('bad!','hello',ID), ('chat_ab',' ',ID), ('chat_ab','x'*2001,ID),
    ('chat_ab','hello','not-a-uuid'), ('chat_ab','hello','A'*32),
    ('chat_ab','hello',None), ('chat_ab',False,ID),
])
def test_reject_invalid_before_db(enabled,thread,content,key):
    adapter=Adapter()
    w=LabWriterV40(GOOD,adapter=adapter)
    with pytest.raises(ValueError): w.send_text(token=TOKEN,thread=thread,content=content,request_id=key)
    assert not adapter.calls


def test_new_insert_parameterized_under_signed_actor(enabled):
    adapter=Adapter();writer=LabWriterV40(GOOD,adapter=adapter)
    outcome=writer.send_text(token=TOKEN,thread='chat_ab',content='safe',request_id=ID)
    assert outcome=={'id':'newid','message_seq':3,'replayed':False}
    assert adapter.calls==[(TOKEN,False)]
    sql,binds=adapter.last.calls[-1]
    assert '%s' in sql and 'INSERT INTO public.messenger_messages' in sql
    assert binds[1:]==('chat_ab','tenant_a','ua','safe',ID)


def test_exact_retry_returns_first_record_without_reinsertion(enabled):
    adapter=Adapter(record=('id1',13,'chat_ab','ua','text','hello'))
    out=LabWriterV40(GOOD,adapter=adapter).send_text(token=TOKEN,thread='chat_ab',content='hello',request_id=ID)
    assert out=={'id':'id1','message_seq':13,'replayed':True}
    assert len(adapter.last.calls)==2 and not any('INSERT INTO' in s for s,_ in adapter.last.calls)


@pytest.mark.parametrize('record', [
    ('id1',1,'other_thread','ua','text','hello'),
    ('id1',1,'chat_ab','somebody','text','hello'),
    ('id1',1,'chat_ab','ua','order','hello'),
    ('id1',1,'chat_ab','ua','text','different')])
def test_same_nonce_different_semantics_rejected(enabled,record):
    with pytest.raises(ReplayConflict):
        LabWriterV40(GOOD,adapter=Adapter(record=record)).send_text(token=TOKEN,thread='chat_ab',content='hello',request_id=ID)


def test_api_validation_and_no_public_app_mount(enabled):
    from app.pg_write_replay_v40 import LabWriterV40
    app=create_lab_app(GOOD)
    with TestClient(app) as c:
        assert c.post('/lab40/threads/chat_ab/messages',json={'content':'hi','request_id':ID}).status_code==401
        assert c.post('/lab40/threads/../messages',json={'content':'hi','request_id':ID},headers={'X-JW-Lab-Session':TOKEN}).status_code in (404,422)
        assert c.post('/lab40/threads/chat_ab/messages',json={'content':'hi','request_id':ID,'org_id':'tenant_b'},headers={'X-JW-Lab-Session':TOKEN}).status_code==422
    p=Path('app/main.py').read_text()
    assert 'pg_write_replay_v40' not in p and 'pg_write_api_v40' not in p
    assert not any(m in {r.path for r in app.routes} for m in ('/api/messages','/messenger'))


def test_api_error_mask_and_http_replay_status(enabled):
    class Fake:
        def __init__(self):self.call=0
        def send_text(self,**kw):
            self.call+=1
            if self.call==1:return {'id':'original','message_seq':2,'replayed':False}
            if self.call==2:return {'id':'original','message_seq':2,'replayed':True}
            if self.call==3:raise ReplayConflict('leak: sensitive source')
            raise RuntimeError('postgresql://secret-host')
    app=create_lab_app(GOOD,writer=Fake())
    with TestClient(app) as c:
        url='/lab40/threads/chat_ab/messages';headers={'X-JW-Lab-Session':TOKEN};body={'content':'hello','request_id':ID}
        a=c.post(url,json=body,headers=headers);b=c.post(url,json=body,headers=headers)
        conflict=c.post(url,json=body,headers=headers);error=c.post(url,json=body,headers=headers)
        assert (a.status_code,b.status_code,conflict.status_code,error.status_code)==(201,200,409,503)
        assert a.headers['cache-control']=='no-store'
        assert 'secret' not in error.text and 'sensitive' not in conflict.text


def test_driver_stays_separate_from_live_app():
    code=Path('app/pg_write_replay_v40.py').read_text()
    assert 'MessengerReviewAdapter' in code and 'ON CONFLICT' not in code
    assert 'JW_PG_LAB_V40' in code and '_check_dsn' in code


def test_concurrent_unique_violation_rechecks_only_expected_constraint(enabled):
    from contextlib import contextmanager
    class Unique(Exception):
        sqlstate='23505'
        diag=SimpleNamespace(constraint_name='messenger_messages_sender_org_request_id_key')
    class RaceAdapter(Adapter):
        @contextmanager
        def verified_transaction(self,token,readonly=True):
            self.calls.append((token,readonly))
            class RaceCursor:
                response=None
                def execute(inner,sql,vals=None):
                    if 'INSERT INTO public.messenger_messages' in sql:
                        raise Unique()
                    if 'SELECT id,message_seq' in sql and readonly:
                        inner.response=('winner',8,'chat_ab','ua','text','hello')
                def fetchone(inner):return inner.response
            yield RaceCursor(),self.tenant,self.actor
    adapter=RaceAdapter()
    ans=LabWriterV40(GOOD,adapter=adapter).send_text(token=TOKEN,thread='chat_ab',content='hello',request_id=ID)
    assert ans=={'id':'winner','message_seq':8,'replayed':True}
    assert adapter.calls==[(TOKEN,False),(TOKEN,True)]


def test_other_unique_constraint_must_not_be_treated_as_duplicate(enabled):
    from contextlib import contextmanager
    class Unique(Exception):
        sqlstate='23505'
        diag=SimpleNamespace(constraint_name='messenger_messages_pkey')
    class UnexpectedAdapter(Adapter):
        @contextmanager
        def verified_transaction(self,token,readonly=True):
            self.calls.append((token,readonly))
            class Cursor:
                def execute(self,sql,params=None):
                    if 'INSERT INTO' in sql:raise Unique()
                def fetchone(self):return None
            yield Cursor(),self.tenant,self.actor
    a=UnexpectedAdapter()
    with pytest.raises(Unique):
        LabWriterV40(GOOD,adapter=a).send_text(token=TOKEN,thread='chat_ab',content='hello',request_id=ID)
    assert a.calls==[(TOKEN,False)]
