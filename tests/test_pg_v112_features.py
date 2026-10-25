"""Isolated V11.2 unit tests: no external PostgreSQL or company data."""
import asyncio
import hashlib
import re
from pathlib import Path
from types import SimpleNamespace
import pytest
from app.pg_v112_wakeup import WakeHub, digest_connection, listen_forever, CHANNEL
from app.pg_v112_ocr_queue import Claim, PgOcrQueue, _metadata, process_one


def test_wakeup_digest_matches_pg_sha256_algorithm():
    assert digest_connection('ci-connection-a') == hashlib.sha256(b'ci-connection-a').hexdigest()
    with pytest.raises(ValueError): digest_connection('')


@pytest.mark.asyncio
async def test_targeted_wakeup_no_cross_chat_and_cleanup():
    hub=WakeHub(max_subscribers=2)
    a=hub.subscribe('a')
    b=hub.subscribe('b')
    assert hub.publish_from_thread(digest_connection('a'))
    await asyncio.sleep(.01)
    assert a.is_set() and not b.is_set()
    with pytest.raises(RuntimeError):hub.subscribe('c')
    hub.unsubscribe('a',a)
    hub.unsubscribe('b',b)
    assert hub.subscriptions==0
    c=hub.subscribe('c')
    assert not c.is_set()
    hub.unsubscribe('c',c)


@pytest.mark.asyncio
async def test_notification_rejects_content_malformed_and_unsubscribed():
    hub=WakeHub()
    ev=hub.subscribe('chat-z')
    assert not hub.publish_from_thread('private_message_payload')
    assert not hub.publish_from_thread(digest_connection('chat-other')[:-1]+'z')
    assert not ev.is_set()
    hub.unsubscribe('chat-z',ev)
    assert hub.publish_from_thread(digest_connection('chat-z'))
    await asyncio.sleep(.005)
    assert not ev.is_set()


def test_loop_guard_rejects_invalid_subscriber_cap():
    for cap in (0,True,100001):
        with pytest.raises(ValueError):WakeHub(max_subscribers=cap)


@pytest.mark.parametrize('value',[
 'tenant/other/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
 'tenant/acme/../secret','tenant/acme/aaaaaaaaaaaa','https://private/blob',
 '',None])
def test_ocr_object_path_tenant_validation(value):
    with pytest.raises(ValueError):_metadata('acme',value,'receipt.pdf','a'*64,'request-abc-001')


def test_ocr_metadata_rejects_invalid_hash_filename_idempotency():
    obj='tenant/acme/'+'a'*32
    for vals in [(obj,'evil\r\nname.pdf','a'*64,'request-abc-001'),
                 (obj,'doc.pdf','Z'*64,'request-abc-001'),
                 (obj,'doc.pdf','a'*64,'abc')]:
        with pytest.raises(ValueError):_metadata('acme',*vals)


class FakeCursor:
    def __init__(self,rows):self.rows=iter(rows);self.calls=[]
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def execute(self,sql,params):
        assert '%s' in sql
        assert sql.count('%s') == len(params)
        self.calls.append((sql,params))
    def fetchone(self):return next(self.rows)


class FakeConn:
    def __init__(self,rows):self.cur=FakeCursor(rows)
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def transaction(self):return self
    def cursor(self):return self.cur


def test_worker_claim_uses_skip_locked_and_fencing_token():
    class DynamicConn(FakeConn):
        def __init__(self): super().__init__([None])
        def cursor(self):
            cur=self.cur
            def getrow():
                token=cur.calls[-1][1][0]
                return ('task-id','company-a','tenant/company-a/'+'a'*32,'b'*64,'scan.pdf',1,token)
            cur.fetchone=getrow
            return cur
    conn=DynamicConn()
    item=PgOcrQueue(lambda:conn).claim()
    assert item.org_id=='company-a'
    assert len(item.lease_token)==64
    sql,params=conn.cur.calls[-1]
    assert 'FOR UPDATE SKIP LOCKED' in sql
    assert 'lease_until' in sql and 'RETURNING' in sql
    assert 'FOR UPDATE' not in params


def test_submit_same_idempotency_key_rejects_different_content():
    con=FakeConn([None,('old-id','tenant/acme/'+'b'*32,'b'*64,'doc.pdf','actor')])
    q=PgOcrQueue(lambda:con)
    with pytest.raises(ValueError):q.submit(org_id='acme',object_key='tenant/acme/'+'a'*32,
        filename='doc.pdf',sha256='a'*64,request_id='request-1234',actor_id='actor')
    assert len(con.cur.calls)==2
    assert 'ON CONFLICT (org_id,request_id) DO NOTHING' in con.cur.calls[0][0]


def test_submit_idempotent_replay_does_not_allocate_duplicate_row():
    key='tenant/acme/'+'a'*32
    con=FakeConn([None,('old-id',key,'a'*64,'doc.pdf','actor')])
    actual=PgOcrQueue(lambda:con).submit(org_id='acme',object_key=key,
        filename='doc.pdf',sha256='a'*64,request_id='request-1234',actor_id='actor')
    assert actual==('old-id',False)


def test_ocr_result_is_always_human_review_state():
    key='tenant/acme/'+'a'*32
    claim=Claim('a'*32,'acme',key,hashlib.sha256(b'pdf').hexdigest(),
                'receipt.pdf',1,'c'*64)
    class Queue:
        def claim(self):return claim
        def complete(self,j,*,result_key):
            assert result_key=='tenant/acme/ocr-result/'+'a'*32
            return True
        def fail(self,*args,**kwargs):raise AssertionError('unexpected failure')
    class Store:
        def read(self,org,k):assert org=='acme' and k==key;return b'pdf'
        def write_proposal(self,org,k,doc):
            assert org=='acme' and k=='tenant/acme/ocr-result/'+'a'*32
            assert doc=={'warnings':['human approval required']}
    assert process_one(Queue(),Store(),lambda name,raw:{'warnings':['human approval required']})=='NEEDS_REVIEW'


def test_bad_ocr_bytes_never_call_parser_and_record_safe_error():
    key='tenant/acme/'+'a'*32
    claim=Claim('a'*32,'acme',key,'b'*64,'x.pdf',1,'c'*64)
    class Queue:
        def claim(self):return claim
        def fail(self,j,*,error_code):assert error_code=='HASH_MISMATCH';return True
    class Store:
        def read(self,*args):return b'wrong'
    assert process_one(Queue(),Store(),lambda *a: (_ for _ in ()).throw(AssertionError()))=='RETRY_OR_FAILED'


def test_ephemeral_sql_denies_persistent_dbs_and_no_worker_grants():
    root=Path(__file__).resolve().parents[1]
    sql=(root/'db/review/v112_ephemeral_only_pg.sql').read_text()
    assert "current_database() !~ '^jw_v112_ci_[0-9a-f]{12}$'" in sql
    assert "ENABLE ROW LEVEL SECURITY" in sql and "FORCE ROW LEVEL SECURITY" in sql
    assert 'CREATE POLICY' not in sql and 'GRANT ALL' not in sql
    assert "sha256(pg_catalog.convert_to(v_connection_id,'UTF8'))" in sql
    assert "CREATE TRIGGER v112_messenger_insert_wakeup" in sql
    assert "CREATE TRIGGER v112_messenger_edit_wakeup" in sql

