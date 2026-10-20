"""V4.3 network-free HTTP/SQLSTATE API gates; PostgreSQL live gate is separate."""
from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.pg_web_bridge_v43 import (create_lab_app, classify_database_error,
                                   LabRefused, PostgreSQLUnverified, ReplayConflict)

GOOD = 'postgresql://jw_app:synthetic@127.0.0.1/jw_v20_test_abcdef123456'
TOKEN = 'a' * 48
KEY = 'f' * 32
PATH = '/lab43/api/messenger/threads/chat_ab/messages'


class Error(Exception):
    def __init__(self, sqlstate=None, message='private pg DSN password/session token'):
        super().__init__(message)
        self.sqlstate = sqlstate


class Cursor:
    def __init__(self, active=True, rows=None):
        self.active = active
        self.rows = rows if rows is not None else [
            ('mid', 3, 'tenant_a', 'ua', 'text', 'safe', '2026-10-20T17:00:00')]
        self.output = None
        self.sql = []

    def execute(self, sql, params):
        self.sql.append((sql, params))
        if 'FROM public.messenger_connections' in sql:
            self.output = (1,) if self.active else None
        elif 'FROM public.messenger_messages' in sql:
            self.output = None

    def fetchone(self):
        return self.output

    def fetchall(self):
        return self.rows


class Adapter:
    def __init__(self, *, active=True, rows=None, error=None, tenant='tenant_a'):
        self.active, self.rows, self.error, self.tenant = active, rows, error, tenant
        self.calls = []
        self.cursors = []

    @contextmanager
    def verified_transaction(self, token, readonly=True):
        self.calls.append((token, readonly))
        if self.error is not None:
            raise self.error
        cur = Cursor(active=self.active, rows=self.rows)
        self.cursors.append(cur)
        yield cur, self.tenant, 'ua'


class Writer:
    def __init__(self, result=None, error=None):
        self.result = result if result is not None else {'id': 'mid', 'message_seq': 3, 'replayed': False}
        self.error = error
        self.calls = []

    def send_text(self, **kwargs):
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.result


@pytest.fixture(autouse=True)
def disposable_flags(monkeypatch):
    for key in ('JW_PG_LAB_V43','JW_PG_LAB_V42','JW_PG_LAB_V41','JW_PG_LAB_V40','JW_PG_LAB_V38'):
        monkeypatch.setenv(key,'ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_ALLOW_TEST_WRITES','ONLY_EPHEMERAL_DATABASE')
    monkeypatch.delenv('JW_ENV',raising=False)


def client(adapter=None, writer=None):
    return TestClient(create_lab_app(GOOD, adapter=adapter or Adapter(), writer=writer or Writer()))


@pytest.mark.parametrize('state,expected,code,retry', [
    ('P0001',403,'TENANT_DENIED',None), ('42501',403,'TENANT_DENIED',None),
    ('28000',503,'PG_CONFIGURATION',None), ('28P01',503,'PG_CONFIGURATION',None),
    ('40001',503,'PG_RETRYABLE','2'), ('40P01',503,'PG_RETRYABLE','2'),
    ('55P03',503,'PG_RETRYABLE','2'), ('57014',503,'PG_RETRYABLE','2'),
    ('53300',503,'PG_RETRYABLE','2'), ('57P03',503,'PG_RETRYABLE','2'),
    ('08001',503,'PG_CONNECTION_LOST','5'), ('08006',503,'PG_CONNECTION_LOST','5'),
    ('23505',503,'PG_UNAVAILABLE',None), ('23503',503,'PG_UNAVAILABLE',None),
    ('23514',503,'PG_UNAVAILABLE',None), ('XX000',503,'PG_UNAVAILABLE',None),
    (None,503,'PG_UNAVAILABLE',None),
])
def test_exact_sqlstate_translation(state, expected, code, retry):
    f = classify_database_error(Error(state))
    assert (f.status, f.code, f.retry_after) == (expected, code, retry)
    assert 'private' not in f.detail and 'password' not in f.detail


@pytest.mark.parametrize('error,expected', [
    (ConnectionError('password'), 'PG_CONNECTION_LOST'),
    (TimeoutError('password'), 'PG_CONNECTION_LOST'),
    (ReplayConflict('password'), 'IDEMPOTENCY_CONFLICT'),
    (PostgreSQLUnverified('password'), 'TENANT_DENIED'),
    (LabRefused('password'), 'TENANT_DENIED'),
    (ValueError('password'), 'PG_UNAVAILABLE'),
    (RuntimeError('password'), 'PG_UNAVAILABLE'),
])
def test_python_error_translation(error, expected):
    assert classify_database_error(error).code == expected


@pytest.mark.parametrize('bad', [
    'postgresql://jw_app:synthetic@evil.example/jw_v20_test_abcdef123456',
    'postgresql://postgres:synthetic@127.0.0.1/jw_v20_test_abcdef123456',
    'postgresql://jw_app:synthetic@127.0.0.1/customer',
    'postgresql://jw_app:synthetic@127.0.0.1/jw_v20_test_abcdef123456?sslmode=disable',
])
def test_denies_unsafe_database_before_route_creation(bad):
    with pytest.raises((LabRefused, PostgreSQLUnverified)):
        create_lab_app(bad, adapter=Adapter(), writer=Writer())


def test_denies_missing_flag_and_production(monkeypatch):
    monkeypatch.delenv('JW_PG_LAB_V43')
    with pytest.raises(LabRefused):
        create_lab_app(GOOD, adapter=Adapter(), writer=Writer())
    monkeypatch.setenv('JW_PG_LAB_V43','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(LabRefused):
        create_lab_app(GOOD, adapter=Adapter(), writer=Writer())


def test_read_page_queries_authoritative_thread_and_uses_tenant():
    a = Adapter(rows=[('id1', 3, 'tenant_a', 'ua', 'text', 'safe', 'now'),
                      ('id2', 4, 'tenant_b', 'ub', 'text', 'partner', 'now')])
    with client(adapter=a) as c:
        res = c.get(PATH, params={'limit':1}, headers={'X-JW-Lab-Session':TOKEN})
        assert res.status_code == 200
        payload=res.json()
        assert payload['has_more'] is True and payload['next_after']==3
        assert payload['messages'][0]['mine'] is True
        assert res.headers['cache-control']=='no-store'
        assert res.headers['x-content-type-options']=='nosniff'
    assert len(a.calls)==1 and a.calls[0] == (TOKEN, True)
    assert 'public.messenger_connections' in a.cursors[0].sql[0][0]
    assert a.cursors[0].sql[0][1]==('chat_ab',)
    assert a.cursors[0].sql[1][1]==('chat_ab', 0, 2)
    assert 'sender_user' in a.cursors[0].sql[1][0]


def test_member_without_messages_returns_empty_list():
    with client(adapter=Adapter(rows=[])) as c:
        r=c.get(PATH,headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==200 and r.json()['messages']==[]


def test_missing_or_unrelated_thread_is_404_not_empty_list():
    a=Adapter(active=False)
    with client(adapter=a) as c:
        for method in ('get','post'):
            kw={'json':{'content':'safe','request_id':KEY}} if method=='post' else {}
            r=getattr(c,method)(PATH,headers={'X-JW-Lab-Session':TOKEN},**kw)
            assert r.status_code==404 and r.json()['code']=='THREAD_NOT_FOUND'


def test_send_new_replay_and_no_cookie_fallback():
    a=Adapter(); w=Writer()
    with client(adapter=a,writer=w) as c:
        r=c.post(PATH,json={'content':'a valid message','request_id':KEY},
                 headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==201 and r.json()['message_seq']==3
        assert w.calls[0]['token']==TOKEN
        w.result={'id':'mid','message_seq':3,'replayed':True}
        r=c.post(PATH,json={'content':'a valid message','request_id':KEY},
                 headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==200 and r.json()['replayed'] is True
        r=c.post(PATH,json={'content':'a valid message','request_id':KEY},
                 headers={'Cookie':'jw_local_dev_session='+TOKEN})
        assert r.status_code==401
    assert len(w.calls)==2


@pytest.mark.parametrize('body', [
    {'content':'','request_id':KEY}, {'content':'   ','request_id':KEY},
    {'content':'x'*2001,'request_id':KEY},
    {'content':'hi','request_id':'X'*32},
    {'content':'hi','request_id':KEY,'sender_org':'tenant_b'},
    {'content':'hi','request_id':KEY,'sender_user':'ub'},
])
def test_reject_bad_payload_and_identity_spoof(body):
    with client() as c:
        r=c.post(PATH,json=body,headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==422 and r.json()['code']=='INVALID_INPUT'
        assert body.get('content','') not in r.text if len(body.get('content','')) > 10 else True


@pytest.mark.parametrize('params', [{'after':-1},{'after':9223372036854775808}, {'limit':0},{'limit':101}])
def test_invalid_pagination_is_422(params):
    with client() as c:
        assert c.get(PATH, params=params,headers={'X-JW-Lab-Session':TOKEN}).status_code==422


@pytest.mark.parametrize('token', ['', 'invalid','a'*513])
def test_invalid_header_returns_401(token):
    with client() as c:
        for method in ('get','post'):
            r=getattr(c,method)(PATH,headers={'X-JW-Lab-Session':token},
                **({'json':{'content':'safe','request_id':KEY}} if method=='post' else {}))
            assert r.status_code==401


def test_invalid_thread_and_method():
    with client() as c:
        hdr={'X-JW-Lab-Session':TOKEN}
        assert c.get('/lab43/api/messenger/threads/..../messages',headers=hdr).status_code==422
        assert c.delete(PATH,headers=hdr).status_code==405
        assert c.get('/docs').status_code==404
        assert c.get('/openapi.json').status_code==404


@pytest.mark.parametrize('state,status,code,retry',[
    ('42501',403,'TENANT_DENIED',None),
    ('40001',503,'PG_RETRYABLE','2'),
    ('40P01',503,'PG_RETRYABLE','2'),
    ('08006',503,'PG_CONNECTION_LOST','5'),
    ('23505',503,'PG_UNAVAILABLE',None),
])
def test_http_error_contract_and_no_sensitive_leak(state,status,code,retry):
    a=Adapter(); w=Writer(error=Error(state))
    with client(adapter=a, writer=w) as c:
        r=c.post(PATH,headers={'X-JW-Lab-Session':TOKEN},
                 json={'content':'safe','request_id':KEY})
        assert (r.status_code,r.json()['code'],r.headers.get('retry-after')) == (status,code,retry)
        assert 'password' not in r.text and TOKEN not in r.text
        assert isinstance(r.json()['detail'], str)  # Existing JS error toast
        assert 'postgresql' not in r.text
        assert r.headers['cache-control']=='no-store'


def test_read_session_rejection_and_database_outage_separately():
    with client(adapter=Adapter(error=Error('P0001'))) as c:
        r=c.get(PATH,headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==403 and r.json()['code']=='TENANT_DENIED'
    with client(adapter=Adapter(error=Error('08001'))) as c:
        r=c.get(PATH,headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==503 and r.json()['code']=='PG_CONNECTION_LOST'


@pytest.mark.parametrize('malformed', [
    {'id':None, 'message_seq':1,'replayed':False},
    {'id':'x','message_seq':0,'replayed':False},
    {'id':'x','message_seq':True,'replayed':False},
    {'id':'x','message_seq':1,'replayed':'false'},
])
def test_invalid_commit_evidence_cannot_be_201(malformed):
    with client(writer=Writer(result=malformed)) as c:
        r=c.post(PATH,json={'content':'safe','request_id':KEY}, headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==503 and r.json()['code']=='PG_UNAVAILABLE'


def test_rejects_backend_auth_error_as_outage_not_tenant_forbidden():
    with client(adapter=Adapter(error=Error('28P01'))) as c:
        r=c.get(PATH, headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code == 503
        assert r.json()['code'] == 'PG_CONFIGURATION'
        assert 'private' not in r.text


def test_no_writer_extra_fields_can_be_reflected_in_json():
    sensitive={'id':'mid','message_seq':3,'replayed':False,
               'dsn':'postgresql://internal-secret', 'token':TOKEN}
    with client(writer=Writer(result=sensitive)) as c:
        r=c.post(PATH, json={'content':'safe','request_id':KEY},
                 headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code == 201
        assert r.json() == {'id':'mid','message_seq':3,'replayed':False}
        assert 'internal-secret' not in r.text and TOKEN not in r.text


def test_stops_requests_if_lab_approval_removed_after_startup(monkeypatch):
    with client() as c:
        assert c.get(PATH,headers={'X-JW-Lab-Session':TOKEN}).status_code == 200
        monkeypatch.setenv('JW_ENV','production')
        r=c.get(PATH,headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code == 503 and r.json()['code']=='PG_UNAVAILABLE'
        monkeypatch.delenv('JW_ENV')
        monkeypatch.delenv('JW_PG_ALLOW_TEST_WRITES')
        r=c.post(PATH,json={'content':'safe','request_id':KEY},
                 headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code == 503 and r.json()['code']=='PG_UNAVAILABLE'


def test_simulated_lost_http_response_reuses_same_request_id():
    # An HTTP response may disappear after DB commit. The browser must
    # retry with the original key; a new key could create a duplicate.
    adapter=Adapter()
    writer=Writer()
    request={'content':'safe','request_id':KEY}
    with client(adapter=adapter,writer=writer) as c:
        first=c.post(PATH,json=request,headers={'X-JW-Lab-Session':TOKEN})
        assert first.status_code==201
        writer.result={'id':'mid','message_seq':3,'replayed':True}
        replay=c.post(PATH,json=request,headers={'X-JW-Lab-Session':TOKEN})
        assert replay.status_code==200 and replay.json()['id']==first.json()['id']
        assert writer.calls[0]['request_id']==writer.calls[1]['request_id']==KEY


def test_5xx_error_messages_never_echo_client_input_or_driver_info():
    secret='private-db-password-and-owner-company'
    with client(writer=Writer(error=Error('23503',secret))) as c:
        r=c.post(PATH,json={'content':'safe','request_id':KEY},
                 headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code==503
        assert secret not in r.text
        assert KEY not in r.text


@pytest.mark.parametrize('method', ['get','post'])
def test_content_security_headers_on_auth_and_validation_errors(method):
    with client() as c:
        kw={'json':{'content':'','request_id':KEY}} if method=='post' else {}
        r=getattr(c,method)(PATH,**kw)
        assert r.status_code in (401,422)
        assert r.headers['cache-control']=='no-store'
        assert r.headers['x-content-type-options']=='nosniff'


def test_existing_web_error_message_contract_is_string():
    with client(writer=Writer(error=Error('40001'))) as c:
        r=c.post(PATH,json={'content':'safe','request_id':KEY},headers={'X-JW-Lab-Session':TOKEN})
        assert r.status_code == 503
        assert isinstance(r.json()['detail'],str)
        assert r.json()['code']=='PG_RETRYABLE'
        # Mirrors existing JS: (result.detail || 'failed') -> new Error(message).
        assert '[object Object]' not in r.json()['detail']
