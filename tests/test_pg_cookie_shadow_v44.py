"""V4.4 isolated end-to-end HTTP contract: no production DB or external API."""
import contextlib
import sqlite3
from dataclasses import replace

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

from app import pg_cookie_shadow_v44 as v44

T = 'a' * 32
USER = {'org_id': 'web_a', 'id': 'web_user_a'}


class Cursor:
    def __init__(self, adapter):
        self.a = adapter
        self.step = ''
    def execute(self, sql, args):
        assert isinstance(args, tuple)
        assert '%s' in sql
        self.step = 'connection' if 'messenger_connections' in sql else 'messages'
        self.a.queries.append((sql,args))
    def fetchone(self):
        return (1,) if self.a.thread_exists else None
    def fetchall(self):
        return self.a.rows


class Adapter:
    def __init__(self):
        self.pg_org = 'pg_a'
        self.pg_actor = 'pg_ua'
        self.thread_exists = True
        self.rows = [('m1',1,'pg_a','text','hello','pg_ua'),
                     ('m2',2,'pg_b','text','world','pg_ub')]
        self.queries = []
        self.readonly = []
        self.tokens = []
        self.fail = None
    def _check_dsn(self):
        pass
    @contextlib.contextmanager
    def verified_transaction(self, token, *, readonly):
        self.readonly.append(readonly)
        self.tokens.append(token)
        if self.fail: raise self.fail
        yield Cursor(self), self.pg_org, self.pg_actor


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(v44, '_gate', lambda dsn: None)
    db = tmp_path/'site.db'
    connection = sqlite3.connect(str(db))
    connection.executescript('''
      CREATE TABLE messenger_connections(id TEXT,org_a TEXT,org_b TEXT,status TEXT);
      CREATE TABLE messenger_companies(org_id TEXT);
      CREATE TABLE messenger_messages(id TEXT,message_seq INTEGER,connection_id TEXT,
                 sender_org TEXT,kind TEXT,body TEXT,sender_user TEXT);
      INSERT INTO messenger_connections VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','web_a','web_b','active');
      INSERT INTO messenger_companies VALUES ('web_a'),('web_b');
      INSERT INTO messenger_messages VALUES ('m1',1,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','web_a','text','hello','web_user_a');
      INSERT INTO messenger_messages VALUES ('m2',2,'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','web_b','text','world','web_user_b');
    ''')
    connection.commit()
    connection.close()
    @contextlib.contextmanager
    def sqlite_conn():
        con = sqlite3.connect(str(db),check_same_thread=False)
        try: yield con
        finally: con.close()
    def website_auth(req: Request):
        if req.cookies.get('jw_local_dev_session') != 'cookie_authenticated':
            raise HTTPException(401,detail='Login required')
        return USER.copy()
    adapter=Adapter()
    binding=v44.ReviewBinding('web_a','web_user_a','pg_a','pg_ua','chat_ab',
            'secret' * 12,(('pg_a','web_a'),('pg_b','web_b')),
            (('pg_ua','web_user_a'),('pg_ub','web_user_b')))
    holder={'binding':binding,'calls':[]}
    def broker(org,user,thread):
        holder['calls'].append((org,user,thread))
        return holder['binding']
    app=v44.create_review_app(dsn='fake',adapter=adapter,sqlite_conn=sqlite_conn,
                               trusted_broker=broker,website_current_user=website_auth)
    client=TestClient(app,raise_server_exceptions=False)
    client.cookies.set('jw_local_dev_session','cookie_authenticated')
    return client,adapter,holder,db


def get(env,thread=T,**kwargs):
    return env[0].get('/lab44/threads/'+thread+'/shadow',**kwargs)


def test_exact_nonempty_matches_only_with_authorized_cookie_and_db_context(env):
    r=get(env)
    assert r.status_code==200 and r.json()=={
        'status':'MATCH','text_row_parity':True,'cutover_approved':False,
        'sqlite_count':2,'postgres_count':2}
    assert env[1].readonly == [True]
    assert env[1].tokens == ['secret'*12]
    assert env[2]['calls']==[('web_a','web_user_a',T)]
    assert 'no-store'==r.headers['Cache-Control']
    assert 'nosniff'==r.headers['X-Content-Type-Options']
    assert 'secret' not in r.text and 'hello' not in r.text


def test_missing_cookie_fails_before_broker_or_sqlite(env):
    client,adapter,holder,db=env
    client.cookies.clear()
    r=get(env)
    assert r.status_code == 401
    assert holder['calls']==[] and adapter.queries==[]


def test_session_from_client_header_is_ignored(env):
    client,adapter,holder,db=env
    client.cookies.clear()
    r=get(env,headers={'X-JW-Lab-Session':'secret'*12,'X-Org-Id':'web_a'})
    assert r.status_code==401 and holder['calls']==[]


def test_post_does_not_offer_a_write_path(env):
    r=env[0].post('/lab44/threads/'+T+'/shadow',json={'body':'hello'})
    assert r.status_code==405 and env[1].queries==[]

@pytest.mark.parametrize('bad', ['', 'not-thread','b'*31, 'x'*32, '../'+T])
def test_rejects_invalid_thread_before_db(env,bad):
    r=get(env,bad)
    assert r.status_code in (404,422)
    assert env[1].queries==[]


def test_other_tenant_sees_404_not_counts(env):
    env[2]['binding'] = replace(env[2]['binding'],source_org='web_c')
    # Real site user must be authorized in SQLite first: no broker called.
    r=get(env,thread='b'*32)
    assert r.status_code==404
    assert 'messages' not in r.text and env[2]['calls']==[]


def test_inactive_thread_fails_before_pg(env):
    import sqlite3
    db=sqlite3.connect(env[3]);db.execute("UPDATE messenger_connections SET status='pending'");db.commit();db.close()
    r=get(env)
    assert r.status_code==404 and env[2]['calls']==[]


def test_unverified_company_fails_before_pg(env):
    import sqlite3
    db=sqlite3.connect(env[3]);db.execute("DELETE FROM messenger_companies WHERE org_id='web_b'");db.commit();db.close()
    r=get(env)
    assert r.status_code==404 and env[2]['calls']==[]


@pytest.mark.parametrize('change',[
    {'source_org':'web_other'}, {'source_user':'web_other'},
    {'pg_token':'too-short'}, {'pg_org':''},
    {'pg_to_source_org':(('pg_a','web_b'),('pg_b','web_a'))},
    {'pg_to_source_org':(('pg_a','web_a'),('pg_a','web_b'))},
    {'pg_to_source_user':(('pg_ua','nobody'),('pg_ub','web_user_b'))},
])
def test_rejects_spoofed_or_malformed_binding(env, change):
    env[2]['binding']=replace(env[2]['binding'],**change)
    r=get(env)
    assert r.status_code==403 and r.json()['code']=='BINDING_DENIED'
    assert env[1].queries==[]


@pytest.mark.parametrize('wrong', [('pg_org','pg_b'),('pg_actor','pg_ub')])
def test_pinned_pg_tenant_and_employee_must_match_database(env, wrong):
    setattr(env[1],wrong[0],wrong[1])
    r=get(env)
    assert r.status_code==403 and env[1].readonly==[True]
    assert r.json()['code']=='BINDING_DENIED'


def test_pg_rls_denied_thread_no_data(env):
    env[1].thread_exists=False
    r=get(env)
    assert r.status_code==404 and r.json()['code']=='THREAD_NOT_FOUND'


def test_pg_database_failure_safe_503_no_secret(env):
    env[1].fail=RuntimeError('password=topsecret postgresql://localhost/test')
    r=get(env)
    assert r.status_code==503 and r.json()['code']=='PG_UNAVAILABLE'
    assert 'topsecret' not in r.text and 'postgresql://' not in r.text


def test_missing_or_wrong_row_is_mismatch_not_match(env):
    env[1].rows.pop()
    r=get(env)
    assert r.status_code==200 and r.json()['status']=='MISMATCH'
    assert r.json()['text_row_parity'] is False


def test_changed_message_body_mismatches(env):
    env[1].rows[0]=('m1',1,'pg_a','text','tampered','pg_ua')
    assert get(env).json()['status']=='MISMATCH'


def test_wrong_author_or_company_mapping_is_incompatible(env):
    env[1].rows[0]=('m1',1,'pg_other','text','hello','pg_ua')
    assert get(env).json()['status']=='UNSUPPORTED'


def test_attachments_never_certified_by_text_shadow(env):
    env[1].rows[0]=('m1',1,'pg_a','text','첨부파일: proof.pdf','pg_ua')
    assert get(env).json()['status']=='UNSUPPORTED'


def test_empty_both_not_certified(env):
    con=sqlite3.connect(env[3]);con.execute('DELETE FROM messenger_messages');con.commit();con.close()
    env[1].rows=[]
    assert get(env).json()=={'status':'EMPTY_UNVERIFIED','text_row_parity':False,'cutover_approved':False,
                             'sqlite_count':0,'postgres_count':0}


def test_limit_is_inconclusive_not_match(env):
    env[1].rows=[('m'+str(i),i+1,'pg_a','text','hi','pg_ua') for i in range(201)]
    r=get(env)
    assert r.json()['status']=='INCOMPLETE' and not r.json()['text_row_parity']


def test_invalid_sql_row_must_fail_safe(env):
    env[1].rows=[('m1', True, 'pg_a','text','hello','pg_ua')]
    r=get(env)
    assert r.status_code==503 and 'Unsupported' not in r.text


def test_feature_flag_rechecked_per_request(env,monkeypatch):
    def disabled(*args,**kwargs):raise RuntimeError('off')
    monkeypatch.setattr(v44,'_gate',disabled)
    r=get(env)
    assert r.status_code==503 and env[1].queries==[]


def test_website_principal_must_be_dict(env):
    from fastapi import HTTPException
    def wrong(request):return {'org_id':'web_a'}
    # Coverage of pure guard, not a TestClient dependency override.
    with pytest.raises(v44.ReviewFault):
        v44._mapping({'org_id':'web_a'},env[2]['binding'])


def test_gate_never_allows_production(monkeypatch):
    monkeypatch.setenv('JW_ENV','production')
    monkeypatch.setenv('JW_PG_LAB_V44','ONLY_DISPOSABLE_LAB')
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    with pytest.raises(RuntimeError):v44._gate('postgresql://x')


def test_main_web_routes_are_not_mounted_by_module(env):
    paths={route.path for route in env[0].app.routes}
    assert not any(p.startswith('/api/') for p in paths)
    assert '/lab44/threads/{thread}/shadow' in paths


def test_message_sequence_mismatch_cannot_pass_shadow(env):
    env[1].rows[0] = ('m1', 900, 'pg_a','text','hello','pg_ua')
    assert get(env).json()['status'] == 'MISMATCH'


def test_no_production_approval_even_with_exact_match(env):
    report = get(env).json()
    assert report['text_row_parity'] is True
    assert report['cutover_approved'] is False
