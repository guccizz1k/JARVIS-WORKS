"""Review adapter rejects invalid input before making external DB connections."""
import pytest
from app.pg_messenger_review import MessengerReviewAdapter, PostgreSQLUnverified,PG_TEST_DB

adapter=MessengerReviewAdapter('postgresql://jw_app:synthetic-only@127.0.0.1/jw_v20_test_abcdef123456')
def test_disposable_database_name_only():
    assert PG_TEST_DB.fullmatch('jw_v20_test_abcdef123456')
    for name in ['production','jw_v20_test_x','jw_v20_test_abcdef123456_foo','jw_v20_test_ABCDEF123456']:
        assert not PG_TEST_DB.fullmatch(name)

def test_requires_signed_employee_token_before_driver():
    with pytest.raises(PostgreSQLUnverified):
        adapter.list_messages('short','thread')

def test_list_validation_without_server():
    for after,limit in [(-1,50),(0,0),(0,101),('0',50)]:
        with pytest.raises(ValueError):adapter.list_messages('a'*40,'thread',after=after,limit=limit)

def test_message_content_validation():
    for text in ['', '   ','x'*2001]:
        with pytest.raises(ValueError):adapter.send_text('a'*40,'thread',text,'0'*32)

def test_idempotency_key_canonical():
    for key in ['x','0'*31,'G'*32,'0'*33]:
        with pytest.raises(ValueError):adapter.send_text('a'*40,'thread','ok',key)

def test_read_position_validation():
    for v in [-1,'0',None]:
        with pytest.raises(ValueError):adapter.mark_read('a'*40,'thread',v)

def test_production_not_wired_to_pg_adapter():
    from app import main
    import inspect
    assert 'pg_messenger_review' not in inspect.getsource(main)
    assert 'SQLite' in inspect.getsource(main) or 'sqlite3' in inspect.getsource(main)


def test_review_transaction_order_and_identity_binding(monkeypatch):
    import sys
    import types
    seen=[]
    class Cursor:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def execute(self,sql,args=None):
            seen.append((sql,args))
        def fetchone(self):
            query=seen[-1][0]
            if 'current_database()' in query:return ('jw_v20_test_abcdef123456','jw_app')
            if 'server_version_num' in query:return ('170011',)
            if 'current_actor()' in query:return ('tenant_a','employee_a')
            return (True,)
        def fetchall(self):return [('m1',1)]
    class DB:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def cursor(self):return Cursor()
    monkeypatch.setitem(sys.modules,'psycopg',types.SimpleNamespace(connect=lambda *args,**kwargs:DB()))
    assert adapter.list_messages('a'*40,'chat_ab')==[('m1',1)]
    assert seen[0][0]=='SET TRANSACTION READ ONLY'
    assert 'current_database()' in seen[1][0]
    assert "set_config('statement_timeout'" in seen[3][0]
    assert seen[4][1]==('a'*40,)
    assert 'jw_guard.current_actor()' in seen[5][0]
    assert seen[-1][1]==('chat_ab',0,50)


def test_adapter_rejects_wrong_role_and_production_db(monkeypatch):
    import sys
    import types
    from app.pg_messenger_review import PostgreSQLUnverified
    class Cursor:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def execute(self,sql,args=None):pass
        def fetchone(self):return ('production','postgres')
    class DB:
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def cursor(self):return Cursor()
    monkeypatch.setitem(sys.modules,'psycopg',types.SimpleNamespace(connect=lambda *a,**k:DB()))
    with pytest.raises(PostgreSQLUnverified):adapter.list_messages('a'*40,'thread')


def test_refuses_any_non_ephemeral_database_before_network(monkeypatch):
    import sys,types
    opened=[]
    monkeypatch.setitem(sys.modules,'psycopg',types.SimpleNamespace(connect=lambda *a,**k:opened.append(1)))
    for dsn in ['postgresql://jw_app:password@127.0.0.1/production',
                'postgresql://postgres:password@127.0.0.1/jw_v20_test_abcdef123456',
                'postgresql://jw_app:password@example.com/jw_v20_test_abcdef123456',
                'postgresql://jw_app:password@127.0.0.1/jw_v20_test_abcdef123456?dbname=production',
                'postgresql://jw_app@127.0.0.1/jw_v20_test_abcdef123456']:
        with pytest.raises(PostgreSQLUnverified):
            MessengerReviewAdapter(dsn).list_messages('a'*40,'thread')
    assert not opened
