"""No real PG operations or external connections in this test suite."""
import pytest
from scripts import jw_v113_ephemeral_pg_integration as gate

class NoConnect:
    def connect(self,*args,**kwargs):
        raise AssertionError('preflight unexpectedly connected')

def test_requires_explicit_isolated_ack(monkeypatch):
    monkeypatch.delenv('JW_PG_CI_ALLOW',raising=False)
    with pytest.raises(RuntimeError,match='CI_DISPOSABLE_ACK_REQUIRED'):
        gate._preflight(NoConnect(),lambda d:{},'postgresql://user:fake@localhost/anything')

@pytest.mark.parametrize("change",[
 {'host':'external.example'},
 {'dbname':'business'},
 {'user':'business_admin'},
 {'port':'5433'},
 {'sslmode':'disable'},
 {'connect_timeout':'60'},
 {'host':'localhost'},
])
def test_preflight_rejects_shared_network_and_unsafe_settings(monkeypatch,change):
    monkeypatch.setenv('JW_PG_CI_ALLOW','ONLY_EPHEMERAL_LOCAL_DATABASE')
    info={'host':'127.0.0.1','port':'5432','dbname':'postgres','user':'postgres',
          'connect_timeout':'5'}
    info.update(change)
    with pytest.raises(RuntimeError,match='REFUSE_ANY_NONLOCAL_OR_NONROOT_DATABASE'):
        gate._preflight(NoConnect(),lambda _:info,'fixture')

def test_manual_pg_contract_marks_unrun_live_work():
    import inspect
    source=inspect.getsource(gate._prove)
    assert "2_render_instances':'NOT_RUN'" in source
    assert 'concurrent_skip_locked' in source
    assert 'rollback_no_notify' in source
    assert 'actor_org_check' in source


@pytest.mark.parametrize("bad_index,error_code",[
 (3,"ROOT_DB_HAS_USER_RELATIONS"),
 (4,"ROOT_DB_HAS_USER_FUNCTIONS"),
 (5,"ROOT_DB_HAS_EXTRA_EXTENSIONS"),
])
def test_root_postgres_database_must_have_no_user_objects(monkeypatch,bad_index,error_code):
    monkeypatch.setenv("JW_PG_CI_ALLOW","ONLY_EPHEMERAL_LOCAL_DATABASE")
    class Cursor:
        def __init__(self):self.calls=[];self.index=0
        def __enter__(self):return self
        def __exit__(self,*_):return False
        def execute(self,query):self.calls.append(query)
        def fetchone(self):
            values=[17,0,0,0,0,0]
            values[bad_index]=1
            index=self.index;self.index+=1
            return (values[index],)
    class Connection:
        def __init__(self):self.c=Cursor()
        def __enter__(self):return self
        def __exit__(self,*_):return False
        def cursor(self):return self.c
    class MockPg:
        def __init__(self):self.conn=Connection()
        def connect(self,*args,**kwargs):return self.conn
    pg=MockPg()
    options={"host":"127.0.0.1","port":"5432","dbname":"postgres",
             "user":"postgres","connect_timeout":"5"}
    with pytest.raises(RuntimeError,match=error_code):
        gate._preflight(pg,lambda _:options,"synthetic-only")
    assert not any("CREATE ROLE" in q or "DROP DATABASE" in q for q in pg.conn.c.calls)


def test_known_empty_disposable_pg17_readonly_preflight_passes(monkeypatch):
    monkeypatch.setenv("JW_PG_CI_ALLOW","ONLY_EPHEMERAL_LOCAL_DATABASE")
    class Cursor:
        def __init__(self):self.calls=[];self.index=0
        def __enter__(self):return self
        def __exit__(self,*_):return False
        def execute(self,sql):self.calls.append(sql)
        def fetchone(self):
            item=(17,) if self.index==0 else (0,)
            self.index+=1;return item
    class Connection:
        def __init__(self):self.c=Cursor()
        def __enter__(self):return self
        def __exit__(self,*_):return False
        def cursor(self):return self.c
    class MockPg:
        def __init__(self):self.conn=Connection()
        def connect(self,*args,**kwargs):return self.conn
    pg=MockPg()
    opts={"host":"127.0.0.1","port":"5432","dbname":"postgres",
          "user":"postgres","connect_timeout":"5"}
    assert gate._preflight(pg,lambda _:opts,"synthetic-only") is None
    assert len(pg.conn.c.calls)==6
    assert all(query.lstrip().upper().startswith("SELECT") for query in pg.conn.c.calls)
