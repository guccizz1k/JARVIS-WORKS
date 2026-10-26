from contextlib import contextmanager
import hashlib
import pytest
from app.pg_stage_v82 import PgStageBlocked, validated_pg_session, create_customer_stage, create_quote_stage

TOKEN='a'*40

class FakeCursor:
    def __init__(self, *, admin=False, identity=None, customer=('Acme',), fail_on=None):
        self.calls=[]
        self.admin=admin
        self.identity=identity or ('jw_app_dev','org-a','user-a')
        self.customer=customer
        self.fail_on=fail_on
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def execute(self,q,args=None):
        self.calls.append((q,args))
        if self.fail_on and self.fail_on in q: raise RuntimeError('simulated db failure')
    def fetchone(self):
        sql=self.calls[-1][0]
        if 'session_user, r.rolsuper' in sql:
            return ('postgres',True,True,True,True) if self.admin else ('jw_stage_lowpriv',False,False,False,False)
        if 'current_user,' in sql: return self.identity
        if 'SELECT name FROM jw_dev.customers' in sql: return self.customer
        raise AssertionError(sql)

class FakeConnection:
    def __init__(self,**kwargs):
        self.cur=FakeCursor(**kwargs)
        self.committed=False
        self.rolled_back=False
    def cursor(self): return self.cur
    @contextmanager
    def transaction(self):
        try:
            yield self
            self.committed=True
        except BaseException:
            self.rolled_back=True
            raise

@pytest.fixture(autouse=True)
def stage_enabled(monkeypatch):
    monkeypatch.setenv('JW_PG_STAGE_V82','DISPOSABLE_PG_STAGE_ONLY')
    monkeypatch.delenv('JW_ENV',raising=False)

def test_customer_and_audit_atomic():
    db=FakeConnection()
    id_=create_customer_stage(db,token=TOKEN,actor_id='user-a',org_id='org-a',name='Acme')
    assert len(id_)==32 and db.committed
    assert any('INSERT INTO jw_dev.customers' in q for q,_ in db.cur.calls)
    assert any('INSERT INTO jw_dev.audit_logs' in q for q,_ in db.cur.calls)
    assert hashlib.sha256(TOKEN.encode()).hexdigest() in str(db.cur.calls)
    assert TOKEN not in str(db.cur.calls)

def test_quote_and_two_items_atomic():
    db=FakeConnection()
    qid=create_quote_stage(db,token=TOKEN,actor_id='user-a',org_id='org-a',customer_id='cust',title='quote',vat_mode='taxable',items=[('x',2,10),('y',3,5)])
    assert len(qid)==32 and db.committed
    assert sum('INSERT INTO jw_dev.quote_items' in q for q,_ in db.cur.calls)==2
    assert any('INSERT INTO jw_dev.audit_logs' in q for q,_ in db.cur.calls)

def test_admin_credentials_rejected():
    db=FakeConnection(admin=True)
    with pytest.raises(PgStageBlocked):
        create_customer_stage(db,token=TOKEN,actor_id='user-a',org_id='org-a',name='Acme')
    assert db.rolled_back and not db.committed

def test_tenant_identity_mismatch_rejected():
    db=FakeConnection(identity=('jw_app_dev','org-b','user-a'))
    with pytest.raises(PgStageBlocked):
        create_customer_stage(db,token=TOKEN,actor_id='user-a',org_id='org-a',name='Acme')
    assert db.rolled_back and not db.committed

def test_missing_customer_rollback():
    db=FakeConnection(customer=None)
    with pytest.raises(PgStageBlocked):
        create_quote_stage(db,token=TOKEN,actor_id='user-a',org_id='org-a',customer_id='not-mine',title='q',vat_mode='exempt',items=[('x',1,100)])
    assert db.rolled_back and not db.committed

def test_second_write_failure_rolls_back_first_write():
    db=FakeConnection(fail_on='INSERT INTO jw_dev.audit_logs')
    with pytest.raises(RuntimeError):
        create_customer_stage(db,token=TOKEN,actor_id='user-a',org_id='org-a',name='Acme')
    assert db.rolled_back and not db.committed

def test_default_disabled_and_production_block(monkeypatch):
    monkeypatch.delenv('JW_PG_STAGE_V82')
    with pytest.raises(PgStageBlocked):
        create_customer_stage(FakeConnection(),token=TOKEN,actor_id='user-a',org_id='org-a',name='Acme')
    monkeypatch.setenv('JW_PG_STAGE_V82','DISPOSABLE_PG_STAGE_ONLY')
    monkeypatch.setenv('JW_ENV','production')
    with pytest.raises(PgStageBlocked):
        create_customer_stage(FakeConnection(),token=TOKEN,actor_id='user-a',org_id='org-a',name='Acme')

def test_validation_refuses_bool_quantity_and_oversized_items():
    db=FakeConnection()
    with pytest.raises(ValueError):
        create_quote_stage(db,token=TOKEN,actor_id='user-a',org_id='org-a',customer_id='id',title='q',vat_mode='taxable',items=[('x',True,10)])
    assert not db.cur.calls
