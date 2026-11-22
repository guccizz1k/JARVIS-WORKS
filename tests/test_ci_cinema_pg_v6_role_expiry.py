from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import patch
import sys
import pytest

from scripts import ci_cinema_pg_v6_role_expiry as r

class FakeConn:
    def __init__(self):
        self.sql=[]
    def __enter__(self): return self
    def __exit__(self,*a): return False
    def transaction(self): return nullcontext()
    def execute(self,sql,*args):
        self.sql.append(sql)
        return self

def test_safe_attribute_guard_rejects_login():
    class Catalog:
        def execute(self,sql):
            self.sql=sql
            return self
        def fetchone(self):
            if 'current_setting' in self.sql: return ('postgres','postgres',170011)
            if 'rolcanlogin' in self.sql: return (True,False,True,False,False,False,False,2)
            return (0,)
    with pytest.raises(r.RoleBlocked,match='role_attributes_not_safe'):
        r.facts(Catalog())

def test_safe_attribute_guard_rejects_sessions():
    class Catalog:
        def execute(self,sql):
            self.sql=sql
            return self
        def fetchone(self):
            if 'current_setting' in self.sql: return ('postgres','postgres',170011)
            if 'rolcanlogin' in self.sql: return (False,False,True,False,False,False,False,2)
            return (1,)
    with pytest.raises(r.RoleBlocked,match='role_sessions_not_zero'):
        r.facts(Catalog())

def test_restore_expired_updates_only_no_login_validity():
    db=FakeConn()
    fake=SimpleNamespace(connect=lambda *a,**k: db)
    with patch.dict(sys.modules,{'psycopg':fake}), \
         patch.dict('os.environ',{'JW_PG_ADMIN_DSN':'hidden'}), \
         patch.object(r,'facts',side_effect=[False,False,True]):
        assert r.restore_expired()=='EXPIRY_RESTORED'
    writes=[s for s in db.sql if s.startswith('ALTER ROLE')]
    assert len(writes)==1
    assert 'jw_backup_ro NOLOGIN VALID UNTIL' in writes[0]
    assert 'PASSWORD' not in writes[0] and 'GRANT' not in writes[0]

def test_expired_role_remains_unchanged():
    db=FakeConn()
    fake=SimpleNamespace(connect=lambda *a,**k: db)
    with patch.dict(sys.modules,{'psycopg':fake}), \
         patch.dict('os.environ',{'JW_PG_ADMIN_DSN':'hidden'}), \
         patch.object(r,'facts',return_value=True):
        assert r.restore_expired()=='ALREADY_EXPIRED'
    assert not db.sql

def test_role_changed_before_write_is_blocked():
    db=FakeConn()
    fake=SimpleNamespace(connect=lambda *a,**k: db)
    with patch.dict(sys.modules,{'psycopg':fake}), \
         patch.dict('os.environ',{'JW_PG_ADMIN_DSN':'hidden'}), \
         patch.object(r,'facts',side_effect=[False,None]):
        with pytest.raises(r.RoleBlocked,match='role_state_changed'):
            r.restore_expired()
    assert not any(x.startswith('ALTER ROLE') for x in db.sql)
