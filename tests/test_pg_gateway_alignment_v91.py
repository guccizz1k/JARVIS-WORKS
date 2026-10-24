"""J1-J6 V9.1: real dev role-alignment regression, test RED before minimal fix.

Mocks solely driver results; live Supabase catalog verification is an additional
read-only independent gate. Never contain passwords or external endpoints.
"""
from __future__ import annotations

from app import pg_connection_gate_v87 as gate
from app import pg_live_dryrun_v88 as drill


class RoleCursor:
    def __init__(self, kind, cfg=None):
        self.kind=kind
        self.cfg=cfg or {}
        self.statement=""
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def execute(self,s,*_):self.statement=s
    def fetchone(self):
        kind=self.kind
        if self.statement==gate.LOGIN_PROBE:
            name="jw_auth_gateway_v90" if kind=="auth" else "jw_trade_gateway_v90"
            return (name,name,False,kind=="auth",kind=="trade",False,True,17,
                    self.cfg.get("canlogin",True))
        if self.statement==gate.ROLE_PROBE:
            return ("jw_auth_stage_v85" if kind=="auth" else "jw_app_dev",
                    False,False,kind=="trade",self.cfg.get("payments_insert",False),
                    kind=="auth",kind=="trade")
        raise AssertionError("Unexpected verification SQL")

class RoleConnection:
    def __init__(self,kind,cfg=None):
        self.cur=RoleCursor(kind,cfg)
        self.closed=False
        self.rolled_back=False
    def cursor(self):return self.cur
    def rollback(self):self.rolled_back=True
    def close(self):self.closed=True


def environment():
    return {"JW_PG_V87_CONNECT_GATE":"ISOLATED_DEV_ONLY",
            "JW_ENV":"dev",
            "JW_PG_AUTH_STAGE_DSN":"synthetic_auth",
            "JW_PG_STAGE_DSN":"synthetic_trade"}


def test_actual_v90_gateway_logins_are_accepted_when_least_privileged():
    dbs=[]
    def connect(dsn,**kw):
        assert kw=={"sslmode":"verify-full","connect_timeout":5}
        d=RoleConnection("auth" if dsn=="synthetic_auth" else "trade")
        dbs.append(d);return d
    out=gate.check_two_connections(connector=connect,env=environment())
    assert out["result"]=="PASS",out
    assert len(dbs)==2 and all(d.closed and d.rolled_back for d in dbs)


def test_nonlogin_role_cannot_be_reported_healthy_even_if_mock_connection_exists():
    def connect(dsn,**kw):
        return RoleConnection("auth" if dsn=="synthetic_auth" else "trade",
                              {"canlogin":False} if dsn=="synthetic_auth" else {})
    out=gate.check_two_connections(connector=connect,env=environment())
    assert out["result"]=="BLOCKED",out


def test_trade_role_direct_payment_insert_remains_denied():
    def connect(dsn,**kw):
        return RoleConnection("auth" if dsn=="synthetic_auth" else "trade",
                              {"payments_insert":True} if dsn=="synthetic_trade" else {})
    assert gate.check_two_connections(connector=connect,env=environment())["result"]=="BLOCKED"


class LockCursor:
    def __init__(self,db):self.db=db;self.last=None
    def __enter__(self):return self
    def __exit__(self,*_):return False
    def execute(self,statement,args=None):
        if "pg_backend_pid()" in statement:
            self.last=(self.db.pid,"jw_app_dev","jw_trade_gateway_v90")
        elif "pg_try_advisory_xact_lock" in statement:
            if args!=(872688,20261023):raise AssertionError("Unexpected lock namespace")
            busy=self.db.pool.held and self.db.pid not in self.db.pool.held
            self.last=(not busy,)
            if not busy:self.db.pool.held.add(self.db.pid)
        else:self.last=None
    def fetchone(self):return self.last

class LockDb:
    def __init__(self,pool,pid):
        self.pool=pool;self.pid=pid
        self.closed=False;self.rolled_back=False
    def cursor(self):return LockCursor(self)
    def rollback(self):self.pool.held.discard(self.pid);self.rolled_back=True
    def close(self):self.closed=True

class Pool:
    def __init__(self):self.held=set();self.items=[]
    def connect(self,dsn,**kw):
        assert dsn=="synthetic_trade"
        assert kw=={"sslmode":"verify-full","connect_timeout":5}
        db=LockDb(self,51+len(self.items));self.items.append(db);return db


def test_v88_real_gateway_account_uses_isolated_lock_and_releases_it(monkeypatch):
    monkeypatch.setattr(drill,"check_two_connections",lambda **_:{"result":"PASS"})
    pool=Pool()
    env={"JW_ENV":"dev","JW_PG_V88_LIVE_GATE":"ISOLATED_DEV_ONLY",
         "JW_PG_STAGE_DSN":"synthetic_trade","JW_PG_AUTH_STAGE_DSN":"synthetic_auth"}
    out=drill.live_gate_v88(connector=pool.connect,env=env)
    assert out["result"]=="PASS",out
    assert out["production_cutover"] is False
    assert out["payment_race_e2e"]=="NOT_RUN"
    assert len(pool.items)==2 and all(x.rolled_back and x.closed for x in pool.items)
    assert not pool.held
