"""Synthetic unit proof for the real-connection readiness check: no network."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types

import pytest


class FakeCursor:
    def __init__(self, login, member, *, superuser=False, forced=35):
        self.login = login
        self.member = member
        self.superuser = superuser
        self.forced = forced
        self.sqls = []
        self.current_role = login

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql):
        self.sqls.append(sql)
        if sql.startswith("SET LOCAL ROLE "):
            self.current_role = sql.removeprefix("SET LOCAL ROLE ")

    def fetchone(self):
        sql = self.sqls[-1]
        if "pg_catalog.pg_roles" in sql:
            return (self.login, "postgres", 170006, self.superuser,
                    False, False, False, self.member[0], self.member[1])
        if sql == "SELECT current_user":
            return (self.current_role,)
        if "pg_catalog.pg_class" in sql:
            return (35, self.forced)
        raise AssertionError("Unexpected SQL")


class FakeConnection:
    def __init__(self, cursor):
        self.fake_cursor = cursor
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def cursor(self):
        return self.fake_cursor


def _load(monkeypatch, *, trade_member=(True, False), auth_member=(False, True),
          trade_superuser=False, trade_rls=35, break_connect=False):
    m_app = types.ModuleType("app")
    m_trade = types.ModuleType("app.pg_api_v84")
    m_auth = types.ModuleType("app.pg_auth_v85")
    tc = FakeCursor("jw_stage1_trade_20261030", trade_member,
                    superuser=trade_superuser, forced=trade_rls)
    ac = FakeCursor("jw_stage1_auth_20261030", auth_member)
    def fail():
        raise RuntimeError("Do not leak connection secrets")
    m_trade._connect = (fail if break_connect else lambda: FakeConnection(tc))
    m_auth._connect = lambda: FakeConnection(ac)
    m_app.pg_api_v84 = m_trade
    m_app.pg_auth_v85 = m_auth
    for name,mod in (("app",m_app),("app.pg_api_v84",m_trade),
                     ("app.pg_auth_v85",m_auth)):
        monkeypatch.setitem(sys.modules,name,mod)
    path = Path(__file__).parents[1] / "scripts" / "jw_v135_stage_connection_probe.py"
    spec = importlib.util.spec_from_file_location("_review_pg_probe",path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module,tc,ac


def test_probes_separate_real_principals_and_forced_rls(monkeypatch):
    module,tc,ac = _load(monkeypatch)
    assert module.verify() == (True,"BOTH_SEPARATE_REAL_ROLE_CONNECTIONS")
    assert tc.sqls[0] == ac.sqls[0] == "SET TRANSACTION READ ONLY"
    assert "SET LOCAL ROLE jw_app_dev" in tc.sqls
    assert "SET LOCAL ROLE jw_auth_stage_v85" in ac.sqls
    assert all("password" not in x.lower() for x in tc.sqls + ac.sqls)


@pytest.mark.parametrize("kwargs,reason",[
    ({"trade_member":(True,True)},"TRADE_LOGIN_ROLE_OR_MEMBERSHIP"),
    ({"auth_member":(True,True)},"AUTH_LOGIN_ROLE_OR_MEMBERSHIP"),
    ({"trade_superuser":True},"TRADE_LOGIN_ROLE_OR_MEMBERSHIP"),
    ({"trade_rls":34},"TRADE_FORCED_RLS_CATALOG"),
    ({"break_connect":True},"TRADE_TLS_CONNECT_OR_QUERY"),
])
def test_negative_probes_fail_closed_without_secrets(monkeypatch,kwargs,reason):
    module,_,_ = _load(monkeypatch,**kwargs)
    assert module.verify() == (False,reason)
