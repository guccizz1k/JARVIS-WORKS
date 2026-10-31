"""Synthetic unit proof for the real-connection readiness check: no network."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import types

import pytest


class FakeCursor:
    def __init__(self, login, member, *, superuser=False, forced=43,
                 review_forced=5, approval_forced=3, approval_policies=6,
                 writer_can_login=False, direct_insert=False, new_table_write=False):
        self.login = login
        self.member = member
        self.superuser = superuser
        self.forced = forced
        self.review_forced = review_forced
        self.approval_forced = approval_forced
        self.approval_policies = approval_policies
        self.new_table_write = new_table_write
        self.writer_can_login = writer_can_login
        self.direct_insert = direct_insert
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
        if "rolcanlogin, rolbypassrls" in sql:
            return (self.writer_can_login,False)
        if "pg_catalog.pg_roles" in sql:
            return (self.login, "postgres", 170006, self.superuser,
                    False, False, False, self.member[0], self.member[1])
        if sql == "SELECT current_user":
            return (self.current_role,)
        if "pg_catalog.pg_policies" in sql:
            return (self.approval_policies,)
        if "pg_catalog.pg_class" in sql:
            if "order_drafts_v127" in sql:
                return (3, self.approval_forced)
            if "review_signup_requests_v151" in sql:
                return (5, self.review_forced)
            return (43, self.forced)
        if "has_table_privilege" in sql:
            if "jw_dev.order_drafts_v127" in sql:
                return (self.new_table_write, False, False, False, False, False)
            return (self.direct_insert, False, False)
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
          trade_superuser=False, trade_rls=43, auth_rls=43, break_connect=False,
          trade_review_rls=5, auth_review_rls=5,
          trade_approval_rls=3, auth_approval_rls=3,
          trade_approval_policies=6, auth_approval_policies=6,
          writer_can_login=False, direct_insert=False,new_table_write=False):
    m_app = types.ModuleType("app")
    m_trade = types.ModuleType("app.pg_api_v84")
    m_auth = types.ModuleType("app.pg_auth_v85")
    tc = FakeCursor("jw_stage1_trade_20261030", trade_member,
                    superuser=trade_superuser, forced=trade_rls,
                    review_forced=trade_review_rls,
                    approval_forced=trade_approval_rls,
                    approval_policies=trade_approval_policies,
                    writer_can_login=writer_can_login,direct_insert=direct_insert,
                    new_table_write=new_table_write)
    ac = FakeCursor("jw_stage1_auth_20261030", auth_member,
                    forced=auth_rls,review_forced=auth_review_rls,
                    approval_forced=auth_approval_rls,
                    approval_policies=auth_approval_policies,
                    writer_can_login=writer_can_login,
                    direct_insert=direct_insert,new_table_write=new_table_write)
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
    ({"trade_rls":35},"TRADE_FORCED_RLS_CATALOG"),
    ({"trade_rls":40},"TRADE_FORCED_RLS_CATALOG"),
    ({"trade_rls":44},"TRADE_FORCED_RLS_CATALOG"),
    ({"auth_rls":40},"AUTH_FORCED_RLS_CATALOG"),
    ({"trade_approval_rls":2},"TRADE_V170_APPROVAL_FORCED_RLS"),
    ({"auth_approval_rls":2},"AUTH_V170_APPROVAL_FORCED_RLS"),
    ({"trade_approval_policies":5},"TRADE_V170_APPROVAL_POLICIES"),
    ({"auth_approval_policies":5},"AUTH_V170_APPROVAL_POLICIES"),
    ({"new_table_write":True},"TRADE_V170_APPROVAL_PRIVILEGE_ESCALATION"),
    ({"trade_review_rls":4},"TRADE_REVIEW_LEDGER_FORCED_RLS"),
    ({"auth_review_rls":4},"AUTH_REVIEW_LEDGER_FORCED_RLS"),
    ({"writer_can_login":True},"TRADE_WRITER_ROLE_UNSAFE"),
    ({"direct_insert":True},"TRADE_REVIEW_DIRECT_WRITE_GRANT"),
    ({"break_connect":True},"TRADE_PG_CONNECT_OR_QUERY_OTHER"),
])
def test_negative_probes_fail_closed_without_secrets(monkeypatch,kwargs,reason):
    module,_,_ = _load(monkeypatch,**kwargs)
    assert module.verify() == (False,reason)


@pytest.mark.parametrize("error,reason",[
    (RuntimeError("password authentication failed for unspecified principal"), "AUTHENTICATION_REJECTED"),
    (RuntimeError("Tenant or user not found"), "POOLER_USER_REJECTED"),
    (RuntimeError("certificate verify failed"), "TLS_CERTIFICATE"),
    (RuntimeError("connection timed out"), "NETWORK_TIMEOUT"),
    (RuntimeError("connection refused"), "NETWORK_REFUSED"),
    (RuntimeError("could not translate host name"), "DNS_RESOLUTION"),
    (RuntimeError("sensitive-db-secret-value"), "PG_CONNECT_OR_QUERY_OTHER"),
])
def test_connection_exception_classifier_never_echoes_secrets(monkeypatch, error, reason):
    module, _, _ = _load(monkeypatch)
    actual = module._failure_code(error)
    assert actual == reason
    assert "sensitive-db-secret-value" not in actual
