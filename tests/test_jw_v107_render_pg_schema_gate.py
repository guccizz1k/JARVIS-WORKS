"""Strict negative tests: cannot accidentally promote Render DB without real evidence."""
import os

import pytest

from scripts import jw_v107_render_pg_schema_gate as gate


def fake_dsn(kind="trade", **change):
    d = {
        "host": gate.EXPECTED_HOST,
        "port": "5432",
        "dbname": gate.EXPECTED_DATABASE,
        "user": gate.EXPECTED_USERS[kind],
        "password": "synthetic-ci-password-not-a-secret",
        "sslmode": "require",
        "connect_timeout": "5",
    }
    d.update(change)
    return " ".join(f"{k}={v}" for k,v in d.items())


def env(**values):
    d = {
        "JW_ENV": "review",
        "JW_RENDER_PG_V107_ACK": gate.ACK,
        "JW_RENDER_PG_TRADE_DSN": fake_dsn("trade"),
        "JW_RENDER_PG_AUTH_DSN": fake_dsn("auth"),
    }
    d.update(values)
    return d


@pytest.mark.parametrize("kind,change", [
    ("trade", {"user": "postgres"}),
    ("trade", {"user": "jw_isolated_stage_pg17_20261025_user"}),
    ("trade", {"host": "example.com"}),
    ("trade", {"host": "dpg-dbeorinavr4c73bke6j0-a.evil.org"}),
    ("trade", {"dbname": "postgres"}),
    ("trade", {"port": "5433"}),
    ("trade", {"sslmode": "disable"}),
    ("trade", {"sslmode": "prefer"}),
    ("trade", {"password": "short"}),
    ("auth", {"user": "jw_trade_gateway_v90"}),
    ("auth", {"application_name": "attempted_override"}),
    ("trade", {"connect_timeout": "60"}),
])
def test_restricted_dsn_rejects_wrong_credential_or_network(kind, change):
    assert not gate.valid_dsn(fake_dsn(kind, **change), kind)


def test_valid_private_render_dsns_are_not_equivalent_to_live_verification():
    assert gate.valid_dsn(fake_dsn("trade"), "trade")
    assert gate.valid_dsn(fake_dsn("auth"), "auth")
    result = gate.check(env=env(JW_RENDER_PG_AUTH_DSN=""))
    assert result["decision"] == "BLOCKED"
    assert result["reason"] == "RESTRICTED_SECRET_DSNS_NOT_CONFIGURED"


@pytest.mark.parametrize("change,reason", [
    ({"JW_ENV":"production"}, "REVIEW_MODE_NOT_APPROVED"),
    ({"JW_RENDER_PG_V107_ACK":""}, "REVIEW_MODE_NOT_APPROVED"),
    ({"JW_RELEASE_APPROVED":"true"}, "REVIEW_MODE_NOT_APPROVED"),
    ({"PGPASSWORD":"unexpected"}, "AMBIENT_PG_CREDENTIALS"),
    ({"JW_RENDER_PG_TRADE_DSN":""}, "RESTRICTED_SECRET_DSNS_NOT_CONFIGURED"),
    ({"JW_RENDER_PG_TRADE_DSN":"invalid"}, "RESTRICTED_DSN_BOUNDARY_INVALID"),
    ({"JW_RENDER_PG_AUTH_DSN":fake_dsn("trade")}, "RESTRICTED_DSN_BOUNDARY_INVALID"),
])
def test_review_preflight_fails_closed_without_connector(change, reason):
    called=[]
    def connector(*args, **kwargs):
        called.append((args,kwargs))
        raise RuntimeError("must never be called")
    result=gate.check(env=env(**change),connector=connector)
    assert result["decision"]=="BLOCKED"
    assert result["reason"]==reason
    assert not called
    assert "synthetic-ci-password-not-a-secret" not in str(result)


def test_connection_failure_redacted_and_release_blocked():
    def connector(dsn, *, kind):
        raise RuntimeError("synthetic-ci-password-not-a-secret")
    result=gate.check(env=env(),connector=connector)
    assert result["decision"] == "BLOCKED"
    assert result["reason"] == "PRIVATE_DB_CONNECTION_FAILED"
    assert not result["production_deployed"]
    assert "synthetic-ci-password-not-a-secret" not in str(result)
    assert result["tenant_row_isolation"]=="NOT_RUN"


class Cursor:
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def execute(self,sql,params=None): self.sql=sql
    def fetchone(self): return ("bad",)


class Connection:
    def __init__(self): self.rolled=False; self.closed=False
    def cursor(self): return Cursor()
    def rollback(self): self.rolled=True
    def close(self): self.closed=True


def test_unsafe_real_pg_role_disables_acceptance_and_closes_connection():
    connection=Connection()
    result=gate.check(env=env(),connector=lambda dsn,kind: connection)
    assert result["decision"]=="BLOCKED"
    assert result["reason"]=="LOGIN_ATTRIBUTES_OR_TLS"
    assert connection.rolled and connection.closed


def test_public_transport_probe_rejects_database_credentials(monkeypatch):
    from scripts import jw_v105_render_https_probe as probe
    assert "JW_RENDER_PG_TRADE_DSN" in probe.BANNED
    assert "JW_RENDER_PG_AUTH_DSN" in probe.BANNED
