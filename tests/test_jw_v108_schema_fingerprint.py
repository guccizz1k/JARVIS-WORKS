"""Synthetic unit contracts for V10.8: no real DB credential or DDL required."""
import copy

import pytest
from scripts import jw_v108_schema_fingerprint as a


def test_manifest_contains_counts_only_and_no_sensitive_source_definitions():
    source = a.source_baseline()
    assert len(source) == 11
    assert source["tables"]["n"] == 35
    assert source["columns"]["n"] == 282
    assert source["constraints"]["n"] == 183
    assert source["indexes"]["n"] == 87
    assert source["functions"]["n"] == 28
    assert source["policies"]["n"] == 40
    assert source["triggers"]["n"] == 45
    assert source["forced_rls"]["force_rls"] == 35
    assert all("digest" in v or "force_rls" in v for v in source.values())


def test_no_roles_or_credentials_fail_closed(monkeypatch):
    monkeypatch.setenv("JW_ENV", "review")
    monkeypatch.delenv("JW_RENDER_PG_TRADE_DSN", raising=False)
    monkeypatch.delenv("JW_RENDER_PG_AUTH_DSN", raising=False)
    assert a.verify()["reason"] == "TWO_ROLE_BOUNDARY_NOT_VERIFIED"


def fake_trade_dsn():
    return ("host=dpg-dbeorinavr4c73bke6j0-a port=5432 "
            "dbname=jw_isolated_stage_pg17_20261025 "
            "user=jw_trade_gateway_v90 "
            "password=synthetic-fixture-never-real sslmode=require connect_timeout=5")


def fake_env():
    return {"JW_ENV":"review","JW_RENDER_PG_TRADE_DSN":fake_trade_dsn()}


class Cursor:
    def __init__(self, actual):
        self.actual = actual
        self.key = None
        self.calls = []
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def execute(self, query):
        self.calls.append(query)
        assert query == "SET TRANSACTION READ ONLY" or query in a.QUERIES.values()
        self.key = next((k for k,v in a.QUERIES.items() if v == query),None)
    def fetchone(self):
        assert self.key is not None
        v = self.actual[self.key]
        return (v["n"], v.get("force_rls",v.get("digest")))


class Connection:
    def __init__(self, actual):
        self.cur=Cursor(actual)
        self.rolled=False
        self.closed=False
    def cursor(self):
        return self.cur
    def rollback(self):
        self.rolled=True
    def close(self):
        self.closed=True


def boundary(**_):
    return {"decision":"PASS"}


def test_exact_mocked_metadata_checks_only_and_releases_connection():
    conn=Connection(a.source_baseline())
    result=a.verify(env=fake_env(),connector=lambda dsn,kind:conn,
                    role_boundary=boundary)
    assert result["decision"]=="PASS"
    assert result["reason"]=="METADATA_EQUIVALENT_ONLY"
    assert result["customer_rows_read"] is False
    assert result["migration_executed"] is False
    assert result["tenant_row_isolation"]=="NOT_RUN"
    assert conn.rolled and conn.closed
    assert len(conn.cur.calls)==len(a.QUERIES)+1
    assert all(q.lstrip().upper().startswith(("SELECT","WITH","SET TRANSACTION READ ONLY"))
               for q in conn.cur.calls)


@pytest.mark.parametrize("section",["tables","columns","constraints","indexes",
    "policies","triggers","functions","sequences","table_acl","function_acl","forced_rls"])
def test_single_catalog_section_mismatch_blocks(section):
    modified=copy.deepcopy(a.source_baseline())
    if section=="forced_rls":
        modified[section]["force_rls"]=34
    else:
        modified[section]["digest"]="0"*32
    conn=Connection(modified)
    result=a.verify(env=fake_env(),connector=lambda dsn,kind:conn,role_boundary=boundary)
    assert result["decision"]=="BLOCKED"
    assert result["reason"]=="SCHEMA_FINGERPRINT_MISMATCH"
    assert result["mismatched_sections"]==[section]
    assert conn.rolled and conn.closed


def test_unverified_role_boundary_never_opens_db():
    calls=[]
    result=a.verify(env=fake_env(),
        connector=lambda *a,**k:calls.append(1),
        role_boundary=lambda **kw:{"decision":"BLOCKED"})
    assert result["decision"]=="BLOCKED"
    assert not calls


def test_connection_failure_redacted():
    result=a.verify(env=fake_env(),
        connector=lambda *a,**k:(_ for _ in ()).throw(RuntimeError("secret leak")),
        role_boundary=boundary)
    assert result["decision"]=="BLOCKED"
    assert result["reason"]=="RESTRICTED_DB_UNREACHABLE"
    assert "secret" not in str(result)


def test_invalid_trade_dsn_rejected_after_role_gate():
    result=a.verify(env={"JW_ENV":"review","JW_RENDER_PG_TRADE_DSN":"invalid"},
      connector=lambda *_a,**_k:None,role_boundary=boundary)
    assert result["reason"]=="TRADE_DSN_INVALID"
