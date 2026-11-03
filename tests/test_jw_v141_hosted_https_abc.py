"""V141 stage-only fixture safety and cookie/DB-session consistency."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from scripts import jw_v141_hosted_https_abc as probe


ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "scripts/review/v141_synthetic_abc_https_seed.sql"
CLEANUP = ROOT / "scripts/review/v141_synthetic_abc_https_cleanup.sql"


def test_v141_cookie_hashes_exactly_match_real_seed_sql():
    sql = SEED.read_text()
    for actor, token in probe._TOKENS.items():
        assert hashlib.sha256(token.encode()).hexdigest() in sql
        assert probe._ORGS[actor] in sql


def test_seed_only_disposable_rows_and_mandatory_empty_database_guard():
    sql = SEED.read_text().lower()
    assert "begin;" in sql and "commit;" in sql
    assert "empty_dev_precondition_failed" in sql
    assert "password_hash" in sql
    assert "synthetic-no-password" in sql
    assert "30 minutes" in sql
    assert "insert into jw_dev.messenger_messages" not in sql
    assert "insert into jw_dev.messenger_attachments" not in sql
    assert "insert into jw_dev.security_events" not in sql
    assert "delete from" not in sql


def test_cleanup_exact_ids_and_no_immutable_trigger_bypass():
    sql = CLEANUP.read_text().lower()
    assert "begin;" in sql and "commit;" in sql
    for table in ("quotes","customers","sessions","users","organizations"):
        assert "delete from jw_dev." + table in sql
    assert "v141_fixture_residual" in sql
    for unsafe in ("disable trigger","alter role","drop table","truncate",
                   "delete from jw_dev.messenger_messages",
                   "delete from jw_dev.messenger_attachments"):
        assert unsafe not in sql


def test_positive_abc_probe_is_disabled_without_exact_stage_optin(monkeypatch):
    monkeypatch.delenv("JW_STAGE1_POSITIVE_HTTPS_PROBE", raising=False)
    assert asyncio.run(probe.check()) == "NOT_RUN_NOT_APPROVED"


def test_positive_abc_probe_has_no_persistent_legitimate_mutation():
    from inspect import getsource
    code = getsource(probe)
    assert ".delete(" not in code
    assert ".put(" not in code
    assert "jw-v141-cb" in code and "X-CSRF-Token" in code
    assert "PASS_HOSTED_HTTPS_ABC_POSITIVE_SESSIONS_RLS_CSRF_WRITE_DENIAL" in code


class FakeResponse:
    def __init__(self, code, obj=None):
        self.status_code = code
        self._obj = obj
    def json(self):
        return self._obj


class FakeClient:
    def __init__(self, leak=False):
        self.leak = leak
        self.events = []
    async def __aenter__(self):
        return self
    async def __aexit__(self, *args):
        pass
    async def get(self, url, headers):
        actor = next((a for a,token in probe._TOKENS.items()
                      if token in headers.get("Cookie","")), None)
        self.events.append(("get", actor, url))
        if "/me" in url:
            return FakeResponse(200,{"org_id":probe._ORGS[actor],
                "csrf_token":"v141-csrf-" + actor + "-12345678901234567890123456789"})
        if "/customers" in url:
            ids=set(probe._CUSTOMERS[actor])
        else:
            ids=set(probe._QUOTES[actor])
        if self.leak and actor=="A" and "/customers" in url:
            ids.add("jw-v141-cb")
        return FakeResponse(200,[{"id":z} for z in ids])
    async def post(self,url,headers,json):
        self.events.append(("post",url))
        return FakeResponse(404 if "X-CSRF-Token" in headers else 403)


def _simulate(monkeypatch,leak):
    monkeypatch.setenv("JW_ENV","dev")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK","V134_STAGE1_PUBLIC_ISOLATED_ONLY")
    monkeypatch.setenv("JW_STAGE1_POSITIVE_HTTPS_PROBE",probe._ACK)
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY","a" * 48)
    fake=FakeClient(leak)
    monkeypatch.setattr(probe.httpx, "AsyncClient",lambda **kw:fake)
    return asyncio.run(probe.check()),fake


def test_positive_abc_contract_and_foreign_write_denial(monkeypatch):
    result,fake=_simulate(monkeypatch,False)
    assert result=="PASS_HOSTED_HTTPS_ABC_POSITIVE_SESSIONS_RLS_CSRF_WRITE_DENIAL"
    assert len([x for x in fake.events if x[0]=="post"])==2


def test_abc_cross_tenant_leak_forces_fail(monkeypatch):
    result,fake=_simulate(monkeypatch,True)
    assert result=="FAIL_CROSS_ORG_CUSTOMER_A"
    assert not any(x[0]=="post" for x in fake.events)
