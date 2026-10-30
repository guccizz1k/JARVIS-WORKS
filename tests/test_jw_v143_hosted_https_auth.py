"""Stage2 V143 review-only live auth proof: fixture, cleanup and fail-closed tests."""
from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

from scripts import jw_v143_hosted_https_auth as probe

ROOT = Path(__file__).resolve().parents[1]
SEED = ROOT / "scripts/review/v143_synthetic_auth_https_seed.sql"
CLEAN = ROOT / "scripts/review/v143_synthetic_auth_https_cleanup.sql"


def test_fixture_passwords_are_real_260k_pbkdf2_for_synthetic_account_only():
    s = SEED.read_text()
    import re
    hashes = re.findall(r"pbkdf2_sha256\$260000\$[0-9a-f]{32}\$[0-9a-f]{64}", s)
    assert len(hashes) == 2
    for item in hashes:
        _, rounds, salt, digest = item.split("$")
        assert hashlib.pbkdf2_hmac("sha256", probe.PWD.encode(),bytes.fromhex(salt),
                                  int(rounds)).hex() == digest
    expected_recovery = hashlib.sha256(
        ("jw-recovery-v1:jw-v143-ub:" + probe.RECOVERY).encode("ascii")).hexdigest()
    assert expected_recovery in s
    assert "V143_REQUIRES_EMPTY_ISOLATED_DEV" in s
    for forbidden in ("INSERT INTO jw_dev.messenger_messages",
                      "INSERT INTO jw_dev.messenger_attachments",
                      "DROP TABLE", "TRUNCATE"):
        assert forbidden not in s


def test_cleanup_exact_scope_and_no_role_or_trigger_bypass():
    s = CLEAN.read_text()
    assert "COMMIT;" in s and "V143_AUTH_FIXTURE_NOT_CLEAN" in s
    for name in ("security_events", "login_failures", "sessions",
                 "mfa_recovery_codes", "mfa_credentials", "users", "organizations"):
        assert "DELETE FROM jw_dev." + name in s
    for bad in ("DISABLE TRIGGER", "DROP TABLE", "ALTER ROLE",
                "DELETE FROM jw_dev.messenger_messages",
                "DELETE FROM jw_dev.messenger_attachments"):
        assert bad not in s


def test_probe_optin_and_missing_key_fail_closed(monkeypatch):
    monkeypatch.delenv("JW_STAGE2_AUTH_HTTPS_PROBE", raising=False)
    assert asyncio.run(probe.verify()) == "NOT_RUN_NOT_APPROVED"
    monkeypatch.setenv("JW_STAGE2_AUTH_HTTPS_PROBE", probe.ACK)
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK", "V134_STAGE1_PUBLIC_ISOLATED_ONLY")
    monkeypatch.setenv("JW_ENV", "dev")
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY", "short")
    assert asyncio.run(probe.verify()) == "BLOCKED_NO_STAGE_KEY"


class Resp:
    def __init__(self, status, body=None, cookie=False):
        self.status_code=status
        self._body=body or {}
        self.headers=({"set-cookie": "__Host-jw_session=synthetic; Path=/; Secure; HttpOnly; SameSite=Strict"}
                      if cookie else {})
    def json(self):
        return self._body


class CookieJar:
    def clear(self):
        pass


class FakeClient:
    def __init__(self, *, leak=False):
        self.actor=None
        self.b_consumed=False
        self.a_revoked=False
        self.events=[]
        self.leak=leak
        self.cookies=CookieJar()
    async def __aenter__(self):
        return self
    async def __aexit__(self, *_):
        return None
    async def post(self, url, json=None, headers=None):
        if url.endswith("/login"):
            actor=json["email"].split("@")[0][-1]
            self.events.append(("login",actor))
            if json["password"] != probe.PWD:
                return Resp(401)
            if actor=="a":
                self.actor="a"
                return Resp(200,{"backend":"postgresql_auth_stage","csrf_token":"z"*40},True)
            code=json.get("recovery_code","")
            if actor=="b" and code==probe.RECOVERY and not self.b_consumed:
                self.b_consumed=True
                self.actor="b"
                return Resp(200,{"backend":"postgresql_auth_stage","csrf_token":"z"*40},True)
            return Resp(401)
        assert url.endswith("/logout")
        self.events.append(("logout",self.actor))
        if not self.actor:
            return Resp(401)
        if headers.get("X-CSRF-Token")!="z"*40:
            return Resp(403)
        self.actor=None
        self.a_revoked=True
        return Resp(200)
    async def get(self,url):
        assert url.endswith("/me")
        self.events.append(("me",self.actor))
        if not self.actor or self.leak:
            return Resp(401)
        return Resp(200,{"org_id":"jw-v143-org"+self.actor})


def _mock(monkeypatch, leak=False):
    monkeypatch.setenv("JW_ENV","dev")
    monkeypatch.setenv("JW_STAGE1_PUBLIC_ACK","V134_STAGE1_PUBLIC_ISOLATED_ONLY")
    monkeypatch.setenv("JW_STAGE2_AUTH_HTTPS_PROBE",probe.ACK)
    monkeypatch.setenv("JW_STAGE1_ACCESS_KEY","synthetic-stage-gate-key-abcdefghijklmnopqrstuvwxyz1234")
    fake=FakeClient(leak=leak)
    monkeypatch.setattr(probe.httpx,"AsyncClient",lambda **_:fake)
    return asyncio.run(probe.verify()),fake


def test_two_account_hosted_auth_contract_and_mfa_one_time(monkeypatch):
    result,fake=_mock(monkeypatch)
    assert result=="PASS_HOSTED_V143_PG_LOGIN_LOGOUT_CSRF_MFA_RECOVERY_REPLAY"
    assert fake.b_consumed and fake.a_revoked
    assert len([evt for evt in fake.events if evt==("login","b")])==4


def test_missing_positive_identity_fails_even_after_successful_login(monkeypatch):
    result,_=_mock(monkeypatch,leak=True)
    assert result=="FAIL_ME_A_401"


def test_probe_isolated_and_no_sensitive_log_reporting():
    from inspect import getsource
    code=getsource(probe)
    assert "STAGE2_HOSTED_AUTH_HTTPS=%s" in code
    assert "LOG.warning" in code
    assert "response.text" not in code and "response.content" not in code
    assert "client.post" in code and "jw-v143" in code
    assert "PASS_HOSTED" in code
