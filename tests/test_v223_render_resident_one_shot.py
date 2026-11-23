"""Fail-closed hosted self-test gates; never contact Render in CI."""
import asyncio
import logging
import pytest

from app import owner_review_hosted_one_shot_v223 as resident
from scripts import ci_v223_render_hosted_e2e as harness

SHA = "a" * 40


def env():
    return {
        "JW_HOSTED_E2E_ACK": harness.ARM,
        "JW_HOSTED_EXPECTED_SHA": SHA,
        "RENDER": "true",
        "RENDER_SERVICE_ID": harness.SERVICE,
        "RENDER_EXTERNAL_URL": harness.HOST,
        "RENDER_GIT_BRANCH": resident.BRANCH,
        "RENDER_GIT_COMMIT": SHA,
        "JW_PUBLIC_QA_MODE": "1",
        "JW_ENV": "review",
        "JW_ROOT_UI": "owner-visual-review",
        "JW_APPROVED_UI_REVIEW": "ISOLATED_REVIEW_ONLY",
        "JW_NO_EXTERNAL_DATABASE": "1",
        "DEMO_SEED": "1",
        "JARVIS_DB_PATH": "/tmp/jw-v223-qa-residenttest123.sqlite3",
        "JW_REVIEW_BASIC_USER": "qa-review",
        "JW_REVIEW_BASIC_PASSWORD": "synthetic-strong-basicauth-ONLY-testing",
    }


@pytest.mark.parametrize(("key","value","reason"),[
    ("JW_HOSTED_E2E_ACK", "", "DISABLED_NO_OPERATOR_ACK"),
    ("RENDER", "", "BLOCKED_WRONG_RENDER_SERVICE"),
    ("RENDER_SERVICE_ID", "srv-foreign", "BLOCKED_WRONG_RENDER_SERVICE"),
    ("RENDER_EXTERNAL_URL", "https://attacker.invalid", "BLOCKED_WRONG_RENDER_SERVICE"),
    ("RENDER_GIT_BRANCH", "main", "BLOCKED_WRONG_RENDER_SERVICE"),
    ("RENDER_GIT_COMMIT", "b"*40, "BLOCKED_UNATTESTED_DEPLOY_SHA"),
    ("JW_HOSTED_EXPECTED_SHA", "not-a-sha", "BLOCKED_UNATTESTED_DEPLOY_SHA"),
    ("JW_PUBLIC_QA_MODE", "", "BLOCKED_PUBLIC_QA_DISABLED"),
    ("JARVIS_DB_PATH", "/opt/render/project/src/data/works.db", "BLOCKED_PUBLIC_QA_ISOLATION"),
    ("DATABASE_URL", "postgresql://prod.invalid/private", "BLOCKED_PUBLIC_QA_ISOLATION"),
    ("JW_PG_BACKUP_KEY", "restricted", "BLOCKED_PUBLIC_QA_ISOLATION"),
    ("JW_REVIEW_BASIC_PASSWORD", "short", "BLOCKED_PUBLIC_QA_ISOLATION"),
])
def test_reject_unsafe_configuration(key,value,reason):
    e=env()
    e[key]=value
    scoped, code=resident.preflight(e)
    assert scoped is None
    assert code==reason


def test_scoped_credentials_reused_in_process_without_untrusted_addresses():
    e=env()
    scoped, code=resident.preflight(e)
    assert code=="READY_SCOPED_RENDER_CREDENTIALS"
    assert scoped["JW_HOSTED_BASIC_USER"]==e["JW_REVIEW_BASIC_USER"]
    assert scoped["JW_HOSTED_BASIC_PASSWORD"]==e["JW_REVIEW_BASIC_PASSWORD"]
    assert scoped["JW_HOSTED_ORIGIN"]==harness.HOST
    assert harness.preflight(scoped)[0]=="READY"
    assert resident.ENV_SHA not in scoped.values()


def test_direct_runner_rejects_runtime_sha_spoofing():
    e=env()
    scoped,_=resident.preflight(e)
    scoped["RENDER_GIT_COMMIT"]="b"*40
    assert harness.preflight(scoped)==(
        "BLOCKED","RENDER_RUNTIME_IDENTITY_MISMATCH")


def test_opt_in_disabled_never_schedules_task(monkeypatch):
    monkeypatch.delenv("JW_HOSTED_E2E_ACK",raising=False)
    assert resident.schedule() is None


def test_one_shot_preflight_decline_never_contacts_network(monkeypatch,caplog):
    e=env()
    e["RENDER_GIT_COMMIT"]="b"*40
    def must_not_run(*args,**kwargs):
        raise AssertionError("an unapproved request was attempted")
    monkeypatch.setattr(harness,"run",must_not_run)
    with caplog.at_level(logging.WARNING):
        result=asyncio.run(resident.execute_once(e,sleeping=0))
    assert result["status"]=="NOT_RUN"
    assert result["reason"]=="BLOCKED_UNATTESTED_DEPLOY_SHA"
    assert "synthetic-strong-basicauth" not in caplog.text
    assert "postgresql://" not in caplog.text


def test_no_public_endpoint_was_added():
    from app.owner_review_app_v223 import app
    assert not any("/e2e" in r.path for r in app.routes if hasattr(r,"path"))
