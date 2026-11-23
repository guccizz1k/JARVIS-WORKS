"""Host E2E must fail closed before any network or customer-data operation."""
import pytest
from scripts import ci_v223_render_hosted_e2e as h

def arming():
    return {
        "JW_HOSTED_E2E_ACK": h.ARM,
        "JW_ENV": "review",
        "JW_NO_EXTERNAL_DATABASE": "1",
        "JW_HOSTED_ORIGIN": h.HOST,
        "JW_HOSTED_SERVICE_ID": h.SERVICE,
        "JW_HOSTED_CANDIDATE_SHA": "a"*40,
        "JW_HOSTED_RENDER_LIVE_SHA": "a"*40,
        "JW_HOSTED_RENDER_DEPLOY_STATUS": "live",
        "JW_HOSTED_BASIC_USER": "review_dummy",
        "JW_HOSTED_BASIC_PASSWORD": "Example-very-long-synthetic-basic-access-only",
    }

@pytest.mark.parametrize("wrong,reason", [
    ({"JW_HOSTED_E2E_ACK":""},"HOSTED_MUTATION_NOT_APPROVED"),
    ({"JW_HOSTED_ORIGIN":"https://attacker.invalid"},"HOSTED_ISOLATION_OR_ORIGIN_MISMATCH"),
    ({"JW_ENV":"production"},"HOSTED_ISOLATION_OR_ORIGIN_MISMATCH"),
    ({"JW_HOSTED_SERVICE_ID":"srv-wrong"},"HOSTED_ISOLATION_OR_ORIGIN_MISMATCH"),
    ({"JW_NO_EXTERNAL_DATABASE":"0"},"HOSTED_ISOLATION_OR_ORIGIN_MISMATCH"),
    ({"DATABASE_URL":"postgresql://do-not-use.invalid"},"SOURCE_OR_PRODUCTION_CREDENTIAL_PRESENT"),
    ({"JW_PG_BACKUP_KEY":"never-use-source-key"},"SOURCE_OR_PRODUCTION_CREDENTIAL_PRESENT"),
    ({"JW_HOSTED_RENDER_LIVE_SHA":"b"*40},"EXACT_LIVE_DEPLOY_SHA_NOT_ATTESTED"),
    ({"JW_HOSTED_CANDIDATE_SHA":"no-sha"},"EXACT_LIVE_DEPLOY_SHA_NOT_ATTESTED"),
    ({"JW_HOSTED_RENDER_DEPLOY_STATUS":"building"},"RENDER_LIVE_DEPLOY_STATUS_NOT_ATTESTED"),
    ({"JW_HOSTED_BASIC_PASSWORD":"Demo!2026secure"},"SCOPED_REVIEW_BASIC_AUTH_UNAVAILABLE"),
    ({"JW_HOSTED_BASIC_PASSWORD":""},"SCOPED_REVIEW_BASIC_AUTH_UNAVAILABLE"),
])
def test_mutation_arms_fail_closed(wrong,reason):
    env=arming()
    env.update(wrong)
    assert h.preflight(env)==("BLOCKED",reason)


def test_old_live_render_sha_must_not_be_used_as_current_review():
    env=arming()
    env["JW_HOSTED_CANDIDATE_SHA"] = env["JW_HOSTED_RENDER_LIVE_SHA"] = (
        "16b06a8da738de1129382cafc10e2b4b5004c424")
    assert h.preflight(env)==(
        "BLOCKED","EXACT_LIVE_DEPLOY_SHA_NOT_ATTESTED")


def test_preflight_reports_only_bounded_codes_and_not_secret_contents():
    env=arming()
    env["DATABASE_URL"]="postgresql://private:pass@invalid/private"
    report=str(h.preflight(env))
    assert "private" not in report.lower()
    assert "pass@" not in report
    assert h.HOST.startswith("https://")
    assert h.preflight(arming())==(
        "READY","HOSTED_PRECHECK_ASSERTED_METADATA_ONLY")


def test_diagnostic_and_default_never_execute_mutation(monkeypatch,capsys):
    monkeypatch.delenv("JW_HOSTED_E2E_ACK",raising=False)
    assert h.main([])==2
    assert h.main(["diagnose"])==1
    captured=capsys.readouterr().out
    assert "NOT_RUN" in captured and "release_ready" in captured
    assert "PASS_SYNTHETIC_BUSINESS_FLOW" not in captured


def test_run_with_no_approval_never_imports_or_creates_http_client(monkeypatch):
    monkeypatch.delenv("JW_HOSTED_E2E_ACK",raising=False)
    result=h.run()
    assert result["hosted_trade_e2e"]=="NOT_RUN"
    assert result["release_ready"] is False


def test_run_with_synthetically_armed_env_still_does_not_certify_release(monkeypatch):
    env=arming()
    for key,value in env.items():
        monkeypatch.setenv(key,value)
    # Prove a transport error cannot reveal a credential or claim success.
    import httpx
    def refused_client(*_args,**_kwargs):
        raise RuntimeError("private-auth-should-never-be-printed")
    monkeypatch.setattr(httpx,"Client",refused_client)
    result=h.run()
    assert result["hosted_trade_e2e"]=="FAIL_OR_BLOCKED"
    assert result["reason"]=="HOSTED_E2E_FAIL_CLOSED_REVIEW_ONLY"
    assert "private-auth" not in str(result)
    assert result["release_ready"] is False
