"""Independent Supabase provider-log evidence guard: strict negative tests."""
import copy
import json
import pytest

from scripts import ci_cinema_pg_v6_provider_log_attest as p


@pytest.fixture
def evidence():
    return json.loads(p.EVIDENCE.read_text(encoding="utf-8"))


def test_valid_historical_server_refusal(evidence):
    result=p.verify_snapshot(evidence)
    assert result["sqlstate"]=="28000"
    assert result["server_refusal"]=="explicit_role_login_prohibited"
    assert result["retained_original_verdict"]=="BLOCKED"
    assert result["provider_signed"] is False


@pytest.mark.parametrize("key,value",[
    ("project_id","wrong-project"),
    ("db_name","other"),
    ("pg_version_num",160000),
    ("original_backup_run_sha","0"*40),
    ("original_runner_verdict","PASS"),
    ("cryptographically_provider_signed",True),
])
def test_reject_false_project_version_or_verdict(evidence,key,value):
    copy_=copy.deepcopy(evidence)
    copy_[key]=value
    with pytest.raises(p.ProviderProofBlocked):
        p.verify_snapshot(copy_)


@pytest.mark.parametrize("index,key,value",[
    (1,"sqlstate","08006"),
    (1,"severity","ERROR"),
    (1,"user","postgres"),
    (1,"message","connection timed out"),
    (0,"sqlstate","28000"),
    (0,"message","other"),
])
def test_auth_or_revoke_event_must_be_exact(evidence,index,key,value):
    copy_=copy.deepcopy(evidence)
    copy_["log_events"][index][key]=value
    with pytest.raises(p.ProviderProofBlocked):
        p.verify_snapshot(copy_)


@pytest.mark.parametrize("field,value",[
    ("can_login",True),
    ("password_expired",False),
    ("active_sessions",1),
    ("superuser",True),
    ("connection_limit",100),
])
def test_unclosed_role_cannot_pass(evidence,field,value):
    copy_=copy.deepcopy(evidence)
    copy_["catalog_observation"][field]=value
    with pytest.raises(p.ProviderProofBlocked):
        p.verify_snapshot(copy_)


def test_reject_reverse_ordered_events(evidence):
    evidence["log_events"].reverse()
    with pytest.raises(p.ProviderProofBlocked):
        p.verify_snapshot(evidence)


def test_reject_same_session_for_termination_and_denial(evidence):
    evidence["log_events"][1]["session_id"]=evidence["log_events"][0]["session_id"]
    with pytest.raises(p.ProviderProofBlocked):
        p.verify_snapshot(evidence)


def test_reject_unrelated_or_out_of_window_login(evidence):
    evidence["log_events"][1]["timestamp"]="2026-11-22T14:19:10.000000Z"
    with pytest.raises(p.ProviderProofBlocked):
        p.verify_snapshot(evidence)


def test_reject_unverified_log_source(evidence):
    evidence["source"]="User-provided freeform text"
    with pytest.raises(p.ProviderProofBlocked):
        p.verify_snapshot(evidence)


def test_no_false_pass_on_invalid_evidence(monkeypatch,capsys):
    def bad():
        raise p.ProviderProofBlocked("real_authentication_refusal_not_proven")
    monkeypatch.setattr(p,"verify_saved",bad)
    monkeypatch.setattr("scripts.ci_cinema_pg_v6_owner_readonly.verify_sources",lambda:None)
    assert p.main()==2
    out=capsys.readouterr().out
    assert "V6_PROVIDER_LOG_HISTORICAL_AUTH_REFUSAL_PASS" not in out
    assert "NO_DB_CHANGE_NO_BACKUP" in out
