"""Independent postrun closure: never call a live backup or alter the source."""
import json
import os
from pathlib import Path
from unittest.mock import patch
import pytest

from scripts import ci_cinema_pg_v6_postrun_attest as a

def test_receipt_strict_sha_and_success_stages(tmp_path):
    file=tmp_path/(a.RECEIPT_PREFIX+"20261122.json")
    file.write_text(json.dumps({"sha":a.SUCCESSFUL_BACKUP_SHA,
              "verdict":"BLOCKED","stages":{key:"PASS" for key in a.REQUIRED}}))
    file.chmod(0o600)
    with patch.object(a.runner,"SUMMARY_FILE",tmp_path/"summary.json"):
        assert a.private_receipt()==file

def test_reject_old_or_incomplete_receipts(tmp_path):
    file=tmp_path/(a.RECEIPT_PREFIX+"20261122.json")
    file.write_text(json.dumps({"sha":"other","verdict":"PASS","stages":{}}))
    file.chmod(0o600)
    with patch.object(a.runner,"SUMMARY_FILE",tmp_path/"summary.json"):
        with pytest.raises(a.AttestationBlocked,match="prior_backup_receipt"):
            a.private_receipt()

def test_original_pooler_refusal_is_sufficient():
    with patch.object(a.runner,"stage_prove_closed",
          return_value={"new_login_refused":True,"refusal":"auth_rejected",
                        "active_sessions":0,"rolcanlogin":False}), \
         patch.object(a,"prove_direct_denial") as direct:
        assert a.independent_proof()=="SESSION_POOLER_AUTH_REJECTION"
        direct.assert_not_called()

def test_transport_error_triggers_only_a_verified_direct_probe():
    error=a.runner.Blocked("new_login_refusal_not_verified: transport")
    with patch.object(a.runner,"stage_prove_closed",side_effect=error), \
         patch.object(a,"prove_direct_denial",return_value="PRIMARY_PG_AUTH_REJECTION"):
        assert a.independent_proof()=="PRIMARY_PG_AUTH_REJECTION"

def test_catalog_failure_disallows_fallback():
    error=a.runner.Blocked("role not closed: sessions=1 can_login=False")
    with patch.object(a.runner,"stage_prove_closed",side_effect=error), \
         patch.object(a,"prove_direct_denial") as probe:
        with pytest.raises(a.AttestationBlocked,match="pooler_catalog"):
            a.independent_proof()
        probe.assert_not_called()

def test_audit_blocks_transport_without_saving_evidence(tmp_path):
    with patch.object(a.gate,"verify_sources"), \
         patch.object(a,"check_live_admin_state"), \
         patch.object(a,"private_receipt",return_value=tmp_path/"receipt.json"), \
         patch.object(a,"independent_proof",return_value="PRIMARY_PG_TRANSPORT_OR_UNRECOGNIZED"):
        with pytest.raises(a.AttestationBlocked,match="authentication_refusal"):
            a.audit()
        assert list(tmp_path.glob("v6_postrun_independent_*"))==[]

def test_classify_refusal_delegates_original_engine_rule():
    class FakeError:
        sqlstate="28000"
    assert a.classify_refusal(FakeError())=="AUTH_REJECTED"
    class Transport:
        sqlstate=None
        def __str__(self):return "connection timed out"
    assert a.classify_refusal(Transport())=="TRANSPORT_OR_UNRECOGNIZED"

def test_main_does_not_claim_pass_without_proof(capsys):
    with patch.object(a,"audit",side_effect=a.AttestationBlocked("authentication_refusal_not_verified")):
        assert a.main()==2
    output=capsys.readouterr().out
    assert "NO_FALSE_PASS_NO_BACKUP_RETRY" in output
    assert "V6_POSTRUN_INDEPENDENT_CLOSURE_PASS" not in output
