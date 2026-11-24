"""Only synthetic, local-only offsite restore guard tests."""
import os
from pathlib import Path
import subprocess
import pytest

from scripts import p1_owner_offline_restore_v223 as offline


def test_preflight_blocks_nonowner_and_absent_consent(monkeypatch):
    monkeypatch.delenv("CODESPACES", raising=False)
    assert offline._preflight()=="OWNER_CODESPACE_REQUIRED"
    monkeypatch.setenv("CODESPACES", "true")
    monkeypatch.delenv("JW_PG_OFFLINE_RESTORE_ACK", raising=False)
    assert offline._preflight()=="EXPLICIT_OWNER_OFFLINE_RESTORE_ACK_REQUIRED"


@pytest.mark.parametrize("bad", ["tcp://malicious:2375","ssh://operator@remote","npipe:////./pipe/docker_engine"])
def test_remote_docker_host_is_forbidden(monkeypatch,bad):
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK",offline.ACK)
    monkeypatch.setenv("DOCKER_HOST",bad)
    monkeypatch.setattr(offline.shutil,"which",lambda n:"/usr/bin/docker")
    assert offline._preflight()=="REMOTE_DOCKER_DAEMON_REFUSED"


@pytest.mark.parametrize("raw,reason",[
    (b'ERROR: role "app_reader" does not exist',"MISSING_DISPOSABLE_TARGET_ROLE"),
    (b"ERROR: extension vector is not available","MISSING_EXTENSION_IN_DISPOSABLE_TARGET"),
    (b"ERROR: permission denied","TARGET_PERMISSION_ERROR"),
    (b"ERROR: check constraint violation","RESTORED_DATA_CONSTRAINT_ERROR"),
    (b"ERROR: secret_name.private","RESTORE_FAILED_UNCLASSIFIED"),
])
def test_restore_error_labels_never_leak_identifiers(raw,reason):
    assert offline._restore_reason(raw)==reason


def test_role_matching_rejects_injected_sql_or_nonascii():
    assert offline.ROLE_MISSING_RE.search(b'role "valid_reader" does not exist').group(1)==b'valid_reader'
    assert offline.ROLE_MISSING_RE.search(b'role "valid;DROP ROLE postgres" does not exist') is None
    assert offline.ROLE_MISSING_RE.search(b'role "role-owner" does not exist') is None


def test_preflight_ignores_untrusted_remote_tls(monkeypatch):
    monkeypatch.setenv("CODESPACES","true")
    monkeypatch.setenv("JW_PG_OFFLINE_RESTORE_ACK",offline.ACK)
    monkeypatch.setenv("DOCKER_TLS_VERIFY","1")
    monkeypatch.setattr(offline.shutil,"which",lambda n:"/usr/bin/docker")
    assert offline._preflight()=="REMOTE_DOCKER_DAEMON_REFUSED"


def test_absent_owner_archives_does_not_start_container(monkeypatch):
    monkeypatch.setattr(offline,"_preflight",lambda:"PASS")
    monkeypatch.setattr(offline.owner,"discover_owner_archive",lambda:([],"NO_PRIVATE_CIPHERTEXT_FOUND"))
    monkeypatch.setattr(offline,"_docker",lambda *a,**kw: (_ for _ in ()).throw(AssertionError("DOCKER_START_NOT_ALLOWED")))
    assert offline.run_offline()["blocker"]=="ARCHIVE_COUNT_NOT_SAFELY_BOUNDED"


def test_offline_report_never_claims_real_source_or_offsite(monkeypatch):
    monkeypatch.setattr(offline,"_preflight",lambda:"OWNER_CODESPACE_REQUIRED")
    r=offline.run_offline()
    assert r["historic_real_source_identity_verified"] is False
    assert r["independent_live_source_signature_compared"] is False
    assert r["remote_storage_proven"] is False
    assert r["overall"]=="BLOCKED"


def test_cli_requires_exact_action(capsys):
    assert offline.main(["run"])==2
    assert "USAGE" in capsys.readouterr().err


@pytest.mark.parametrize("constraint,row,total", [
    ("0"*63, "1"*64, "22"),
    ("0"*64, "1"*63, "22"),
    ("0"*64, "1"*64, "-1"),
    ("0"*64, "1"*64, "5000001"),
])
def test_untrusted_current_source_reference_rejected(monkeypatch,constraint,row,total):
    monkeypatch.setenv(offline.REFERENCE_CONSTRAINT_ENV,constraint)
    monkeypatch.setenv(offline.REFERENCE_ROW_ENV,row)
    monkeypatch.setenv(offline.REFERENCE_TOTAL_ENV,total)
    with pytest.raises(offline.backup.BackupError, match="INVALID_READONLY_SOURCE_REFERENCE"):
        offline._source_snapshot_reference()


def test_current_source_reference_is_explicit_opt_in(monkeypatch):
    for name in (offline.REFERENCE_CONSTRAINT_ENV, offline.REFERENCE_ROW_ENV,
                 offline.REFERENCE_TOTAL_ENV):
        monkeypatch.delenv(name,raising=False)
    assert offline._source_snapshot_reference() is None
    monkeypatch.setenv(offline.REFERENCE_CONSTRAINT_ENV,"a"*64)
    monkeypatch.setenv(offline.REFERENCE_ROW_ENV,"b"*64)
    monkeypatch.setenv(offline.REFERENCE_TOTAL_ENV,"22")
    assert offline._source_snapshot_reference()==("a"*64,"b"*64,22)


def test_reference_never_yields_historic_attestation(monkeypatch):
    monkeypatch.setattr(offline,"_preflight",lambda:"OWNER_CODESPACE_REQUIRED")
    r=offline.run_offline()
    assert r["historic_real_source_identity_verified"] is False
    assert r["current_source_snapshot_is_historic_attestation"] is False
    assert r["overall"]=="BLOCKED"



@pytest.mark.parametrize("name,count,comp,jsonhash", [
    ("cinema_pg_transitions; DROP SCHEMA jw_dev", "22", "a"*64, "b"*64),
    ("cinema-pg-transitions", "22", "a"*64, "b"*64),
    ("cinema_pg_transitions", "-1", "a"*64, "b"*64),
    ("cinema_pg_transitions", "22", "xyz", "b"*64),
    ("cinema_pg_transitions", "22", "a"*64, "b"*63),
    ("", "22", "a"*64, "b"*64),
])
def test_focus_ref_fail_closed_before_network_or_docker(monkeypatch,name,count,comp,jsonhash):
    monkeypatch.setenv(offline.FOCUS_TABLE_ENV,name)
    monkeypatch.setenv(offline.FOCUS_COUNT_ENV,count)
    monkeypatch.setenv(offline.FOCUS_COMPOSITE_ENV,comp)
    monkeypatch.setenv(offline.FOCUS_JSON_ENV,jsonhash)
    with pytest.raises(offline.backup.BackupError,match="FOCUS_REFERENCE_INVALID"):
        offline._focus_reference()


def test_no_focus_reference_is_optional(monkeypatch):
    for key in (offline.FOCUS_TABLE_ENV,offline.FOCUS_COUNT_ENV,
                offline.FOCUS_COMPOSITE_ENV,offline.FOCUS_JSON_ENV):
        monkeypatch.delenv(key,raising=False)
    assert offline._focus_reference() is None


def test_valid_focus_reference_only_uses_digest_values(monkeypatch):
    monkeypatch.setenv(offline.FOCUS_TABLE_ENV,"cinema_pg_transitions")
    monkeypatch.setenv(offline.FOCUS_COUNT_ENV,"22")
    monkeypatch.setenv(offline.FOCUS_COMPOSITE_ENV,"a"*64)
    monkeypatch.setenv(offline.FOCUS_JSON_ENV,"b"*64)
    assert offline._focus_reference() == ("cinema_pg_transitions",22,"a"*64,"b"*64)


def test_focus_sql_identifier_rejects_untrusted_names(monkeypatch):
    assert offline._focus_probe("untrusted","postgres","bad'; select secret") is None



def test_focus_diagnose_complete_diagnostic_does_not_claim_data_pass(monkeypatch,capsys):
    result={
        "offline_restore_execution":"PASS_LOCAL_ONLY",
        "container_removed":"PASS",
        "focus_reference_provided":True,
        "focus_probe_unavailable_count":0,
        "focus_comparison":"FOCUS_CONTENT_OR_SNAPSHOT_DIFFERENCE",
        "current_source_comparison":"SOURCE_DRIFT_OR_RESTORED_DATA_DIFFERENCE",
        "overall":"BLOCKED",
    }
    monkeypatch.setattr(offline,"run_offline",lambda:result)
    assert offline.main(["diagnose-focus"]) == 0
    import json
    out=json.loads(capsys.readouterr().out)
    assert out["overall"] == "BLOCKED"
    assert out["focus_comparison"] == "FOCUS_CONTENT_OR_SNAPSHOT_DIFFERENCE"
    assert offline.main(["restore-offline"]) == 1


@pytest.mark.parametrize("bad_field,bad_value",[
    ("offline_restore_execution","BLOCKED_INCOMPLETE"),
    ("container_removed","BLOCKED_CLEANUP"),
    ("focus_reference_provided",False),
    ("focus_probe_unavailable_count",1),
    ("focus_comparison","FOCUS_DIAGNOSTIC_INCOMPLETE"),
    ("focus_comparison","NOT_RUN"),
])
def test_focus_diagnose_never_passes_missing_or_incomplete_evidence(monkeypatch,bad_field,bad_value,capsys):
    result={
        "offline_restore_execution":"PASS_LOCAL_ONLY",
        "container_removed":"PASS",
        "focus_reference_provided":True,
        "focus_probe_unavailable_count":0,
        "focus_comparison":"FOCUS_CONTENT_OR_SNAPSHOT_DIFFERENCE",
        "overall":"BLOCKED"
    }
    result[bad_field]=bad_value
    monkeypatch.setattr(offline,"run_offline",lambda:result)
    assert offline.main(["diagnose-focus"]) == 1
    assert '"overall":"BLOCKED"' in capsys.readouterr().out



@pytest.mark.parametrize("key,bad",[
    (offline.REFERENCE_SCHEMA_NAMES_ENV,"x"*64),
    (offline.REFERENCE_EMPTY_NAMES_ENV,"bad"),
    (offline.REFERENCE_LITERAL_MANIFEST_ENV,"f"*63),
    (offline.REFERENCE_NONEMPTY_ENV,"-1"),
    (offline.REFERENCE_NONEMPTY_ENV,"100001"),
])
def test_manifest_reference_fail_closed_on_partial_invalid(monkeypatch,key,bad):
    for name in (
        offline.REFERENCE_SCHEMA_NAMES_ENV,offline.REFERENCE_EMPTY_NAMES_ENV,
        offline.REFERENCE_LITERAL_MANIFEST_ENV,offline.REFERENCE_NONEMPTY_ENV
    ):
        monkeypatch.delenv(name,raising=False)
    monkeypatch.setenv(key,bad)
    with pytest.raises(offline.backup.BackupError):
        offline._manifest_reference()


def test_manifest_reference_complete_or_optional(monkeypatch):
    for name in (
        offline.REFERENCE_SCHEMA_NAMES_ENV,offline.REFERENCE_EMPTY_NAMES_ENV,
        offline.REFERENCE_LITERAL_MANIFEST_ENV,offline.REFERENCE_NONEMPTY_ENV
    ):
        monkeypatch.delenv(name,raising=False)
    assert offline._manifest_reference() is None
    monkeypatch.setenv(offline.REFERENCE_SCHEMA_NAMES_ENV,"a"*64)
    monkeypatch.setenv(offline.REFERENCE_EMPTY_NAMES_ENV,"b"*64)
    monkeypatch.setenv(offline.REFERENCE_LITERAL_MANIFEST_ENV,"c"*64)
    monkeypatch.setenv(offline.REFERENCE_NONEMPTY_ENV,"1")
    assert offline._manifest_reference() == ("a"*64,"b"*64,"c"*64,1)


def test_diagnose_manifest_exit_never_claims_source_integrity(monkeypatch,capsys):
    from scripts import p1_owner_offline_restore_v223 as offline
    report={
        "offline_restore_execution":"PASS_LOCAL_ONLY",
        "container_removed":"PASS",
        "manifest_metadata_reference_provided":True,
        "metadata_probe_unavailable_count":0,
        "manifest_reconciliation":"SCHEMA_NAME_SET_DIFFERS",
        "overall":"BLOCKED",
    }
    monkeypatch.setattr(offline,"run_offline",lambda:report)
    assert offline.main(["diagnose-manifest"])==0
    assert '"overall":"BLOCKED"' in capsys.readouterr().out
    assert offline.main(["restore-offline"])==1


@pytest.mark.parametrize("key,bad",[
    ("manifest_metadata_reference_provided",False),
    ("metadata_probe_unavailable_count",1),
    ("manifest_reconciliation","NOT_RUN"),
    ("manifest_reconciliation","METADATA_PROBE_INCOMPLETE"),
    ("container_removed","BLOCKED_CLEANUP"),
])
def test_diagnose_manifest_requires_complete_evidence(monkeypatch,capsys,key,bad):
    result={
        "offline_restore_execution":"PASS_LOCAL_ONLY",
        "container_removed":"PASS",
        "manifest_metadata_reference_provided":True,
        "metadata_probe_unavailable_count":0,
        "manifest_reconciliation":"PASS_CURRENT_SCHEMA_AND_AGGREGATES",
        "overall":"BLOCKED",
    }
    result[key]=bad
    monkeypatch.setattr(offline,"run_offline",lambda:result)
    assert offline.main(["diagnose-manifest"])==1
    capsys.readouterr()



def test_all_restore_failure_and_success_returns_have_same_arity():
    """Prevent a real fail-closed pg_restore error from becoming ValueError
    during unpacking and obscuring the underlying fixed failure category.
    """
    import ast
    import inspect
    import textwrap
    tree=ast.parse(textwrap.dedent(inspect.getsource(offline._restore_one)))
    ret=[n.value for n in ast.walk(tree) if isinstance(n,ast.Return)]
    assert len(ret)>=10
    assert all(isinstance(n,ast.Tuple) and len(n.elts)==8 for n in ret)


def test_restore_create_db_failure_yields_safe_eight_fields(monkeypatch):
    import subprocess
    monkeypatch.setattr(offline,"_exec",lambda *a,**kw: subprocess.CompletedProcess([],1,b"",b"db inaccessible"))
    result=offline._restore_one("nonexistent",bytearray(),0)
    assert len(result)==8
    assert result[0]=="CREATE_DISPOSABLE_DB_FAILED"
    assert all(v is None for v in result[2:])



def test_schema_token_reference_strictly_rejects_injection_and_duplicates(monkeypatch):
    for name in (offline.SCHEMA_SALT_ENV,offline.SCHEMA_TOKENS_ENV,
                 offline.SCHEMA_SHAPES_ENV,offline.SCHEMA_NAMES_ENV):
        monkeypatch.delenv(name,raising=False)
    assert offline._schema_source_reference() is None
    monkeypatch.setenv(offline.SCHEMA_SALT_ENV,"a"*24)
    monkeypatch.setenv(offline.SCHEMA_SHAPES_ENV,"b"*64)
    monkeypatch.setenv(offline.SCHEMA_NAMES_ENV,"c"*64)
    for invalid in ("", "a"*15, "z"*16, "0"*32, "a"*17, "b"*16+"a"*16):
        monkeypatch.setenv(offline.SCHEMA_TOKENS_ENV,invalid)
        with pytest.raises(offline.backup.BackupError):
            offline._schema_source_reference()
    monkeypatch.setenv(offline.SCHEMA_TOKENS_ENV,"0"*16+"1"*16)
    assert offline._schema_source_reference()[1]=={"0"*16,"1"*16}


def test_schema_fingerprints_fails_closed_on_sql_injection_or_remote_probe(monkeypatch):
    assert offline._schema_delta_probe("none","none","abc';SELECT secret") is None


@pytest.mark.parametrize("key,bad",[
    ("schema_delta_reference_provided",False),
    ("schema_delta_probe_unavailable_count",1),
    ("schema_delta_classification","SCHEMA_DIAGNOSTIC_INCOMPLETE_OR_INCONSISTENT"),
    ("container_removed","BLOCKED_CLEANUP")
])
def test_schema_diagnosis_requires_full_safe_execution(monkeypatch,capsys,key,bad):
    report={"offline_restore_execution":"PASS_LOCAL_ONLY","container_removed":"PASS",
            "schema_delta_reference_provided":True,"schema_delta_probe_unavailable_count":0,
            "schema_delta_classification":"TABLE_NAME_DRIFT_COLUMN_SHAPES_MATCH","overall":"BLOCKED"}
    report[key]=bad
    monkeypatch.setattr(offline,"run_offline",lambda:report)
    assert offline.main(["diagnose-schema"])==1
    assert '"overall":"BLOCKED"' in capsys.readouterr().out


def test_schema_diagnosis_can_complete_without_falsely_reporting_parity(monkeypatch,capsys):
    report={"offline_restore_execution":"PASS_LOCAL_ONLY","container_removed":"PASS",
            "schema_delta_reference_provided":True,"schema_delta_probe_unavailable_count":0,
            "schema_delta_classification":"TABLE_NAME_DRIFT_COLUMN_SHAPES_MATCH",
            "schema_delta_only_in_live_per_archive":1,"schema_delta_only_in_backup_per_archive":1,
            "overall":"BLOCKED"}
    monkeypatch.setattr(offline,"run_offline",lambda:report)
    assert offline.main(["diagnose-schema"])==0
    assert '"overall":"BLOCKED"' in capsys.readouterr().out
    assert offline.main(["restore-offline"])==1



def test_c_collation_reference_acceptance_requires_full_independent_schema_proofs():
    """Regression: owner 2026-11-23 14:39 actual 11/11 current C-matched,
    while default-order row manifest alone disagreed. Never fake provenance.
    """
    n=11
    data={
        "offline_restore_execution":"PASS_LOCAL_ONLY",
        "offline_restored_archive_count":n,
        "offline_restore_failure_count":0,
        "offline_restore_skipped_budget_count":0,
        "container_removed":"PASS",
        "current_source_comparison":"PASS_CURRENT_C_COLLATION_REFERENCE",
        "current_source_reference_provided":True,
        "current_source_c_sorted_combined_match_count":n,
        "current_source_combined_match_count":0,
        "schema_delta_reference_provided":True,
        "schema_delta_classification":"IDENTICAL_TABLE_NAME_SET",
        "schema_delta_name_sha256_match_count":n,
        "schema_delta_column_shapes_match_count":n,
        "schema_delta_probe_unavailable_count":0,
        "manifest_reconciliation":"NOT_RUN",
        "focus_comparison":"NOT_RUN",
        "overall":"BLOCKED",
    }
    assert offline._restored_source_verdict_pass(data)
    for failure in (
        {"current_source_c_sorted_combined_match_count":n-1},
        {"schema_delta_column_shapes_match_count":n-1},
        {"schema_delta_name_sha256_match_count":n-1},
        {"schema_delta_classification":"TABLE_NAME_DRIFT_COLUMN_SHAPES_MATCH"},
        {"schema_delta_probe_unavailable_count":1},
        {"schema_delta_reference_provided":False},
        {"current_source_reference_provided":False},
        {"container_removed":"BLOCKED_CLEANUP"},
        {"offline_restore_failure_count":1},
        {"manifest_reconciliation":"SCHEMA_NAME_SET_OR_SORT_ORDER_DIFFERS"},
        {"focus_comparison":"FOCUS_CONTENT_OR_SNAPSHOT_DIFFERENCE"}
    ):
        assert not offline._restored_source_verdict_pass({**data,**failure}), failure
    for allowed in ("COLLATION_SORT_ORDER_DIFFERENCE","LEGACY_AGGREGATION_DIFFERS"):
        assert offline._restored_source_verdict_pass({**data,"manifest_reconciliation":allowed})
    assert not offline._restored_source_verdict_pass({**data,"overall":"BLOCKED",
                                                     "current_source_comparison":"SOURCE_DRIFT_OR_RESTORED_DATA_DIFFERENCE"})


def test_restore_offline_cli_returns_zero_only_on_proven_current_reference(monkeypatch,capsys):
    result={
        "offline_restore_execution":"PASS_LOCAL_ONLY",
        "offline_restored_archive_count":11,
        "offline_restore_failure_count":0,
        "offline_restore_skipped_budget_count":0,
        "container_removed":"PASS",
        "current_source_comparison":"PASS_CURRENT_C_COLLATION_REFERENCE",
        "current_source_reference_provided":True,
        "current_source_c_sorted_combined_match_count":11,
        "schema_delta_reference_provided":True,
        "schema_delta_classification":"IDENTICAL_TABLE_NAME_SET",
        "schema_delta_name_sha256_match_count":11,
        "schema_delta_column_shapes_match_count":11,
        "schema_delta_probe_unavailable_count":0,
        "manifest_reconciliation":"NOT_RUN",
        "focus_comparison":"NOT_RUN",
        "overall":"BLOCKED",
    }
    monkeypatch.setattr(offline,"run_offline",lambda:result)
    assert offline.main(["restore-offline"]) == 0
    assert '"overall":"BLOCKED"' in capsys.readouterr().out
    result["schema_delta_column_shapes_match_count"]=10
    assert offline.main(["restore-offline"]) == 1
    assert '"overall":"BLOCKED"' in capsys.readouterr().out



def test_final_pg17_readiness_does_not_accept_temporary_initdb_server(monkeypatch):
    """The initdb temporary postmaster can say pg_isready=0 while the entrypoint
    is about to shut it down. Only PID1=postgres and ready can pass."""
    import subprocess
    calls=[]
    state={"phase":"initdb"}
    def execute(container, command, **kw):
        calls.append(tuple(command))
        if command == ["cat","/proc/1/comm"]:
            name=b"docker-entrypoi\n" if state["phase"]=="initdb" else b"postgres\n"
            return subprocess.CompletedProcess(command,0,name,b"")
        if command[0]=="pg_isready":
            return subprocess.CompletedProcess(command,0,b"accepting connections",b"")
        raise AssertionError("unexpected command")
    monkeypatch.setattr(offline,"_exec",execute)
    assert offline._final_pg17_ready("isolated") is False
    assert calls == [("cat","/proc/1/comm")]
    state["phase"]="final"
    assert offline._final_pg17_ready("isolated") is True
    assert calls[-2:] == [("cat","/proc/1/comm"),
                           ("pg_isready","-U","postgres","-d","postgres")]


def test_final_pg17_readiness_denies_final_server_not_accepting(monkeypatch):
    import subprocess
    def execute(container, command, **kw):
        if command[0]=="cat":
            return subprocess.CompletedProcess(command,0,b"postgres\n",b"")
        return subprocess.CompletedProcess(command,1,b"rejecting",b"")
    monkeypatch.setattr(offline,"_exec",execute)
    assert offline._final_pg17_ready("isolated") is False
