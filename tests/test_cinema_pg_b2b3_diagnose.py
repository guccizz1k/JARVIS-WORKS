import json
from scripts.ci_cinema_pg_b2b3_diagnose import diagnose, safe_read

def report(reason="backup tool produced no usable summary", proof="new_login_refusal_not_verified"):
    return json.dumps({"stages": {
        "renew": {"status": "PASS"},
        "live_login": {"status": "PASS"},
        "backup_restore_compare": {"status": "BLOCKED", "reason": reason},
        "revoke": {"status": "PASS"},
        "prove_closed": {"status": "BLOCKED", "reason": proof},
    }})

def test_failure_codes_are_fixed_labels_and_no_secrets():
    secret = "postgresql://user:super-secret@host/db"
    lines = diagnose(report(), "FAIL_V223_SNAPSHOT_MISMATCH " + secret)
    assert "DIAG ENGINE_CODE_FAIL_V223_SNAPSHOT_MISMATCH" in lines
    assert "DIAG CLOSE_CAUSE_AUTH_REFUSAL_NOT_PROVEN" in lines
    assert all(secret not in line and "super-secret" not in line for line in lines)

def test_source_and_target_classification():
    assert "DIAG BACKUP_CAUSE_DUMP_FAILURE" in diagnose(report(), "pg_dump: connection unexpectedly closed")
    assert "DIAG BACKUP_CAUSE_TARGET_RESTORE" in diagnose(report(), "pg_restore: failed")
    assert "DIAG BACKUP_CAUSE_SOURCE_TLS" in diagnose(report(), "certificate verify failed")

def test_corrupt_or_absent_report_never_claims_success():
    assert diagnose("invalid json", "password=secret") == ["DIAG SUMMARY_UNAVAILABLE"]
    assert "DIAG BACKUP_CAUSE_UNKNOWN" in diagnose(report(), "arbitrary confidential text")

def test_symlink_and_oversize_private_files_are_not_followed(tmp_path):
    private = tmp_path / "private"
    private.write_text("sensitive")
    link = tmp_path / "link"
    link.symlink_to(private)
    assert safe_read(link) == ""
    assert safe_read(private, limit=1) == ""

def test_identity_failure_names_are_allowlisted():
    output = diagnose(report(), "BLOCKED_V223_SOURCE_IDENTITY_NOT_VERIFIED:role,schema_fingerprint")
    assert "DIAG IDENTITY_CHECK_ROLE_FAILED" in output
    assert "DIAG IDENTITY_CHECK_SCHEMA_FINGERPRINT_FAILED" in output
    assert not any("PASSWORD" in line for line in output)
