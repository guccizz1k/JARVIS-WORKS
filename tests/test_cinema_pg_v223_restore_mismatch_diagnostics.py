"""No customer data or ACL/constraint definition may escape restore diagnostics."""
from scripts.pg_backup_v223 import diagnose_signature_mismatches, diff_signatures


def test_mismatch_diagnostics_count_only_and_never_weaken_verdict():
    source = {
        "acl": [["orders", "SECRET_SOURCE_ACL"], ["invoices", "same"]],
        "constraints": [["check_company", "SECRET_SOURCE_DEF"]],
    }
    restored = {
        "acl": [["orders", "SECRET_RESTORED_ACL"], ["invoices", "same"], ["extra", "x"]],
        "constraints": [],
    }
    diagnosis = diagnose_signature_mismatches(source, restored)
    assert diagnosis == {
        "acl": {"source_objects": 2, "restored_objects": 3,
                "missing_in_restore": 0, "unexpected_in_restore": 1,
                "different_definition_or_grants": 1},
        "constraints": {"source_objects": 1, "restored_objects": 0,
                        "missing_in_restore": 1, "unexpected_in_restore": 0,
                        "different_definition_or_grants": 0},
    }
    assert "SECRET" not in repr(diagnosis)
    assert diff_signatures(source, restored)


def test_mismatch_diagnostics_empty_and_equal():
    signature = {"acl": [["t", "grant"]], "constraints": [["c", "check"]]}
    d = diagnose_signature_mismatches(signature, signature)
    assert all(all(value == 0 for key, value in part.items()
                   if key not in ("source_objects", "restored_objects"))
               for part in d.values())
    assert diff_signatures(signature, signature) == []
