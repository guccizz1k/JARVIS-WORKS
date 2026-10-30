"""Adversarial mutants for offline-only V13.1 SQL safety-contract tests.

Mutation tests prove that the six static guards REJECT known-bad SQL edits.
No database or browser connection. Never advertise as business E2E.
"""
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "scripts/review/v131_real_abc_finance_rollback.sql"
GUARD = ROOT / "tests/test_v131_finance_review_contract.py"

def _load_guard():
    spec = spec_from_file_location("v131_source_contract_guards", GUARD)
    assert spec is not None and spec.loader is not None
    mod = module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

@pytest.mark.parametrize(("deleted","replacement","guard"), [
    ("ROLLBACK;", "COMMIT;", "test_01_single_rolled_back_transaction"),
    ("FINANCE_REVIEW_MUST_START_EMPTY", "EMPTY_GUARD_REMOVED", "test_02_no_schema_changes_or_production_rows"),
    ("jw-v99-ext-hash-unknown", "unknown_identity_check_removed", "test_03_forces_real_app_role_and_all_tenant_sessions"),
    ("OVERPAYMENT_ACCEPTED", "overpayment_no_longer_asserted", "test_04_required_negative_financial_controls"),
    ("PAYMENT_REPLAY_NOT_IDEMPOTENT", "dedup_assertion_removed", "test_05_idempotency_and_reversal_regression_controls"),
    ("PASS_REAL_V131_ABC_FINANCE_RLS_PAYMENT_REVERSAL_ROLLBACK", "false_positive_verdict", "test_06_independent_residual_cleanliness_check_in_sql"),
], ids=("commit-instead-of-rollback","remove-empty-guard","remove-unknown-session",
        "remove-overpayment-denial","remove-idempotency-proof","forge-success-marker"))
def test_adversarial_mutation_is_rejected(deleted, replacement, guard, tmp_path):
    original = SQL.read_text(encoding="utf-8")
    assert original.count(deleted) >= 1, "Original fixture drift; cannot trust mutation test"
    mutated = original.replace(deleted, replacement, 1)
    assert mutated != original
    forged_sql = tmp_path / "forged.sql"
    forged_sql.write_text(mutated, encoding="utf-8")
    mod = _load_guard()
    mod.SQL = forged_sql
    with pytest.raises(AssertionError):
        getattr(mod, guard)()
