"""Offline-only integrity tests for the V13.1 DEV transactional RLS/finance fixture.

These do NOT run the SQL or certify production/HTTP business workflows.
The actual DB execution is a separate owner-scoped manual/isolated review step.
"""
from pathlib import Path
import re

SQL = (Path(__file__).resolve().parents[1] /
       "scripts/review/v131_real_abc_finance_rollback.sql")

def _sql() -> str:
    text = SQL.read_text(encoding="utf-8")
    assert 3000 < len(text) < 25000
    return text

def test_01_single_rolled_back_transaction():
    text = _sql()
    executable = re.sub(r"(?m)^\s*--.*$", "", text)
    assert re.search(r"(?m)^BEGIN;$", executable)
    assert len(re.findall(r"(?m)^ROLLBACK;$", executable)) == 1
    assert not re.search(r"\bCOMMIT\s*;", executable, re.I)

def test_02_no_schema_changes_or_production_rows():
    text = _sql()
    executable = re.sub(r"(?m)^\s*--.*$", "", text)
    assert not re.search(r"\b(CREATE|ALTER|DROP|TRUNCATE)\s+(TABLE|SCHEMA|ROLE)\b",
                         executable, re.I)
    for marker in ("current_database()<>'postgres'",
                   "V99 fixture must only run on empty isolated dev state",
                   "FINANCE_REVIEW_MUST_START_EMPTY"):
        assert marker in text

def test_03_forces_real_app_role_and_all_tenant_sessions():
    text = _sql()
    for marker in ("SET LOCAL ROLE jw_app_dev",
                   "jw-v99-ext-hash-a", "jw-v99-ext-hash-b",
                   "jw-v99-ext-hash-c", "jw-v99-ext-hash-unknown"):
        assert marker in text

def test_04_required_negative_financial_controls():
    text = _sql()
    for marker in ("EARLY_INVOICE_ACCEPTED",
                   "OVERPAYMENT_ACCEPTED",
                   "FOREIGN_INVOICE_PAYMENT_ACCEPTED",
                   "C_FOREIGN_PAYMENT_ACCEPTED",
                   "UNKNOWN_SESSION_PAYMENT_ACCEPTED",
                   "REVERSED_KEY_REUSED",
                   "FINANCE_INTERNAL_STATE_PUBLICLY_CALLABLE"):
        assert marker in text

def test_05_idempotency_and_reversal_regression_controls():
    text = _sql()
    for marker in ("record_payment_v83(", "reverse_payment_v83(",
                   "PAYMENT_REPLAY_NOT_IDEMPOTENT",
                   "DUPLICATE_PAYMENT", "REVERSED_PAYMENT_ACTIVE",
                   "ACTIVE_BALANCE_MISMATCH", "active_amount<>2200"):
        assert marker in text

def test_06_independent_residual_cleanliness_check_in_sql():
    text = _sql()
    for marker in ("FAIL_RESIDUAL_FIXTURES",
                   "jw_dev.organizations WHERE id LIKE 'jw-v99-ext-%'",
                   "jw_dev.invoices WHERE id LIKE 'jw-v131-%'",
                   "jw_dev.payments WHERE reference LIKE 'jw131-%'",
                   "PASS_REAL_V131_ABC_FINANCE_RLS_PAYMENT_REVERSAL_ROLLBACK"):
        assert marker in text
