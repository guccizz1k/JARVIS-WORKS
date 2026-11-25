"""Safety and fail-closed semantics of the real PostgreSQL V15.0 review probe.

Run in exact GitHub checkout, not a manually transcribed source mirror.
The real PostgreSQL result must be read from an independent actual DB run.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SQL = ROOT / "scripts/review/v150_real_pg_temp_integrity_rollback.sql"


def _sql():
    assert SQL.is_file()
    return re.sub(r"--[^\n]*", "", SQL.read_text(encoding="utf-8"))


def test_v150_never_creates_persistent_schema_or_commits():
    sql = _sql()
    assert re.search(r"(?m)^\s*BEGIN\s*;", sql)
    assert re.search(r"(?m)^\s*ROLLBACK\s*;", sql)
    assert len(re.findall(r"\bCREATE\s+TEMP\s+TABLE\b", sql, re.I)) == 4
    assert len(re.findall(r"\bON\s+COMMIT\s+DROP\b", sql, re.I)) == 4
    for term in (r"\bCOMMIT\s*;", r"\bGRANT\b", r"\bREVOKE\b", r"\bTRUNCATE\b",
                 r"\bALTER\s+(?:ROLE|TABLE)\b", r"\bCREATE\s+ROLE\b",
                 r"\bDROP\s+TABLE\b", r"\bINSERT\s+INTO\s+jw_dev\."):
        assert re.search(term, sql, re.I) is None


def test_v150_fails_closed_if_existing_dev_contains_data():
    sql = _sql()
    assert "V150_REQUIRES_EMPTY_ISOLATED_DEV" in sql
    for name in ("organizations", "users", "orders", "invoices", "payments",
                 "messenger_messages", "audit_logs"):
        assert f"jw_dev.{name}" in sql
    assert "FAIL_V150_RESIDUAL_OR_UNEXPECTED_DATA" in sql


def test_v150_database_checks_reject_business_and_email_duplicates():
    sql = _sql()
    for error in ("FAIL_DUPLICATE_EMAIL_ACCEPTED",
                  "FAIL_DUPLICATE_BUSINESS_ACCEPTED",
                  "FAIL_REPLAYED_NONCE_ACCEPTED",
                  "FAIL_PARTIAL_ENROLLMENT_ROLLBACK",
                  "FAIL_AUTO_ACTIVATION_ACCEPTED"):
        assert error in sql
    assert "PENDING_HUMAN_REVIEW" in sql


def test_v150_database_checks_reject_delivery_posting_tamper():
    sql = _sql()
    for error in ("FAIL_CROSS_ORG_ORDER_REPLAY_ACCEPTED",
                  "FAIL_DELIVERY_QUANTITY_MISMATCH_ACCEPTED",
                  "FAIL_DUPLICATE_ITEM_ACCEPTED",
                  "FAIL_SAME_SIGNER_ACCEPTED",
                  "FAIL_SAME_RECEIPT_NONCE_ACCEPTED",
                  "FAIL_PAYMENT_AMOUNT_DIVERGENCE_ACCEPTED",
                  "FAIL_PARTIAL_DELIVERY_ROLLBACK"):
        assert error in sql


def test_v150_never_claims_actual_signup_or_delivery_approval():
    sql = _sql()
    assert "APPROVED" in sql  # negative case must be explicitly rejected
    assert "status='PENDING_HUMAN_REVIEW'" in sql
    assert "PASS_REAL_PG17_V150_TEMP_CONSTRAINTS_AND_ATOMIC_ROLLBACK" in sql
    assert "PASS_REAL_PG17_MULTIWRITER" not in sql
