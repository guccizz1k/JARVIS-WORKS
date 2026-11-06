"""Offline fail-closed regression for the proposed two-person quote CHECK.

The full behavioural test uses the installed CHECK expression on ephemeral PG16/17 in
ci_cinema_pg_terms_gate_v223.py (T5.16); this file does not claim DB coverage.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_check_requires_both_non_null_identities():
    sql = (ROOT / "scripts/review/cinema_pg_v223_quote_two_person_proposal.sql").read_text()
    assert "submitted_by IS NOT NULL AND approved_by IS NOT NULL" in sql
    assert "approved_by IS DISTINCT FROM submitted_by" in sql
    assert "(submitted_by IS NULL OR approved_by IS NULL" in sql
    assert "NOT VALID" in sql


def test_ephemeral_pg_gate_evaluates_live_check_not_just_sql_source():
    src = (ROOT / "scripts/ci_cinema_pg_terms_gate_v223.py").read_text()
    assert "T5.16_actual_constraint_rejects_null_approver_for_approved_and_ordered" in src
    assert "pg_get_expr(c.conbin, c.conrelid)" in src
    assert "CREATE TEMP TABLE quote_guard_null_probe" in src
    assert "EXCEPTION WHEN check_violation THEN NULL" in src
