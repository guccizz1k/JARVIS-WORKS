"""V17.0 review-only schema promotion: mutation-resistant approval boundary.

Static negative assertions complement actual Supabase rollback dry-run and
the existing disposable PostgreSQL V12.7/V12.8 HTTP replay. They do not
attest a real issuer, bank, external signer, or production readiness.
"""
from __future__ import annotations

from pathlib import Path
import ast
import re
import pytest

ROOT = Path(__file__).resolve().parents[1]
SQL = (ROOT / "scripts/review/v170_dev_review_draft_schema.sql").read_text()
SOURCE = (ROOT / "scripts/ci_v127_ephemeral_order.sql").read_text()
API = (ROOT / "app/pg_quote_api_v92.py").read_text()


def _proof(sql: str) -> bool:
    # Review oracle intentionally treats losing ANY required guard as a fail.
    hard = (
        "BEGIN;", "SET LOCAL lock_timeout", "SET LOCAL statement_timeout",
        "V170_NONEMPTY_OR_UNEXPECTED_DATABASE_BLOCKED",
        "current_database() <> 'postgres'", "current_user <> 'postgres'",
        "forced <> 40", "policies <> 56",
        "COALESCE(role_ok,false) = false",
        "OR to_regclass('jw_dev.order_drafts_v127') IS NOT NULL",
        "OR to_regclass('jw_dev.order_draft_items_v127') IS NOT NULL",
        "OR to_regclass('jw_dev.quote_review_receipts_v128') IS NOT NULL",
        "OR EXISTS(SELECT 1 FROM jw_dev.organizations)",
        "OR EXISTS(SELECT 1 FROM jw_dev.sessions)",
        "OR EXISTS(SELECT 1 FROM jw_dev.orders)",
        "OR EXISTS(SELECT 1 FROM jw_dev.payments)",
        "CREATE TABLE jw_dev.order_drafts_v127",
        "CREATE TABLE jw_dev.order_draft_items_v127",
        "CREATE TABLE jw_dev.quote_review_receipts_v128",
        "GRANT SELECT,INSERT ON jw_dev.order_drafts_v127,jw_dev.order_draft_items_v127 TO jw_app_dev",
        "GRANT SELECT,INSERT ON jw_dev.quote_review_receipts_v128 TO jw_app_dev",
        "JW_DEV.CURRENT_ORG_FROM_SESSION()",  # case-insensitive
        "jw_dev.stage_identity_v84()",
        "q.org_id=order_drafts_v127.org_id",
        "q.customer_id=order_drafts_v127.customer_id",
        "q.org_id=quote_review_receipts_v128.org_id",
        "actor_id=(SELECT actor_id FROM jw_dev.stage_identity_v84())",
        "FORCE ROW LEVEL SECURITY",
        "WITH CHECK",
        "forced <> 43", "policies <> 62", "inserted <> 0",
        "V170_PRIVILEGE_ESCALATION_BLOCKED",
        "COMMIT;",
        "PASS_V170_REVIEW_ONLY_SCHEMA_43_FORCED_RLS_62_POLICIES",
    )
    if not all(fragment.lower() in sql.lower() for fragment in hard):
        return False
    if sql.count("CREATE TABLE jw_dev.") != 3 or sql.count("FORCE ROW LEVEL SECURITY") != 3:
        return False
    if sql.count("CREATE POLICY jw_v170_") != 6:
        return False
    if sql.count("WITH CHECK") != 3 or sql.count(" FOR SELECT TO jw_app_dev") != 3:
        return False
    if sql.count(" FOR INSERT TO jw_app_dev") != 3:
        return False
    if any(re.search(p,sql,re.I) for p in (
        r"GRANT\s+(UPDATE|DELETE|TRUNCATE|ALL)\b",
        r"\b(DISABLE ROW LEVEL SECURITY|SECURITY DEFINER|DROP TABLE|TRUNCATE|DELETE FROM|UPDATE jw_dev|INSERT INTO jw_dev.payments)\b",
        r"SET ROLE (postgres|service_role)",
        r"CREATE TABLE jw_dev\.(orders|invoices|payments)\b",
        r"q\.org_id\s*=\s*q\.org_id",
    )):
        return False
    return True


def test_actual_migration_is_strictly_additive_and_approval_scoped():
    assert _proof(SQL)
    for n in ("order_drafts_v127","order_draft_items_v127",
              "quote_review_receipts_v128"):
        assert f"CREATE TABLE jw_dev.{n}" in SOURCE
    ast.parse(API)
    assert "original_checked: Literal[True]" in API
    assert "preview_checked: Literal[True]" in API
    assert "review_receipt_id" in API
    assert "900:" in API
    assert '"approval_posted": False' in API
    assert '"draft_only": True' in API
    assert '"source_document_verified": False' in API
    assert "INSERT INTO jw_dev.payments" not in API
    assert "INSERT INTO jw_dev.invoices" not in API


# 30 independent unauthorized/missing-control mutations must be rejected.
_MUTATIONS = [
    ("BEGIN;", ""),
    ("SET LOCAL lock_timeout", "SET LOCAL lock_timeouts"),
    ("SET LOCAL statement_timeout", "SET LOCAL statement_timeouts"),
    ("current_database() <> 'postgres'", "false"),
    ("current_user <> 'postgres'", "false"),
    ("forced <> 40", "false"),
    ("policies <> 56", "false"),
    ("COALESCE(role_ok,false) = false", "false"),
    ("OR to_regclass('jw_dev.order_drafts_v127') IS NOT NULL", ""),
    ("OR to_regclass('jw_dev.order_draft_items_v127') IS NOT NULL", ""),
    ("OR to_regclass('jw_dev.quote_review_receipts_v128') IS NOT NULL", ""),
    ("OR EXISTS(SELECT 1 FROM jw_dev.organizations)", ""),
    ("OR EXISTS(SELECT 1 FROM jw_dev.sessions)", ""),
    ("OR EXISTS(SELECT 1 FROM jw_dev.orders)", ""),
    ("OR EXISTS(SELECT 1 FROM jw_dev.payments)", ""),
    ("CREATE TABLE jw_dev.order_drafts_v127", "CREATE TABLE jw_dev.orders_v127"),
    ("CREATE TABLE jw_dev.order_draft_items_v127", "CREATE TABLE jw_dev.order_draft_items_v999"),
    ("CREATE TABLE jw_dev.quote_review_receipts_v128", "CREATE TABLE jw_dev.quote_review_receipts_v999"),
    ("FORCE ROW LEVEL SECURITY", "ENABLE ROW LEVEL SECURITY"),
    ("GRANT SELECT,INSERT ON jw_dev.order_drafts_v127,jw_dev.order_draft_items_v127 TO jw_app_dev", "GRANT ALL ON jw_dev.order_drafts_v127,jw_dev.order_draft_items_v127 TO jw_app_dev"),
    ("GRANT SELECT,INSERT ON jw_dev.quote_review_receipts_v128 TO jw_app_dev", "GRANT UPDATE ON jw_dev.quote_review_receipts_v128 TO jw_app_dev"),
    ("jw_dev.current_org_from_session()", "true"),
    ("q.customer_id=order_drafts_v127.customer_id", "true"),
    ("q.org_id=order_drafts_v127.org_id", "q.org_id=q.org_id"),
    ("q.org_id=quote_review_receipts_v128.org_id", "q.org_id=q.org_id"),
    ("actor_id=(SELECT actor_id FROM jw_dev.stage_identity_v84())", "true"),
    ("WITH CHECK", "WITHOUT CHECK"),
    ("forced <> 43", "forced < 43"),
    ("policies <> 62", "policies < 62"),
    ("inserted <> 0", "inserted < 0"),
    ("V170_PRIVILEGE_ESCALATION_BLOCKED", "V170_ESCALATION_IGNORED"),
    ("COMMIT;", "ROLLBACK;"),
]


@pytest.mark.parametrize(("before","after"),_MUTATIONS,ids=[f"m{i+1:02}" for i in range(len(_MUTATIONS))])
def test_mutation_cannot_preserve_acceptance_proof(before,after):
    assert before in SQL, before
    poisoned=SQL.replace(before,after,1)
    assert poisoned != SQL and not _proof(poisoned)
