"""Security contract for V15.1 candidate ledger. No DB credentials or network."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DDL = ROOT / "scripts/review/v151_private_review_ledger_candidate.sql"
CHECKS = ROOT / "scripts/review/v151_private_review_ledger_assertions.sql"
WRITER = ROOT / "app/pg_delivery_review_reservation_v151.py"


def _uncomment(sql):
    return re.sub(r"--[^\n]*", "", sql)


def test_new_schema_is_only_private_review_with_five_force_rls_tables():
    sql = _uncomment(DDL.read_text())
    assert len(re.findall(r"CREATE TABLE jw_dev.review_\w+_v151", sql)) == 5
    assert len(re.findall(r"ENABLE ROW LEVEL SECURITY;", sql)) == 5
    assert len(re.findall(r"FORCE ROW LEVEL SECURITY;", sql)) == 5
    assert not re.search(r"\bCREATE POLICY\b", sql)
    assert not re.search(r"\bGRANT\b", sql)
    assert "REVOKE ALL ON TABLE" in sql
    assert "jw_auth_stage_v85" in sql and "jw_app_dev" in sql
    for forbidden in ("INSERT INTO jw_dev.users", "INSERT INTO jw_dev.invoices",
                      "INSERT INTO jw_dev.payments", "DROP TABLE",
                      "ALTER ROLE", "COMMIT;"):
        assert forbidden not in sql


def test_no_untrusted_source_item_or_tenant_order_can_enter_review():
    sql = _uncomment(DDL.read_text())
    assert "o.id=NEW.order_id AND o.org_id=NEW.org_id" in sql
    assert "o.status='fulfilled'" in sql and "o.review_state='acknowledged'" in sql
    assert "i.id=NEW.source_item_id AND i.order_id=NEW.order_id" in sql
    for field in ("i.position=NEW.position", "i.quantity=NEW.quantity",
                  "i.unit_price=NEW.unit_price_krw"):
        assert field in sql
    assert len(re.findall(r"SECURITY INVOKER", sql)) == 3
    assert not re.search(r"\bSECURITY DEFINER\b", sql)
    assert "REVOKE ALL ON FUNCTION" in sql


def test_ledger_status_and_finance_flags_cannot_advance():
    sql = _uncomment(DDL.read_text())
    assert sql.count("CHECK(status='PENDING_HUMAN_REVIEW')") == 2
    for flag in ("physical_delivery_verified", "invoice_posted",
                 "payment_posted"):
        assert f"CHECK({flag}=false)" in sql
    assert "CHECK(dispatch_actor <> recipient_actor)" in sql
    assert "UNIQUE(order_id,purpose)" in sql
    assert "UNIQUE(request_id,purpose)" in sql


def test_real_pg_fixture_is_review_only_and_rejects_source_spoofing():
    sql = _uncomment(CHECKS.read_text())
    for name in ("FAIL_V151_DUPLICATE_EMAIL", "FAIL_V151_DUPLICATE_BUSINESS",
                 "FAIL_V151_NONCE_REPLAY", "FAIL_V151_FOREIGN_TENANT_ORDER",
                 "FAIL_V151_WRONG_SOURCE_POSITION", "FAIL_V151_WRONG_SOURCE_QUANTITY",
                 "FAIL_V151_WRONG_SOURCE_PRICE", "FAIL_V151_PUBLIC_OR_DEFINER_TRIGGER"):
        assert name in sql
    assert not re.search(r"\bCOMMIT\s*;", sql)
    assert not re.search(r"\bINSERT INTO jw_dev\.(users|invoices|payments)\b", sql)


def test_private_writer_remains_unmounted_and_has_no_approval_or_payment_api():
    code = WRITER.read_text()
    assert "stage_identity_v84()" in code
    assert "FOR UPDATE" in code
    assert "evaluate_delivery(" in code
    assert "review_delivery_nonces_v151" in code
    assert "PENDING_HUMAN_REVIEW" in code
    for forbidden in ("@router.", "include_router(", "register_routes(",
                      "SET ROLE ", "GRANT ", "INSERT INTO jw_dev.invoices",
                      "INSERT INTO jw_dev.payments", "db.commit()"):
        assert forbidden not in code


def test_v152_rejects_any_mutation_of_five_evidence_ledgers():
    sql = _uncomment(DDL.read_text())
    assert "v152_reject_evidence_mutation" in sql
    assert "V152_REVIEW_EVIDENCE_IMMUTABLE" in sql
    assert len(re.findall(r"BEFORE UPDATE OR DELETE ON jw_dev.review_", sql)) == 5
    assert "REVOKE ALL ON FUNCTION jw_dev.v152_reject_evidence_mutation()" in sql
    assert not re.search(r"\bSECURITY DEFINER\b", sql)


def test_v152_real_postgresql_assertions_check_updates_and_deletes():
    sql = _uncomment(CHECKS.read_text())
    assert "FAIL_V152_EVIDENCE_UPDATE_ACCEPTED" in sql
    assert "FAIL_V152_EVIDENCE_DELETE_ACCEPTED" in sql
    assert "FAIL_V152_MUTATION_TRIGGER_PRIVILEGE" in sql
    for table in (
        "review_signup_requests_v151", "review_signup_nonces_v151",
        "review_delivery_receipts_v151", "review_delivery_nonces_v151",
        "review_delivery_items_v151",
    ):
        assert table in sql
