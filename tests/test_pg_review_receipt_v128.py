
"""V12.8 review receipt tamper/rescope contracts; real PG17/Chromium is authoritative."""
from pathlib import Path
import ast
ROOT=Path(__file__).resolve().parents[1]
def src(name):
    return (ROOT/name).read_text(encoding="utf-8")

def test_browser_requires_server_review_instead_of_client_boolean():
    a=src("scripts/ci_v93_https_pg_browser.py")
    ast.parse(a)
    for needle in (
        "premature.code!==422", "forged.code!==409", "badDigest.code!==409",
        "noReviewCsrf.code!==403", "acknowledged.code!==201",
        "source_document_verified!==false",
        "JW_V128_PG17_REVIEW_RECEIPT_A_B_C_PASS",
    ):
        assert needle in a

def test_review_receipt_binds_tenant_actor_quote_and_digest():
    a=src("app/pg_quote_api_v92.py")
    ast.parse(a)
    for needle in ("review_receipt_id: str", "source_sha256=%s",
                   "AND actor_id=%s", "AND quote_id=%s",
                   "quote_preview_acknowledged", "source_document_verified", 
                   "0 <= (", "<= 900", "Missing, stale or foreign"):
        assert needle in a
    assert "receipt = cur.fetchone()" in a
    assert "return" in a

def test_receipt_table_forces_rls_and_has_no_update_delete():
    s=src("scripts/ci_v127_ephemeral_order.sql")
    assert "CREATE TABLE jw_dev.quote_review_receipts_v128" in s
    assert "ALTER TABLE jw_dev.quote_review_receipts_v128 FORCE ROW LEVEL SECURITY" in s
    assert "CREATE POLICY ci_review_insert" in s
    assert "CREATE POLICY ci_review_select" in s
    assert "GRANT SELECT,INSERT ON jw_dev.quote_review_receipts_v128" in s
    assert "GRANT UPDATE" not in s and "GRANT DELETE" not in s

def test_unverified_original_document_never_claimed_verified():
    for path in ("app/pg_quote_api_v92.py","scripts/ci_v93_https_pg_browser.py"):
        assert "source_document_verified" in src(path)
    assert "preview_acknowledged" in src("app/pg_quote_read_v93.py")
    assert "CHECK(review_state='preview_acknowledged')" in src("scripts/ci_v127_ephemeral_order.sql")
