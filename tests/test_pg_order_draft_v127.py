"""Test-oracle inventory for actual isolated PG17 quote->order-draft browser E2E.
These checks supplement, never substitute for, the Chromium job.
"""
from pathlib import Path
import ast
ROOT=Path(__file__).resolve().parents[1]
def read(path):
    return (ROOT/path).read_text(encoding="utf-8")

def test_stage_route_never_enabled_for_production():
    s=read("app/pg_quote_api_v92.py")
    ast.parse(s)
    assert 'v90._pg_validated_cursor' in s
    assert "original_checked: Literal[True]" in s
    assert 'ON CONFLICT DO NOTHING RETURNING id' in s
    assert "create_from_checked_quote" in s
    assert '"approval_posted": False' in s
    assert "request.headers.get" in s
    assert 'router.add_api_route("/order-drafts"' in s

def test_ephemeral_pg_order_tables_are_force_rls_and_insert_only():
    s=read("scripts/ci_v127_ephemeral_order.sql").upper()
    for fragment in ("CREATE TABLE JW_DEV.ORDER_DRAFTS_V127", "CREATE TABLE JW_DEV.ORDER_DRAFT_ITEMS_V127",
                     "FORCE ROW LEVEL SECURITY", "CREATE POLICY CI_ORDER_INSERT",
                     "CREATE POLICY CI_ORDER_ITEM_INSERT", "WITH CHECK",
                     "UNIQUE(ORG_ID,QUOTE_ID)"):
        assert fragment in s
    assert "GRANT SELECT,INSERT" in s
    assert "GRANT UPDATE" not in s and "GRANT DELETE" not in s

def test_browser_exercises_negative_and_replay_cases():
    s=read("scripts/ci_v93_https_pg_browser.py")
    ast.parse(s)
    for fragment in ("original_checked:false", "rejectUnchecked.code!==422",
                     "noOrderCSRF.code!==403", "orderRetry.code!==200",
                     "conflict.code!==409", "foreignOrder.code!==404",
                     "cOrder.code!==404", "JW_V128_PG17_REVIEW_RECEIPT_A_B_C_PASS"):
        assert fragment in s
    assert "restore_proof()" in s
    assert s.index("restore_proof()") < s.index("ci_v127_ephemeral_order.sql")


def test_not_posting_to_live_business_order_or_payment_tables():
    stage=read("scripts/ci_v127_ephemeral_order.sql").upper()
    engine=read("app/pg_quote_api_v92.py")
    assert "CREATE TABLE JW_DEV.ORDER_DRAFTS_V127" in stage
    assert "CREATE TABLE JW_DEV.ORDER_DRAFT_ITEMS_V127" in stage
    assert "CREATE TABLE JW_DEV.ORDERS " not in stage
    assert "INSERT INTO jw_dev.orders" not in engine
    assert "INSERT INTO jw_dev.payments" not in engine
