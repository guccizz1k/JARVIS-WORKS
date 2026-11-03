"""V16.8 review-only source integrity: isolated policy hardening must fail closed.

Static checks are not a substitute for independent real PG17/RLS testing.
The SQL candidate is never executed by this module.
"""
import re
from pathlib import Path

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/review/v168_dev_rls_parent_tenant_candidate.sql"

EXPECTED = {
    "jw_stage_read_automation_statements_v60": ("automation_statements_v60", "USING", "o.org_id = automation_statements_v60.org_id"),
    "jw_stage_read_evidence_lines_v66": ("evidence_lines_v66", "USING", "r.org_id = evidence_lines_v66.org_id"),
    "jw_stage_read_evidence_links_v65": ("evidence_links_v65", "USING", "r.org_id = evidence_links_v65.org_id"),
    "jw_stage_read_evidence_records_v64": ("evidence_records_v64", "USING", "p.org_id = evidence_records_v64.org_id"),
    "jw_stage_read_invoice_adjustment_decisions_v69": ("invoice_adjustment_decisions_v69", "USING", "a.org_id = invoice_adjustment_decisions_v69.org_id"),
    "jw_stage_read_invoice_adjustments_v69": ("invoice_adjustments_v69", "USING", "i.org_id = invoice_adjustments_v69.org_id"),
    "jw_stage_read_payments": ("payments", "USING", "i.org_id = payments.org_id"),
    "jw_stage_read_reconciliation_reviews_v67": ("reconciliation_reviews_v67", "USING", "r.org_id = reconciliation_reviews_v67.org_id"),
    "v153_delivery_line_select": ("review_delivery_items_v151", "USING", "r.org_id = jw_dev.current_org_from_session()"),
    "v159_item_read": ("review_delivery_items_v151", "USING", "r.org_id = jw_dev.current_org_from_session()"),
    "v153_delivery_nonce_select": ("review_delivery_nonces_v151", "USING", "r.org_id = jw_dev.current_org_from_session()"),
    "v159_nonce_read": ("review_delivery_nonces_v151", "USING", "r.org_id = jw_dev.current_org_from_session()"),
    "v159_receipt_insert": ("review_delivery_receipts_v151", "WITH CHECK", "a.org_id = review_delivery_receipts_v151.org_id"),
}


def policy_chunks(source: str) -> dict:
    chunks = {}
    for part in source.split(";"):
        match = re.search(
            r"\bALTER\s+POLICY\s+(\w+)\s+ON\s+jw_dev\.(\w+)\s+(USING|WITH CHECK)\s*\(",
            part, flags=re.I | re.S,
        )
        if match:
            key = match.group(1)
            assert key not in chunks, "Duplicate policy: " + key
            chunks[key] = (match.group(2), match.group(3).upper(), part)
    return chunks


def validate(source: str) -> None:
    assert re.search(r"^\s*--[^\n]*\n(?:--[^\n]*\n)*BEGIN;", source)
    assert source.rstrip().endswith("COMMIT;")
    for guard in (
        "SET LOCAL lock_timeout = '2s'",
        "SET LOCAL statement_timeout = '15s'",
        "current_setting('jw.v168_review_approval', true) IS DISTINCT FROM 'DEV_ONLY_V168_EXPLICIT'",
        "expected exactly 40 FORCE RLS tables",
        "source policy inventory differs",
        ")) <> 13 THEN",
    ):
        assert guard in source, "Missing protective guard: " + guard
    assert not re.search(
        r"\b(?:DROP|TRUNCATE|GRANT|REVOKE|CREATE|DELETE|UPDATE|INSERT)\s+",
        source, re.I,
    ), "Unauthorized schema/data/privilege statement"
    assert not re.search(r"\b(\w+)\.org_id\s*=\s*\1\.org_id\b", source)
    chunks = policy_chunks(source)
    assert set(chunks) == set(EXPECTED), (set(chunks) ^ set(EXPECTED))
    for name, (table, command, binding) in EXPECTED.items():
        actual_table, actual_command, statement = chunks[name]
        assert (actual_table, actual_command) == (table, command), name
        assert binding in statement, "Missing parent-tenant proof for " + name
        assert "current_org_from_session()" in statement, "Missing user tenant for " + name
        if table.startswith("review_delivery_") and command == "USING":
            assert "EXISTS (SELECT 1 FROM jw_dev.review_delivery_receipts_v151" in statement
    receipt = chunks["v159_receipt_insert"][2]
    for fragment in (
        "a.actor_role = 'admin'",
        "o.status = 'fulfilled'",
        "o.review_state = 'acknowledged'",
        "o.org_id = review_delivery_receipts_v151.org_id",
    ):
        assert fragment in receipt


def replace_policy_fragment(source: str, name: str, needle: str, value: str) -> str:
    prefix, found, rest = source.partition("ALTER POLICY " + name + " ON")
    assert found
    body, semi, suffix = rest.partition(";")
    assert semi and needle in body
    return prefix + found + body.replace(needle, value, 1) + semi + suffix


def test_intended_13_policies_have_strict_approval_gate():
    validate(SOURCE.read_text())


@pytest.mark.parametrize("name", list(EXPECTED))
def test_parent_scope_cannot_be_replaced_with_tautology(name):
    source = SOURCE.read_text()
    clause = EXPECTED[name][2]
    corrupted = replace_policy_fragment(source, name, clause, "1 = 1")
    with pytest.raises(AssertionError):
        validate(corrupted)


@pytest.mark.parametrize("replacement", [
    "", "\nGRANT SELECT ON jw_dev.payments TO public;\n",
    "\nDROP TABLE jw_dev.payments;\n",
    "\nREVOKE SELECT ON jw_dev.payments FROM jw_app_dev;\n",
    "\nUPDATE jw_dev.payments SET amount = 0;\n",
    "\nINSERT INTO jw_dev.payments DEFAULT VALUES;\n",
    "\nCREATE ROLE unsafe_role;\n",
])
def test_no_unauthorized_schema_or_data_changes(replacement):
    sql = SOURCE.read_text()
    if replacement:
        sql = sql.replace("COMMIT;", replacement + "COMMIT;")
    else:
        sql = sql.replace("COMMIT;", "")
    with pytest.raises(AssertionError):
        validate(sql)


@pytest.mark.parametrize("old,new", [
    ("BEGIN;", ""),
    ("SET LOCAL lock_timeout = '2s'", ""),
    ("SET LOCAL statement_timeout = '15s'", ""),
    ("DEV_ONLY_V168_EXPLICIT", "true"),
    ("expected exactly 40 FORCE RLS tables", "expected exactly 39 FORCE RLS tables"),
    (")) <> 13 THEN", ")) <> 12 THEN"),
    ("ALTER POLICY jw_stage_read_payments ON jw_dev.payments", "ALTER POLICY jw_stage_read_payments ON jw_dev.orders"),
    ("ALTER POLICY jw_stage_read_payments ON jw_dev.payments\n  USING", "ALTER POLICY jw_stage_read_payments ON jw_dev.payments\n  WITH CHECK"),
    ("ALTER POLICY v159_receipt_insert ON jw_dev.review_delivery_receipts_v151\n  WITH CHECK", "ALTER POLICY v159_receipt_insert ON jw_dev.review_delivery_receipts_v151\n  USING"),
])
def test_changed_guards_and_policy_bindings_are_detected(old, new):
    source = SOURCE.read_text()
    assert old in source
    with pytest.raises(AssertionError):
        validate(source.replace(old, new, 1))


def test_duplicate_policy_is_rejected():
    sql = SOURCE.read_text()
    marker = "ALTER POLICY jw_stage_read_payments ON"
    start = sql.index(marker)
    end = sql.index(";", start) + 1
    duplicated = sql.replace("COMMIT;", sql[start:end] + "\nCOMMIT;")
    with pytest.raises(AssertionError):
        validate(duplicated)


def test_explicit_parent_self_join_is_rejected_even_when_binding_looks_present():
    sql = SOURCE.read_text()
    key = "i.org_id = payments.org_id"
    attack = sql.replace(key, key + " AND i.org_id = i.org_id", 1)
    with pytest.raises(AssertionError):
        validate(attack)
