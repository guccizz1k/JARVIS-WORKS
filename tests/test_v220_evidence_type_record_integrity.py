"""V22.0 strict document-type/financial-record matrix, real API in isolated SQLite."""
from __future__ import annotations

import pytest

from tests.test_evidence_v64 import stage, approve, xlsx

DOCUMENTS = {
    "영수증": ("receipt", ("sales", "purchase", "expense")),
    "매출전표": ("sales_slip", ("sales",)),
    "매입전표": ("purchase_slip", ("purchase",)),
    "거래명세표": ("trade_statement", ("sales", "purchase")),
    "재고표": ("inventory_sheet", ("inventory_snapshot",)),
}
RECORD_TYPES = ("sales", "purchase", "expense", "inventory_snapshot")
BAD = [(label, kind, record, amount)
       for label, (kind, allowed) in DOCUMENTS.items()
       for record in RECORD_TYPES if record not in allowed
       for amount in (None, 11000)]


@pytest.mark.parametrize("label,kind,record,amount", BAD)
def test_unsupported_kind_record_pairs_cannot_post(api, label, kind, record, amount):
    p = stage(api, "source.xlsx", xlsx(kind=label)).json()
    assert p["document"]["document_kind"] == kind
    baseline = api.get("/evidence/dashboard").json()
    attempt = approve(api, p, kind=kind, type=record, amount=amount,
                      reference="UNSUPPORTED-KIND-REF",
                      sku="SKU-1", quantity=2)
    assert attempt.status_code == 422, (label, record, attempt.text)
    assert "원본문서 종류" in attempt.text
    after = api.get("/evidence/dashboard").json()
    assert after["total_confirmed"] == baseline["total_confirmed"]
    assert after["pending_review"] == baseline["pending_review"]
    assert not api.get("/evidence/records").json()
    assert api.get("/dashboard").json()["invoices"] == 0


GOOD = [(label, kind, record)
        for label, (kind, allowed) in DOCUMENTS.items()
        for record in allowed]


@pytest.mark.parametrize("label,kind,record", GOOD)
def test_supported_kind_record_pairs_remain_manual_and_nonposting(api, label, kind, record):
    p = stage(api, "legitimate.xlsx", xlsx(kind=label)).json()
    assert p["document"]["document_kind"] == kind
    baseline = api.get("/dashboard").json()
    before = api.get("/evidence/dashboard").json()
    assert before["total_confirmed"] == 0 and before["pending_review"] == 1
    result = approve(api, p, kind=kind, type=record,
                     amount=None if record == "inventory_snapshot" else 11000,
                     sku="SKU-1" if record == "inventory_snapshot" else "",
                     quantity=2 if record == "inventory_snapshot" else None,
                     reference="GOOD-MATRIX-REF")
    assert result.status_code == 201, (label, record, result.text)
    result = result.json()
    assert result["accounting_posted"] is False
    assert result["payment_created"] is False
    assert result["inventory_stock_changed"] is False
    after = api.get("/dashboard").json()
    assert after["invoices"] == baseline["invoices"]
    assert after["outstanding"] == baseline["outstanding"]
    assert api.get("/evidence/dashboard").json()["total_confirmed"] == 1
    assert api.get("/evidence/dashboard").json()["pending_review"] == 0
