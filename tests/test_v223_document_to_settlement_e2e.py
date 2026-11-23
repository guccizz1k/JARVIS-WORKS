"""End-to-end synthetic document -> linked trade settlement on protected review app.

Distinct from existing per-route tests: one imported XLSX source must retain its
single tenant/order lineage all the way through statement, invoice, payment,
idempotency and reversal. No public deployment or production data.
"""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from app import main as core
from app.owner_review_app_v223 import app as owner_app
from tests.test_smart_import import make_xlsx


@pytest.fixture
def review_client(tmp_path, monkeypatch):
    for key, value in {
        "JW_ENV": "review",
        "JW_ROOT_UI": "owner-visual-review",
        "JW_APPROVED_UI_REVIEW": "ISOLATED_REVIEW_ONLY",
        "JW_NO_EXTERNAL_DATABASE": "1",
        "DEMO_SEED": "1",
    }.items():
        monkeypatch.setenv(key, value)
    for key in ("JW_PUBLIC_QA_MODE", "BOOTSTRAP_EMAIL", "BOOTSTRAP_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setattr(core, "DB_PATH", tmp_path / "synthetic_import_settlement.db")
    with TestClient(owner_app, base_url="https://testserver") as client:
        yield client


def login(client, email):
    r = client.post("/api/login", json={
        "email": email, "password": "Demo!2026secure"})
    assert r.status_code == 200, r.text
    token = r.cookies.get(core.SESSION_COOKIE)
    assert token and r.json()["csrf_token"]
    return {
        "Cookie": core.SESSION_COOKIE + "=" + token,
        "X-CSRF-Token": r.json()["csrf_token"],
    }


def assert_http(r, expected):
    assert r.status_code == expected, (
        "expected", expected, "actual", r.status_code, r.text[:400])
    return r.json()


def test_imported_document_full_trade_chain_and_negative_boundaries(review_client):
    c = review_client
    owner = login(c, "demo@hanbit.example")
    baseline_orders = len(assert_http(c.get("/api/orders", headers=owner), 200))
    baseline_invoices = len(assert_http(c.get("/api/invoices", headers=owner), 200))
    original = make_xlsx()
    preview = assert_http(c.post("/api/imports/preview", headers=owner,
        files={"file": ("synthetic_purchase.xlsx", original,
                       "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}), 201)
    preview_id = preview["id"]
    total = preview["document"]["money"]["total"]
    assert total == 1_705_000
    assert preview["document"]["record_type"] == "order"
    assert preview["confirmation_required"] and preview["ready_to_confirm"]
    assert len(assert_http(c.get("/api/orders", headers=owner), 200)) == baseline_orders
    assert not any(x["id"] == preview_id for x in
        assert_http(c.get("/api/imports/queue", headers=owner), 200)["confirmed"])

    payload = {
        "preview_digest": preview["digest"],
        "confirmed_customer": preview["document"]["company"],
        "confirmed_order_date": preview["document"]["ordered_at"],
        "confirmed_total": total,
        "approve": True,
    }
    assert_http(c.post("/api/imports/" + preview_id + "/confirm", headers=owner,
                       json={**payload, "confirmed_total": total + 1}), 409)
    assert_http(c.post("/api/imports/" + preview_id + "/confirm",
                       headers={"Cookie": owner["Cookie"]}, json=payload), 403)
    assert len(assert_http(c.get("/api/orders", headers=owner), 200)) == baseline_orders
    accepted = assert_http(c.post("/api/imports/" + preview_id + "/confirm",
                                  headers=owner, json=payload), 201)
    order_id = accepted["order"]["id"]
    quote_id = accepted["quote_id"]
    assert accepted["import_id"] == preview_id
    assert accepted["order"]["source_import_id"] == preview_id
    assert accepted["order"]["quote_id"] == quote_id
    assert accepted["order"]["money"]["total"] == total
    assert accepted["order"]["review_state"] == "clean"
    assert len(assert_http(c.get("/api/orders", headers=owner), 200)) == baseline_orders + 1
    assert_http(c.post("/api/imports/" + preview_id + "/confirm",
                       headers=owner, json=payload), 409)
    assert_http(c.post("/api/imports/preview", headers=owner,
                       files={"file": ("same.xlsx", original)}), 409)

    invoice_request = {"order_id": order_id, "due_date": "2099-12-31"}
    statement_request = {"order_id": order_id}
    assert_http(c.post("/api/invoices/from-order",
                       headers=owner, json=invoice_request), 409)
    assert_http(c.post("/api/automation/statements/from-order",
                       headers=owner, json=statement_request), 409)
    for state in ("processing", "fulfilled"):
        after = assert_http(c.post("/api/orders/" + order_id + "/status",
                                  headers=owner, json={"status": state}), 200)
        assert after["status"] == state

    statement = assert_http(c.post("/api/automation/statements/from-order",
                                   headers=owner, json=statement_request), 201)
    assert statement["order_id"] == order_id
    assert statement["document"]["source_order_id"] == order_id
    assert statement["document"]["money"]["total"] == total
    assert statement["document"]["finalized"] is True
    assert statement["document"]["legal_status"] == "internal_business_record_not_tax_invoice"
    reused = assert_http(c.post("/api/automation/statements/from-order",
                                headers=owner, json=statement_request), 200)
    assert reused["id"] == statement["id"] and reused["reused"] is True

    invoice = assert_http(c.post("/api/invoices/from-order",
                                 headers=owner, json=invoice_request), 201)
    invoice_id = invoice["id"]
    assert invoice["order_id"] == order_id and invoice["money"]["total"] == total
    assert invoice["balance"] == total and invoice["paid"] == 0
    assert len(assert_http(c.get("/api/invoices", headers=owner), 200)) == baseline_invoices + 1
    assert_http(c.post("/api/invoices/from-order",
                       headers=owner, json=invoice_request), 409)
    reconciliation = assert_http(c.get("/api/reconciliation/" + order_id,
                                       headers=owner), 200)
    assert reconciliation["has_invoice"] is True
    assert reconciliation["quote_money"]["total"] == total
    assert reconciliation["order_money"]["total"] == total
    assert reconciliation["invoice_money"]["total"] == total
    assert reconciliation["quote_to_order"] == reconciliation["order_to_invoice"] == []

    pay_endpoint = "/api/invoices/" + invoice_id + "/payments"
    paid_at = datetime.now(core.KST).date().isoformat()
    partial = {"reference": "JW-DOC-TO-PAYMENT-00001",
               "amount": 500_000, "paid_at": paid_at, "note": "synthetic"}
    first = assert_http(c.post(pay_endpoint, headers=owner, json=partial), 201)
    assert first["paid"] == 500_000 and first["balance"] == total - 500_000
    assert_http(c.post(pay_endpoint, headers=owner, json=partial), 201)
    assert len(assert_http(c.get(pay_endpoint, headers=owner), 200)) == 1
    assert_http(c.post(pay_endpoint, headers=owner,
                       json={**partial, "amount": 500_001}), 409)
    rest = {"reference": "JW-DOC-TO-PAYMENT-00002",
            "amount": total - 500_000, "paid_at": paid_at, "note": "synthetic"}
    settled = assert_http(c.post(pay_endpoint, headers=owner, json=rest), 201)
    assert settled["paid"] == total and settled["balance"] == 0
    assert_http(c.post(pay_endpoint, headers=owner,
                       json={**rest, "reference": "JW-DOC-TO-PAYMENT-00003",
                             "amount": 1}), 409)

    trace = assert_http(c.get("/api/automation/transactions/" + order_id,
                              headers=owner), 200)
    assert trace["source_order_id"] == order_id
    assert trace["quote_id"] == quote_id
    assert trace["statement_id"] == statement["id"]
    assert trace["invoice_id"] == invoice_id
    assert trace["active_paid"] == total and trace["remaining_balance"] == 0
    assert {"quote", "order", "trade_statement", "invoice", "payment"} <= {
        event["type"] for event in trace["events"]}
    assert len([event for event in trace["events"] if event["type"] == "payment"]) == 2

    other = login(c, "demo@bada.example")
    for endpoint in ("/api/imports/" + preview_id,
                     "/api/orders/" + order_id,
                     "/api/invoices/" + invoice_id,
                     "/api/automation/statements/" + statement["id"],
                     "/api/automation/transactions/" + order_id):
        assert_http(c.get(endpoint, headers=other), 404)

    record = next(row for row in settled["payments"]
                  if row["reference"] == partial["reference"])
    reversed_doc = assert_http(c.post(pay_endpoint + "/" + record["id"] + "/reverse",
                                      headers=owner), 200)
    assert reversed_doc["paid"] == total - 500_000
    assert reversed_doc["balance"] == 500_000
    assert_http(c.post(pay_endpoint + "/" + record["id"] + "/reverse",
                       headers=owner), 409)
    assert_http(c.post(pay_endpoint, headers=owner, json=partial), 409)
    final = assert_http(c.get("/api/invoices/" + invoice_id, headers=owner), 200)
    assert final["money"]["total"] == total
    assert final["paid"] == total - 500_000 and final["balance"] == 500_000
    assert final["order_id"] == order_id
