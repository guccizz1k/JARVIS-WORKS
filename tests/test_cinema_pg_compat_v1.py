"""Legacy -> PG translation rules. Pure logic; no FastAPI, no database.

The most important cases are the refusals: a legacy request that PG cannot hold without loss or
invention must be refused with a stable code, never trimmed and never completed with made-up
deliveries or statements.
"""
from datetime import date

import pytest

from app import pg_cinema_compat_v1 as cm

RID = "req-12345678"
ITEMS = [{"name": "A", "quantity": 2, "unit_price": 1000}]


def refused(fn, *a, **k):
    with pytest.raises(cm.CompatRefusal) as info:
        fn(*a, **k)
    return info.value


# ------------------------------------------------------------- happy paths
def test_customer_maps_to_partner_and_normalises_business_number():
    out = cm.partner_from_customer({"name": "회사", "business_number": "123-45-67890", "email": "a@b.co"}, RID)
    assert out == {"request_id": RID, "name": "회사", "business_number": "1234567890",
                   "contact_name": "", "email": "a@b.co", "phone": ""}


def test_customer_update_carries_partner_id_and_version_together():
    out = cm.partner_from_customer({"name": "x"}, RID, partner_id="pa-1", expected_version=3)
    assert out["partner_id"] == "pa-1" and out["expected_version"] == 3


def test_quote_create_renames_customer_to_partner_and_defaults_vat():
    out = cm.quote_create({"customer_id": "pa-1", "title": "T", "items": ITEMS}, RID)
    assert out == {"request_id": RID, "partner_id": "pa-1", "title": "T", "vat_mode": "taxable", "items": ITEMS}


def test_quote_update_and_transition():
    out = cm.quote_update({"title": "T2", "items": ITEMS}, RID, expected_version=2,
                          current_partner_id="pa-1", current_vat_mode="exempt")
    assert out["expected_version"] == 2 and "partner_id" not in out and "vat_mode" not in out
    assert cm.quote_transition({"status": "sent"}, RID, expected_version=1)["to"] == "submitted"
    assert cm.quote_transition({"status": "accepted"}, RID, expected_version=1)["to"] == "approved"
    assert cm.quote_transition({"status": "rejected"}, RID, expected_version=1)["to"] == "rejected"
    assert set(cm.QUOTE_STATUS_MAP.values()) <= cm.PG_QUOTE_TARGETS


def test_order_and_payment_translate_when_nothing_would_be_lost():
    assert cm.order_from_quote({"quote_id": "q-1"}, RID) == {"request_id": RID, "quote_id": "q-1"}
    out = cm.payment_for_invoice({"reference": "BANK-0001", "amount": 5000, "paid_at": date(2026, 11, 1)},
                                 RID, today=date(2026, 11, 6))
    assert out == {"request_id": RID, "amount_krw": 5000, "paid_on": "2026-11-01", "reference": "BANK-0001"}


# --------------------------------------------- refusals: loss and invention are never allowed
def test_order_due_date_is_refused_not_dropped():
    err = refused(cm.order_from_quote, {"quote_id": "q-1", "due_date": date(2026, 12, 1)}, RID)
    assert err.code == "due_date_not_stored_in_pg" and err.http_status == 409


def test_payment_note_is_refused_not_dropped():
    err = refused(cm.payment_for_invoice, {"reference": "BANK-0001", "amount": 1, "paid_at": "2026-11-01",
                                           "note": "memo"}, RID, today=date(2026, 11, 6))
    assert err.code == "note_not_stored_in_pg"


def test_future_dated_payment_and_fractional_amount_are_refused():
    base = {"reference": "BANK-0001", "amount": 1, "paid_at": "2026-12-31"}
    assert refused(cm.payment_for_invoice, base, RID, today=date(2026, 11, 6)).code == "future_payment"
    assert refused(cm.payment_for_invoice, {**base, "paid_at": "2026-11-01", "amount": 10.5}, RID,
                   today=date(2026, 11, 6)).code == "not_integer_krw"
    assert refused(cm.payment_for_invoice, {**base, "paid_at": "2026-11-01", "amount": True}, RID,
                   today=date(2026, 11, 6)).code == "not_integer_krw"


def test_business_number_that_is_not_ten_digits_is_refused_not_truncated():
    assert refused(cm.partner_from_customer, {"name": "x", "business_number": "12345"}, RID
                   ).code == "business_number_not_10_digits"


def test_partner_update_without_version_is_refused():
    assert refused(cm.partner_from_customer, {"name": "x"}, RID, partner_id="pa-1").code == "version_required_for_update"
    assert refused(cm.partner_from_customer, {"name": "x"}, RID, expected_version=2).code == "version_required_for_update"


def test_quote_edit_cannot_silently_keep_a_changed_partner_or_vat_mode():
    kw = dict(expected_version=1, current_partner_id="pa-1", current_vat_mode="taxable")
    assert refused(cm.quote_update, {"title": "T", "items": ITEMS, "customer_id": "pa-2"}, RID, **kw
                   ).code == "pg_quote_partner_is_immutable"
    assert refused(cm.quote_update, {"title": "T", "items": ITEMS, "vat_mode": "exempt"}, RID, **kw
                   ).code == "pg_quote_vat_mode_is_immutable"
    # the same values are fine: nothing is being changed
    cm.quote_update({"title": "T", "items": ITEMS, "customer_id": "pa-1", "vat_mode": "taxable"}, RID, **kw)


def test_extra_line_fields_and_bad_items_are_refused():
    assert refused(cm.quote_create, {"customer_id": "p", "title": "T",
                                     "items": [{**ITEMS[0], "source_quote_item_id": "x"}]}, RID
                   ).code == "unsupported_line_field"
    for items in ([], None, "x", [1], [{"name": "", "quantity": 1, "unit_price": 1}],
                  [{"name": "A", "quantity": 0, "unit_price": 1}],
                  [{"name": "A", "quantity": 1, "unit_price": -1}],
                  [{"name": "A", "quantity": 1.5, "unit_price": 1}],
                  [ITEMS[0]] * 41):
        assert refused(cm.quote_create, {"customer_id": "p", "title": "T", "items": items}, RID).http_status in (409, 422)


def test_unknown_status_and_bad_request_id_are_refused():
    assert refused(cm.quote_transition, {"status": "cancelled"}, RID, expected_version=1).code == "unknown_quote_status"
    assert refused(cm.quote_transition, {"status": "sent"}, "short", expected_version=1).code == "bad_request_id"
    assert refused(cm.order_from_quote, {"quote_id": "q"}, "bad id with spaces").code == "bad_request_id"


# ----------------------------------------------- the steps that have no honest PG equivalent
def test_invoice_from_order_is_refused_and_never_fabricates_a_delivery():
    err = cm.unsupported("invoice_from_order")
    assert err.http_status == 409 and err.code == "pg_requires_confirmed_delivery_and_statement"
    assert "fabricated" in err.detail
    # the module has no function that could build a delivery or statement request at all
    names = {n for n in dir(cm) if not n.startswith("_")}
    assert not [n for n in names if "deliver" in n.lower() and n != "unsupported"]
    assert not [n for n in names if "statement" in n.lower() and n not in ("UNSUPPORTED",)]


@pytest.mark.parametrize("step", sorted(cm.UNSUPPORTED))
def test_every_unsupported_step_has_a_stable_code_and_reason(step):
    err = cm.unsupported(step)
    assert err.http_status == 409 and err.code.startswith("pg_") and len(err.detail) > 20
    assert err.as_dict() == {"code": err.code, "detail": err.detail}


def test_unsupported_steps_cover_the_eight_gap_rows_of_the_route_matrix():
    from scripts import ci_cinema_pg_route_matrix_v223 as rm
    gaps = [row for row in rm.CORE_MAPPING if row[4] == "GAP"]
    assert len(gaps) == 8 and len(cm.UNSUPPORTED) == 6        # 3 adjustment routes share one reason
    joined = " ".join(f"{m} {p}" for m, p, *_ in gaps)
    for needle in ("from-order", "acknowledge", "/status", "adjustments"):
        assert needle in joined


# ----------------------------------------------------------------------- request ids
def test_request_id_is_stable_for_a_retry_and_distinct_otherwise():
    a = cm.derive_request_id("org", "user", "POST /api/quotes", "idem-key-0001")
    assert a == cm.derive_request_id("org", "user", "POST /api/quotes", "idem-key-0001")
    assert a != cm.derive_request_id("org", "user", "POST /api/quotes", "idem-key-0002")
    assert a != cm.derive_request_id("org2", "user", "POST /api/quotes", "idem-key-0001")
    assert cm.REQUEST_ID_RE.fullmatch(a)
    assert refused(cm.derive_request_id, "o", "u", "r", "").code == "idempotency_key_required"
    # separators cannot be abused to make two different tuples collide
    assert cm.derive_request_id("a", "b\x1fc", "r", "idem-key-0001") != cm.derive_request_id("a\x1fb", "c", "r", "idem-key-0001")


def test_module_is_not_wired_into_the_app():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    users = [p.name for p in (root / "app").glob("*.py")
             if p.name != "pg_cinema_compat_v1.py" and "pg_cinema_compat_v1" in p.read_text(encoding="utf-8")]
    assert users == [], "wiring the module is a separate, approved step"
