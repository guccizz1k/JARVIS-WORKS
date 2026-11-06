"""Input hardening of app.pg_cinema_compat_v1: no unusable identity passes the two-person quote rule, and a
malformed request body is a 4xx refusal, never an unhandled exception (a route would turn that into a 500)."""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app import pg_cinema_compat_v1 as cm

RID = "req-00000001"
ITEMS = [{"name": "A", "quantity": 1, "unit_price": 100}]


def refusal(fn, *a, **kw) -> cm.CompatRefusal:
    with pytest.raises(cm.CompatRefusal) as exc:
        fn(*a, **kw)
    return exc.value


# ------------------------------------------------------------- quote approval: identities
@pytest.mark.parametrize("actor,submitter", [
    (None, "u1"), ("u1", None), (None, None), ("", "u1"), ("u1", ""), (0, 0), (1, "1"), (True, 1),
    (" u1", "u1"), ("u1 ", "u1"), ("u1", " u1"), ("   ", "   "), ("u1\x00", "u1"), ("u1\n", "u1"),
    (b"u1", b"u1"), (["u1"], ["u1"]), (("u1",), ("u1",)), ({"id": "u1"}, {"id": "u1"}), ("u​1", "u1"),
])
def test_unusable_identity_is_unknown_not_passed(actor, submitter):
    assert refusal(cm.quote_approval_guard, actor, submitter).code in (
        "quote_approval_identity_unknown", "quote_second_person_required")
    assert refusal(cm.quote_approval_guard, actor, submitter).http_status == 409


@pytest.mark.parametrize("actor,submitter", [(" u1", "u1"), ("u1 ", "u1"), (None, "u1"), (1, "1"), ("u​1", "u1")])
def test_padding_and_wrong_types_are_unknown_specifically(actor, submitter):
    assert refusal(cm.quote_approval_guard, actor, submitter).code == "quote_approval_identity_unknown"


@pytest.mark.parametrize("actor,submitter", [("U1", "u1"), ("u1", "U1"), ("ｕ１", "u1"), ("abc", "abc")])
def test_same_person_in_another_spelling_is_still_the_same_person(actor, submitter):
    assert refusal(cm.quote_approval_guard, actor, submitter).code == "quote_second_person_required"


def test_two_different_people_pass():
    assert cm.quote_approval_guard("u1", "u2") is None
    assert cm.quote_approval_guard("a" * 32, "b" * 32) is None


def test_transition_accepted_needs_both_identities_even_when_missing_from_the_call():
    assert refusal(cm.quote_transition, {"status": "accepted"}, RID, expected_version=1).code == \
        "quote_approval_identity_unknown"
    assert cm.quote_transition({"status": "accepted"}, RID, expected_version=1, actor_id="u1",
                               submitted_by="u2")["to"] == "approved"


# ------------------------------------------------------------- bodies that are not objects
@pytest.mark.parametrize("bad", [None, "accepted", 5, ["accepted"], (1,)])
@pytest.mark.parametrize("fn,kw", [
    (cm.partner_from_customer, {}), (cm.quote_create, {}), (cm.order_from_quote, {}),
    (cm.payment_for_invoice, {}),
    (cm.quote_update, {"expected_version": 1, "current_partner_id": "p", "current_vat_mode": "taxable"}),
    (cm.quote_transition, {"expected_version": 1, "actor_id": "u1", "submitted_by": "u2"}),
])
def test_non_object_body_is_a_422_refusal(fn, kw, bad):
    err = refusal(fn, bad, RID, **kw)
    assert err.http_status in (400, 422)


@pytest.mark.parametrize("status", [["accepted"], {}, 5, None, True, "ACCEPTED", "approved"])
def test_unhashable_or_odd_status_is_unknown_status(status):
    assert refusal(cm.quote_transition, {"status": status}, RID, expected_version=1,
                   actor_id="u1", submitted_by="u2").code == "unknown_quote_status"


# ------------------------------------------------------------- text fields are never coerced
@pytest.mark.parametrize("field,value", [("name", 5), ("name", ["x"]), ("business_number", 1234567890),
                                         ("contact_name", {}), ("email", 7), ("phone", ["1"]), ("name", "a\x00b")])
def test_partner_text_fields_must_be_text(field, value):
    body = {"name": "N", "business_number": "1234567890", field: value}
    assert refusal(cm.partner_from_customer, body, RID).http_status == 422


def test_partner_business_number_must_be_ascii_digits():
    assert refusal(cm.partner_from_customer, {"name": "N", "business_number": "１２３４５６７８９０"}, RID).code == \
        "business_number_not_10_digits"
    assert cm.partner_from_customer({"name": "N", "business_number": "123-45-67890"}, RID)["business_number"] == "1234567890"


@pytest.mark.parametrize("cid", [5, ["p"], {"a": 1}, "", None])
def test_quote_create_needs_a_text_customer_id(cid):
    assert refusal(cm.quote_create, {"customer_id": cid, "title": "T", "items": ITEMS}, RID).http_status == 422


@pytest.mark.parametrize("vat", [["taxable"], {}, 5, "TAXABLE"])
def test_quote_create_vat_mode_unhashable_or_wrong(vat):
    assert refusal(cm.quote_create, {"customer_id": "p", "title": "T", "vat_mode": vat, "items": ITEMS}, RID).code == \
        "bad_vat_mode"


@pytest.mark.parametrize("qid", [5, ["q"], "", None])
def test_order_from_quote_needs_a_text_quote_id(qid):
    assert refusal(cm.order_from_quote, {"quote_id": qid}, RID).http_status == 422


# ------------------------------------------------------------- payments
@pytest.mark.parametrize("paid", ["2026-02-30", "2026-13-01", "2026-00-10", "２０２０-01-01", "2026-1-1",
                                  "2026-11-01T00:00:00", 20261101, None, ["2026-11-01"]])
def test_impossible_or_odd_payment_date_is_a_refusal_not_a_crash(paid):
    assert refusal(cm.payment_for_invoice, {"amount": 10, "paid_at": paid}, RID).http_status == 422


def test_reference_is_never_silently_truncated():
    # the engine CHECK is length(btrim(reference)) BETWEEN 1 AND 80; 81+ must be a 422 here, not a PG 502
    ok = cm.payment_for_invoice({"amount": 10, "paid_at": "2026-11-01", "reference": "r" * 80}, RID)
    assert ok["reference"] == "r" * 80
    assert refusal(cm.payment_for_invoice, {"amount": 10, "paid_at": "2026-11-01", "reference": "r" * 81}, RID).http_status == 422
    assert refusal(cm.payment_for_invoice, {"amount": 10, "paid_at": "2026-11-01", "reference": 77}, RID).http_status == 422


def test_amount_must_be_a_plain_integer():
    for amount in (True, 10.5, "10", None, [10]):
        assert refusal(cm.payment_for_invoice, {"amount": amount, "paid_at": "2026-11-01", "reference": "R"},
                       RID).code in ("not_integer_krw", "out_of_range")


# ------------------------------------------------------------- V22.3 QA: values the engine would refuse
ENGINE = (Path(__file__).resolve().parents[1] / "scripts/review/cinema_pg_write_engine.sql").read_text()


@pytest.mark.parametrize("key,pattern", [
    ("partner_name", r"name text NOT NULL CHECK\(length\(btrim\(name\)\) BETWEEN 1 AND (\d+)\),\n  business_number"),
    ("contact_name", r"contact_name text NOT NULL DEFAULT '' CHECK\(length\(contact_name\)<=(\d+)\)"),
    ("email", r"email text NOT NULL DEFAULT '' CHECK\(length\(email\)<=(\d+)\)"),
    ("phone", r"phone text NOT NULL DEFAULT '' CHECK\(length\(phone\)<=(\d+)\)"),
    ("quote_title", r"title text NOT NULL CHECK\(length\(btrim\(title\)\) BETWEEN 1 AND (\d+)\)"),
    ("payment_reference", r"reference text NOT NULL CHECK\(length\(btrim\(reference\)\) BETWEEN 1 AND (\d+)\)"),
])
def test_text_limits_match_the_engine_checks(key, pattern):
    m = re.search(pattern, ENGINE)
    assert m, f"engine CHECK for {key} drifted"
    assert cm.PG_TEXT_LIMITS[key] == int(m.group(1))


@pytest.mark.parametrize("field,limit", [("contact_name", 80), ("email", 254), ("phone", 40)])
def test_partner_optional_text_obeys_engine_limit(field, limit):
    ok = cm.partner_from_customer({"name": "N", field: "x" * limit}, RID)
    assert ok[field] == "x" * limit
    assert refusal(cm.partner_from_customer, {"name": "N", field: "x" * (limit + 1)}, RID).code == "bad_" + field


@pytest.mark.parametrize("bad", ["a\x00b", "   ", "\ud800", "", "x" * 151, 5, None])
def test_quote_title_engine_would_refuse_is_422(bad):
    for fn, kw in ((cm.quote_create, {}),
                   (cm.quote_update, {"expected_version": 1, "current_partner_id": "p", "current_vat_mode": "taxable"})):
        assert refusal(fn, {"customer_id": "p", "title": bad, "items": ITEMS}, RID, **kw).code == "bad_title"


@pytest.mark.parametrize("bad", ["\x00", "  ", "\udfff", "", "n" * 151])
def test_line_name_engine_would_refuse_is_422(bad):
    items = [{"name": bad, "quantity": 1, "unit_price": 1}]
    assert refusal(cm.quote_create, {"customer_id": "p", "title": "T", "items": items}, RID).code == "bad_items"


@pytest.mark.parametrize("bad", ["   ", "\ud800", "a\x00"])
def test_partner_name_engine_would_refuse_is_422(bad):
    assert refusal(cm.partner_from_customer, {"name": bad}, RID).code == "bad_name"


@pytest.mark.parametrize("pid,ver", [(5, 1), ("", 1), ("p\n1", 1), ("p" * 65, 1),
                                     ("pa-1", "3"), ("pa-1", True), ("pa-1", 0), ("pa-1", 2**31)])
def test_partner_update_id_and_version_are_validated(pid, ver):
    assert refusal(cm.partner_from_customer, {"name": "N"}, RID, partner_id=pid, expected_version=ver).http_status == 422


@pytest.mark.parametrize("ref", [None, "", "   ", "r\x00", "\ud800", 7])
def test_payment_reference_is_required_like_the_engine(ref):
    assert refusal(cm.payment_for_invoice, {"amount": 1, "paid_at": "2026-11-01", "reference": ref}, RID).code == \
        "bad_reference"


@pytest.mark.parametrize("note", [0, False, [], {}, "x", " "])
def test_payment_note_values_are_refused_not_dropped(note):
    body = {"amount": 1, "paid_at": "2026-11-01", "reference": "R", "note": note}
    assert refusal(cm.payment_for_invoice, body, RID).code == "note_not_stored_in_pg"


@pytest.mark.parametrize("args", [
    ("o", "u", "r", ["k"] * 8), ("o", "u", "r", 12345678), ("o", "u", "r", "\ud800" * 8),
    ("o", "u", "r", "k\x00" * 4), ("o", "u", "r", "k" * 257), (None, "u", "r", "k" * 8),
    ("o", 7, "r", "k" * 8), ("o", "u", "", "k" * 8), ("\udfff", "u", "r", "k" * 8),
])
def test_request_id_derivation_refuses_instead_of_crashing(args):
    assert refusal(cm.derive_request_id, *args).http_status == 400


def test_request_id_derivation_still_stable():
    a = cm.derive_request_id("o", "u", "r", "key-12345")
    assert a == cm.derive_request_id("o", "u", "r", "key-12345") and a.startswith("compat:")
