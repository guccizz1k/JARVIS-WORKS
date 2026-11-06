"""Legacy-shaped views of PG engine entities. The SHAPES dict is REAL output captured from the CINEMA engine
running on a throw-away PostgreSQL 16.15 (partner, quote, order, invoice, payment, and the VAT function results);
ci_cinema_pg_terms_gate_v223 re-checks the key contract against PostgreSQL 17 in CI, so a drifting engine fails
there. Pure logic; no FastAPI, no database."""
import json
import pathlib
import re

import pytest

from app import pg_cinema_compat_view_v1 as vw

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHAPES = json.loads(r'''
{
 "partner": {
  "id": "a5f58b038793442ea0ff75614b35e0e3",
  "name": "캡처 거래처",
  "email": "a@example.invalid",
  "phone": "010-0000-0000",
  "org_id": "ci-a",
  "version": 1,
  "created_at": "2026-11-06T16:55:53.292473+09:00",
  "created_by": "ci-ua",
  "updated_at": "2026-11-06T16:55:53.292473+09:00",
  "contact_name": "홍길동",
  "business_number": "2208114412"
 },
 "quote_draft": {
  "id": "bea4bd2dbba048839309b608ebf4c49b",
  "items": [
   {
    "id": "2e95bc0adf2247ffa1a34f0dc1413ac8",
    "name": "부품 A",
    "org_id": "ci-a",
    "position": 0,
    "quantity": 3,
    "quote_id": "bea4bd2dbba048839309b608ebf4c49b",
    "unit_price": 1005
   },
   {
    "id": "73be958ed5864f188b6aa0ab769ecf9d",
    "name": "부품 B",
    "org_id": "ci-a",
    "position": 1,
    "quantity": 1,
    "quote_id": "bea4bd2dbba048839309b608ebf4c49b",
    "unit_price": 250
   }
  ],
  "title": "캡처 견적",
  "org_id": "ci-a",
  "status": "draft",
  "version": 1,
  "trade_no": "T261106-0021",
  "vat_mode": "taxable",
  "created_at": "2026-11-06T16:55:53.331009+09:00",
  "created_by": "ci-ua3",
  "partner_id": "a5f58b038793442ea0ff75614b35e0e3",
  "updated_at": "2026-11-06T16:55:53.331009+09:00",
  "approved_at": null,
  "approved_by": null,
  "submitted_by": null
 },
 "quote_approved": {
  "id": "bea4bd2dbba048839309b608ebf4c49b",
  "items": [
   {
    "id": "2e95bc0adf2247ffa1a34f0dc1413ac8",
    "name": "부품 A",
    "org_id": "ci-a",
    "position": 0,
    "quantity": 3,
    "quote_id": "bea4bd2dbba048839309b608ebf4c49b",
    "unit_price": 1005
   },
   {
    "id": "73be958ed5864f188b6aa0ab769ecf9d",
    "name": "부품 B",
    "org_id": "ci-a",
    "position": 1,
    "quantity": 1,
    "quote_id": "bea4bd2dbba048839309b608ebf4c49b",
    "unit_price": 250
   }
  ],
  "title": "캡처 견적",
  "org_id": "ci-a",
  "status": "approved",
  "version": 3,
  "trade_no": "T261106-0021",
  "vat_mode": "taxable",
  "created_at": "2026-11-06T16:55:53.331009+09:00",
  "created_by": "ci-ua3",
  "partner_id": "a5f58b038793442ea0ff75614b35e0e3",
  "updated_at": "2026-11-06T16:55:53.40812+09:00",
  "approved_at": "2026-11-06T16:55:53.40812+09:00",
  "approved_by": "ci-ua",
  "submitted_by": "ci-ua3"
 },
 "order": {
  "id": "ede83caa78d4423e8209c193ec99bad9",
  "items": [
   {
    "id": "5a51ca6c9b27459392136b2ad00fde1c",
    "name": "부품 A",
    "org_id": "ci-a",
    "order_id": "ede83caa78d4423e8209c193ec99bad9",
    "position": 0,
    "quantity": 3,
    "unit_price": 1005,
    "source_quote_item_id": "2e95bc0adf2247ffa1a34f0dc1413ac8"
   },
   {
    "id": "fdf1afb1a15e4ac2aef07bd34d269f4e",
    "name": "부품 B",
    "org_id": "ci-a",
    "order_id": "ede83caa78d4423e8209c193ec99bad9",
    "position": 1,
    "quantity": 1,
    "unit_price": 250,
    "source_quote_item_id": "73be958ed5864f188b6aa0ab769ecf9d"
   }
  ],
  "org_id": "ci-a",
  "status": "open",
  "quote_id": "bea4bd2dbba048839309b608ebf4c49b",
  "trade_no": "T261106-0021",
  "vat_mode": "taxable",
  "created_at": "2026-11-06T16:55:53.446464+09:00",
  "created_by": "ci-ua",
  "partner_id": "a5f58b038793442ea0ff75614b35e0e3",
  "updated_at": "2026-11-06T16:55:53.446464+09:00"
 },
 "order_after_delivery": {
  "id": "ede83caa78d4423e8209c193ec99bad9",
  "items": [
   {
    "id": "5a51ca6c9b27459392136b2ad00fde1c",
    "name": "부품 A",
    "org_id": "ci-a",
    "order_id": "ede83caa78d4423e8209c193ec99bad9",
    "position": 0,
    "quantity": 3,
    "unit_price": 1005,
    "source_quote_item_id": "2e95bc0adf2247ffa1a34f0dc1413ac8"
   },
   {
    "id": "fdf1afb1a15e4ac2aef07bd34d269f4e",
    "name": "부품 B",
    "org_id": "ci-a",
    "order_id": "ede83caa78d4423e8209c193ec99bad9",
    "position": 1,
    "quantity": 1,
    "unit_price": 250,
    "source_quote_item_id": "73be958ed5864f188b6aa0ab769ecf9d"
   }
  ],
  "org_id": "ci-a",
  "status": "fulfilled",
  "quote_id": "bea4bd2dbba048839309b608ebf4c49b",
  "trade_no": "T261106-0021",
  "vat_mode": "taxable",
  "created_at": "2026-11-06T16:55:53.446464+09:00",
  "created_by": "ci-ua",
  "partner_id": "a5f58b038793442ea0ff75614b35e0e3",
  "updated_at": "2026-11-06T16:55:53.648473+09:00"
 },
 "payment": {
  "id": "39f70463f9f54c5c861cc5de14fb4601",
  "org_id": "ci-a",
  "paid_on": "2026-11-06",
  "reversed": false,
  "trade_no": "T261106-0021",
  "reference": "REF-CAP-1",
  "amount_krw": 1000,
  "invoice_id": "2208b3e16bdb4002838c44a9533802f4",
  "recorded_at": "2026-11-06T16:55:53.925968+09:00",
  "recorded_by": "ci-ua",
  "bank_confirmed": false
 },
 "invoice": {
  "id": "2208b3e16bdb4002838c44a9533802f4",
  "org_id": "ci-a",
  "status": "draft",
  "vat_krw": 327,
  "order_id": "ede83caa78d4423e8209c193ec99bad9",
  "paid_krw": 0,
  "trade_no": "T261106-0021",
  "total_krw": 3592,
  "created_at": "2026-11-06T16:55:53.781437+09:00",
  "created_by": "ci-ua",
  "invoice_no": "INV-T261106-0021-01",
  "reviewed_at": null,
  "reviewed_by": null,
  "void_reason": null,
  "confirmed_at": null,
  "confirmed_by": null,
  "statement_id": "4bc264695c1240fe8ed717600ca40050",
  "subtotal_krw": 3265
 },
 "vat": {
  "0": {
   "taxable": 0,
   "exempt": 0
  },
  "1": {
   "taxable": 0,
   "exempt": 0
  },
  "4": {
   "taxable": 0,
   "exempt": 0
  },
  "5": {
   "taxable": 1,
   "exempt": 0
  },
  "6": {
   "taxable": 1,
   "exempt": 0
  },
  "14": {
   "taxable": 1,
   "exempt": 0
  },
  "15": {
   "taxable": 2,
   "exempt": 0
  },
  "16": {
   "taxable": 2,
   "exempt": 0
  },
  "25": {
   "taxable": 3,
   "exempt": 0
  },
  "95": {
   "taxable": 10,
   "exempt": 0
  },
  "105": {
   "taxable": 11,
   "exempt": 0
  },
  "1000": {
   "taxable": 100,
   "exempt": 0
  },
  "999999995": {
   "taxable": 100000000,
   "exempt": 0
  },
  "3015": {
   "taxable": 302,
   "exempt": 0
  },
  "3265": {
   "taxable": 327,
   "exempt": 0
  }
 }
}
''')


def legacy_columns(table):
    text = (ROOT / "app/main.py").read_text(encoding="utf-8")
    m = re.search(rf"CREATE TABLE IF NOT EXISTS {table} \(\n(.*?)\n\);", text, re.S)
    assert m, f"legacy DDL for {table} moved"
    cols = []
    for line in m.group(1).splitlines():
        for part in re.split(r",\s*(?![^()]*\))", line.strip()):
            tok = part.strip().split(" ")[0]
            if tok and tok.isidentifier() and tok.upper() not in ("UNIQUE", "PRIMARY", "CHECK", "FOREIGN", "CONSTRAINT"):
                cols.append(tok)
    return cols


Q, O, P, PAY = SHAPES["partner"], SHAPES["quote_approved"], SHAPES["partner"], SHAPES["payment"]
NAME = "캡처 거래처"


# ----------------------------------------------------------------------------- key contract
@pytest.mark.parametrize("kind, entity", [("partner", SHAPES["partner"]), ("quote", SHAPES["quote_approved"]),
                                          ("order", SHAPES["order"]), ("payment", SHAPES["payment"])])
def test_real_engine_entities_carry_every_key_the_mappers_read(kind, entity):
    assert set(vw.ENTITY_KEYS[kind]) <= set(entity)


def test_real_engine_line_items_carry_their_keys():
    assert set(vw.ENTITY_KEYS["quote_item"]) <= set(SHAPES["quote_approved"]["items"][0])
    assert set(vw.ENTITY_KEYS["order_item"]) <= set(SHAPES["order"]["items"][0])


# ------------------------------------------------------------------------------------- ids
def test_every_exposed_id_is_prefixed_and_safe_for_the_ui_separator_and_url_paths():
    q = vw.quote_view(SHAPES["quote_approved"], partner_name=NAME)
    ids = [q["id"], q["customer_id"]] + [i["id"] for i in q["items"]]
    assert all(re.fullmatch(r"pg_[0-9a-f]{32}", i) for i in ids)
    assert all("|" not in i and re.fullmatch(r"[A-Za-z0-9_]+", i) for i in ids)


def test_order_quote_join_the_ui_relies_on_holds():
    q = vw.quote_view(SHAPES["quote_approved"], partner_name=NAME)
    o = vw.order_view(SHAPES["order"], partner_name=NAME, title=q["title"])
    assert o["quote_id"] == q["id"] and o["customer_id"] == q["customer_id"]       # app.js: orders.some(y=>y.quote_id===id)
    assert all(i["source_quote_item_id"] in {x["id"] for x in q["items"]} for i in o["items"])


@pytest.mark.parametrize("value, expected", [
    ("pg_" + "a" * 32, ("pg", "a" * 32)),
    ("a" * 32, ("legacy", "a" * 32)),
    ("ci-ua", ("legacy", "ci-ua")),
])
def test_parse_public_id_routes_by_prefix_only(value, expected):
    assert vw.parse_public_id(value) == expected


@pytest.mark.parametrize("bad", ["", None, 5, "pg_", "pg_xyz", "pg_" + "A" * 32, "pg_" + "a" * 31, "pg_" + "a" * 33,
                                 "PG_" + "a" * 32, "Pg_abc"])
def test_malformed_or_odd_cased_pg_ids_are_refused_not_treated_as_legacy(bad):
    with pytest.raises(vw.ViewError):
        vw.parse_public_id(bad)


def test_public_id_round_trip_and_rejects_non_engine_ids():
    raw = SHAPES["partner"]["id"]
    assert vw.parse_public_id(vw.public_id(raw)) == ("pg", raw)
    for bad in ("", "short", raw.upper(), raw + "0", None):
        with pytest.raises(vw.ViewError):
            vw.public_id(bad)


# ---------------------------------------------------------------------------------- money
@pytest.mark.parametrize("subtotal, by_mode", sorted(SHAPES["vat"].items(), key=lambda kv: int(kv[0])))
def test_python_money_equals_the_real_postgres_vat_function(subtotal, by_mode):
    for mode in ("taxable", "exempt"):
        m = vw.money([{"quantity": 1, "unit_price": int(subtotal)}], mode)
        assert m["vat"] == by_mode[mode] and m["total"] == int(subtotal) + by_mode[mode]


def test_quote_money_for_the_captured_quote():
    q = vw.quote_view(SHAPES["quote_approved"], partner_name=NAME)
    assert q["money"] == {"subtotal": 3 * 1005 + 250, "vat": (3265 + 5) // 10, "total": 3265 + 327}


# --------------------------------------------------------------------------------- statuses
@pytest.mark.parametrize("pg, legacy", [("draft", "draft"), ("submitted", "sent"), ("approved", "accepted"),
                                       ("ordered", "accepted"), ("rejected", "rejected"), ("cancelled", "cancelled")])
def test_quote_statuses(pg, legacy):
    assert vw.quote_view({**SHAPES["quote_approved"], "status": pg}, partner_name=NAME)["status"] == legacy


def test_unknown_statuses_are_refused_not_mapped_to_the_nearest_word():
    with pytest.raises(vw.ViewError):
        vw.quote_view({**SHAPES["quote_approved"], "status": "archived"}, partner_name=NAME)
    with pytest.raises(vw.ViewError):
        vw.order_view({**SHAPES["order"], "status": "weird"}, partner_name=NAME, title="t")


def test_order_status_open_depends_on_confirmed_deliveries():
    base = dict(partner_name=NAME, title="t")
    assert SHAPES["order"]["status"] == "open"
    assert vw.order_view(SHAPES["order"], **base)["status"] == "received"
    assert vw.order_view(SHAPES["order"], any_confirmed_delivery=True, **base)["status"] == "processing"
    assert SHAPES["order_after_delivery"]["status"] == "fulfilled"
    assert vw.order_view(SHAPES["order_after_delivery"], **base)["status"] == "fulfilled"


# ------------------------------------------------------------------ parity with the legacy schema
def test_quote_view_has_every_legacy_quote_column():
    q = vw.quote_view(SHAPES["quote_approved"], partner_name=NAME)
    assert set(legacy_columns("quotes")) <= set(q)
    assert {"items", "money", "customer_name"} <= set(q)


def test_order_view_has_every_legacy_order_column():
    o = vw.order_view(SHAPES["order"], partner_name=NAME, title="t", due_date="2026-12-01")
    assert set(legacy_columns("orders")) <= set(o)
    assert o["due_date"] == "2026-12-01" and o["review_state"] == "clean"
    assert vw.order_view(SHAPES["order"], partner_name=NAME, title="t")["due_date"] == ""     # never invented


def test_customer_view_has_every_legacy_customer_column():
    c = vw.customer_view(SHAPES["partner"])
    assert set(legacy_columns("customers")) <= set(c)
    assert c["name"] == SHAPES["partner"]["name"] and c["business_number"] == "2208114412"


def test_payment_view_has_the_fields_the_legacy_payment_list_returns():
    p = vw.payment_view(SHAPES["payment"], note="n", reversed_at="2026-11-06T07:49:00+00:00")
    legacy = {"id", "amount", "paid_at", "note", "created_at", "reference", "reversed_at"}
    assert legacy <= set(p) and p["amount"] == 1000 and p["note"] == "n"
    assert p["reversed_at"] == "2026-11-06T16:49:00+09:00"
    assert vw.payment_view(SHAPES["payment"])["note"] == "" and vw.payment_view(SHAPES["payment"])["reversed_at"] is None


def test_order_and_quote_items_keep_legacy_item_columns():
    q = vw.quote_view(SHAPES["quote_approved"], partner_name=NAME)
    o = vw.order_view(SHAPES["order"], partner_name=NAME, title="t")
    assert set(legacy_columns("quote_items")) <= set(q["items"][0])
    assert set(legacy_columns("order_items")) <= set(o["items"][0])
    assert [i["position"] for i in q["items"]] == sorted(i["position"] for i in q["items"])


# ----------------------------------------------------------------------------------- times
def test_timestamps_become_legacy_kst_seconds():
    assert vw.kst("2026-11-06T07:49:00.123456+00:00") == "2026-11-06T16:49:00+09:00"
    assert vw.kst("2026-11-06T07:49:00Z") == "2026-11-06T16:49:00+09:00"
    assert vw.kst(None) is None
    for bad in ("2026-11-06T07:49:00", "yesterday", 5):
        with pytest.raises(vw.ViewError):
            vw.kst(bad)
    q = vw.quote_view(SHAPES["quote_approved"], partner_name=NAME)
    assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+09:00", q["created_at"])


# --------------------------------------------------------------------------- fail closed
@pytest.mark.parametrize("key", ["id", "trade_no", "partner_id", "status", "items", "version"])
def test_missing_engine_keys_fail_closed(key):
    broken = {k: v for k, v in SHAPES["quote_approved"].items() if k != key}
    with pytest.raises(vw.ViewError):
        vw.quote_view(broken, partner_name=NAME)


def test_non_object_and_bad_vat_mode_fail_closed():
    with pytest.raises(vw.ViewError):
        vw.quote_view(None, partner_name=NAME)
    with pytest.raises(vw.ViewError):
        vw.quote_view({**SHAPES["quote_approved"], "vat_mode": "zero"}, partner_name=NAME)


# ------------------------------------------------------------------------------- not wired
def test_view_module_is_not_imported_by_any_application_module():
    for f in (ROOT / "app").glob("*.py"):
        if f.name != "pg_cinema_compat_view_v1.py":
            assert "pg_cinema_compat_view_v1" not in f.read_text(encoding="utf-8"), f.name


def test_the_legacy_ddl_parser_really_reads_the_columns_it_is_compared_against():
    # without this, an empty column list would make every parity test above pass vacuously
    assert legacy_columns("quotes") == ["id", "org_id", "customer_id", "customer_name_snapshot", "doc_no", "title",
                                        "status", "vat_mode", "created_at", "updated_at"]
    assert "due_date" in legacy_columns("orders") and "review_state" in legacy_columns("orders")
    assert "business_number" in legacy_columns("customers")


def test_items_are_returned_in_position_order_even_if_the_engine_returns_them_shuffled():
    shuffled = {**SHAPES["quote_approved"], "items": list(reversed(SHAPES["quote_approved"]["items"]))}
    assert [i["position"] for i in vw.quote_view(shuffled, partner_name=NAME)["items"]] == [0, 1]
