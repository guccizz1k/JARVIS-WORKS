"""PostgreSQL engine entity -> legacy (V22.2 UI) response shape. PURE LOGIC.
Used only by the gated ``app/pg_cinema_legacy_api_v1.py`` (V22.3); ``app/main.py`` does not import it.

The V22.2 UI keeps working unchanged only if a PG-home document looks exactly like a legacy one. This
module builds those shapes and refuses (``ViewError``) instead of inventing a value when the engine did
not supply one.

Decisions, each checked against the UI source or the engine SQL:
  * ids: PG ids are exposed as ``pg_<32 hex>``. Legacy ids are ``uuid4().hex`` and PG ids are the same
    32-hex shape, so the store of origin cannot be read from the id. The UI treats ids as opaque
    (it only joins ``order.quote_id === quote.id`` and splits its own ``id|status`` pairs on ``|``), so
    one consistent prefix on EVERY entity is safe; a prefix applied to only some entities would break the join.
  * statuses: quote ``submitted->sent``, ``approved->accepted``, ``ordered->accepted`` (a legacy quote stays
    accepted after the order exists), ``cancelled`` is passed through (the UI badge already knows it).
    An unknown engine status raises; it is never mapped to the nearest word.
  * order ``open`` becomes ``processing`` once any delivery is confirmed, else ``received``;
    ``review_state`` is ``clean`` because PG order lines cannot be edited after creation.
  * timestamps become legacy KST ISO seconds (``2026-11-06T16:49:00+09:00``).
  * money uses the legacy rule (round-half-up 10 % of the subtotal for taxable documents); the PG function
    ``cinema_pg_vat`` is compared with it on a real PostgreSQL in ``ci_cinema_pg_terms_gate_v223``.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

KST = timezone(timedelta(hours=9))
RAW_ID = re.compile(r"^[0-9a-f]{32}$")
PUBLIC_ID = re.compile(r"^pg_[0-9a-f]{32}$")
PREFIX = "pg_"

QUOTE_STATUS_TO_LEGACY = {"draft": "draft", "submitted": "sent", "approved": "accepted",
                          "ordered": "accepted", "rejected": "rejected", "cancelled": "cancelled"}
ORDER_STATUSES = {"open", "fulfilled", "cancelled"}

# The keys each mapper reads from the engine entity. ci_cinema_pg_terms_gate_v223 asserts a real PG entity
# carries all of them, so an engine change that drops one is caught on PostgreSQL, not in production.
ENTITY_KEYS = {
    "partner": ("id", "org_id", "name", "business_number", "contact_name", "email", "phone", "version", "created_at"),
    "quote": ("id", "org_id", "trade_no", "partner_id", "title", "status", "vat_mode", "version", "created_at",
              "updated_at", "items"),
    "quote_item": ("id", "position", "name", "quantity", "unit_price"),
    "order": ("id", "org_id", "trade_no", "quote_id", "partner_id", "vat_mode", "status", "created_at",
              "updated_at", "items"),
    "order_item": ("id", "source_quote_item_id", "position", "name", "quantity", "unit_price"),
    "payment": ("id", "org_id", "invoice_id", "amount_krw", "paid_on", "reference", "recorded_at"),
}


class ViewError(ValueError):
    """The engine entity cannot be shown in the legacy shape without guessing."""


# ----------------------------------------------------------------------------------- ids
def public_id(raw: str) -> str:
    if not isinstance(raw, str) or not RAW_ID.fullmatch(raw):
        raise ViewError("engine id is not 32 lowercase hex characters")
    return PREFIX + raw


def parse_public_id(value) -> tuple[str, str]:
    """('pg', raw) for ``pg_<hex>``; ('legacy', value) for anything that does not start with ``pg_``.
    A malformed ``pg_`` id is refused, never treated as legacy."""
    if not isinstance(value, str) or not value:
        raise ViewError("id must be a non-empty string")
    if value[: len(PREFIX)].lower() == PREFIX:                # any case: legacy ids never start like this
        if not PUBLIC_ID.fullmatch(value):
            raise ViewError("malformed pg_ id")
        return "pg", value[len(PREFIX):]
    return "legacy", value


# ------------------------------------------------------------------------------- helpers
def _need(entity: dict, kind: str) -> dict:
    if not isinstance(entity, dict):
        raise ViewError(f"{kind} entity must be an object")
    missing = [k for k in ENTITY_KEYS[kind] if k not in entity]
    if missing:
        raise ViewError(f"{kind} entity lacks {','.join(missing)}")
    return entity


def kst(value) -> str | None:
    """PG timestamptz text -> legacy KST ISO seconds. None stays None."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise ViewError("timestamp must be text")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ViewError("timestamp is not ISO-8601") from exc
    if parsed.tzinfo is None:
        raise ViewError("timestamp has no time zone")
    return parsed.astimezone(KST).isoformat(timespec="seconds")


def money(items: list, vat_mode: str) -> dict:
    """The legacy rule of app/main.py money(): VAT is round-half-up 10 % of the document subtotal."""
    if vat_mode not in ("taxable", "exempt"):
        raise ViewError("vat_mode must be taxable or exempt")
    subtotal = sum(int(i["quantity"]) * int(i["unit_price"]) for i in items)
    vat = (subtotal + 5) // 10 if vat_mode == "taxable" else 0
    return {"subtotal": subtotal, "vat": vat, "total": subtotal + vat}


def _lines(items: list, parent_key: str, parent_public: str, kind: str, with_source: bool) -> list:
    out = []
    for i in items:
        _need(i, kind)
        row = {"id": public_id(i["id"]), parent_key: parent_public, "name": i["name"],
               "quantity": int(i["quantity"]), "unit_price": int(i["unit_price"]), "position": int(i["position"])}
        if with_source:
            row["source_quote_item_id"] = public_id(i["source_quote_item_id"])
        out.append(row)
    return sorted(out, key=lambda r: r["position"])


# ------------------------------------------------------------------------------ mappers
def customer_view(partner: dict) -> dict:
    p = _need(partner, "partner")
    return {"id": public_id(p["id"]), "org_id": p["org_id"], "name": p["name"],
            "business_number": p["business_number"], "contact_name": p["contact_name"], "email": p["email"],
            "phone": p["phone"], "created_at": kst(p["created_at"]), "version": p["version"], "source": "pg"}


def quote_view(quote: dict, *, partner_name: str) -> dict:
    q = _need(quote, "quote")
    if q["status"] not in QUOTE_STATUS_TO_LEGACY:
        raise ViewError(f"unknown quote status {q['status']!r}")
    pub = public_id(q["id"])
    items = _lines(q["items"], "quote_id", pub, "quote_item", False)
    return {"id": pub, "org_id": q["org_id"], "customer_id": public_id(q["partner_id"]),
            "customer_name_snapshot": partner_name, "customer_name": partner_name,
            "doc_no": q["trade_no"], "title": q["title"], "status": QUOTE_STATUS_TO_LEGACY[q["status"]],
            "vat_mode": q["vat_mode"], "created_at": kst(q["created_at"]), "updated_at": kst(q["updated_at"]),
            "items": items, "money": money(items, q["vat_mode"]), "version": q["version"], "source": "pg"}


def order_view(order: dict, *, partner_name: str, title: str, due_date: str | None = None,
               any_confirmed_delivery: bool = False) -> dict:
    o = _need(order, "order")
    if o["status"] not in ORDER_STATUSES:
        raise ViewError(f"unknown order status {o['status']!r}")
    status = o["status"]
    if status == "open":
        status = "processing" if any_confirmed_delivery else "received"
    pub = public_id(o["id"])
    items = _lines(o["items"], "order_id", pub, "order_item", True)
    return {"id": pub, "org_id": o["org_id"], "customer_id": public_id(o["partner_id"]),
            "quote_id": public_id(o["quote_id"]), "customer_name_snapshot": partner_name,
            "customer_name": partner_name, "doc_no": o["trade_no"], "title": title, "status": status,
            "review_state": "clean", "vat_mode": o["vat_mode"], "due_date": due_date or "",
            "created_at": kst(o["created_at"]), "updated_at": kst(o["updated_at"]),
            "items": items, "money": money(items, o["vat_mode"]), "source": "pg"}


def payment_view(payment: dict, *, note: str | None = None, reversed_at: str | None = None) -> dict:
    p = _need(payment, "payment")
    return {"id": public_id(p["id"]), "invoice_id": public_id(p["invoice_id"]), "amount": int(p["amount_krw"]),
            "paid_at": p["paid_on"], "note": note or "", "created_at": kst(p["recorded_at"]),
            "reference": p["reference"], "reversed_at": kst(reversed_at), "source": "pg"}
