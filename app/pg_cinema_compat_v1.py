"""Legacy (V22.2 UI) request -> PostgreSQL cinema-trade request translation. PURE LOGIC.

Status: NOT WIRED INTO ANY ROUTE. Importing this module changes nothing in the running app, so
the existing SQLite-backed behaviour is untouched. It is the first, testable piece of the
server-side compatibility layer (option A): it decides, for every field the V22.2 UI can send,
whether it can be carried into the PostgreSQL engine EXACTLY, and refuses (with a stable code)
when it cannot. Nothing is dropped silently and nothing is invented.

Rules this module enforces (all verified against ``scripts/review/cinema_pg_write_engine.sql``
and its 222-case test script):
  * the PG chain is quote -> order -> recorded delivery (with uploaded evidence, confirmed by a
    DIFFERENT user) -> confirmed statement -> reviewed+confirmed invoice -> payment. The legacy
    shortcut "invoice straight from an order" has NO honest PG equivalent, because that would
    need a fabricated delivery and statement. It is refused, never synthesised.
  * fields the PG tables have no column for (order ``due_date``, payment ``note``) are refused
    rather than discarded, because discarding would lose user data.
  * statuses are mapped only where the meaning is the same; ``accepted`` means PG ``approved``.
    PG requires an ADMINISTRATOR for it but, measured on the engine SQL, does NOT stop the person
    who submitted the quote from approving it (only delivery confirmation is DB-enforced as
    "different person"). The two-person quote rule is therefore enforced HERE, fail-closed, until
    the database constraint in docs/review/cinema-pg-v223-terms-and-two-person-proposal.md exists.

Standard library only; no database, no FastAPI, no pydantic.
"""
from __future__ import annotations

import hashlib
import re
from datetime import date

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
PG_QUOTE_TARGETS = {"submitted", "approved", "rejected", "cancelled"}
# legacy quote status -> PG transition target. 'sent' is the UI's word for submitting a draft.
QUOTE_STATUS_MAP = {"sent": "submitted", "accepted": "approved", "rejected": "rejected"}
MAX_ITEMS, MAX_QTY, MAX_PRICE = 40, 100_000, 1_000_000_000      # PG request limits


class CompatRefusal(Exception):
    """The legacy request cannot be expressed in the PG engine without loss or invention."""

    def __init__(self, code: str, detail: str, http_status: int = 409):
        super().__init__(code)
        self.code, self.detail, self.http_status = code, detail, http_status

    def as_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail}


def derive_request_id(org_id: str, user_id: str, route: str, idempotency_key: str) -> str:
    """Stable PG ``request_id`` for a retried call. Without a client key there is no honest way to
    make a retry idempotent, so the caller must pass a fresh random key and accept that."""
    if not idempotency_key or len(idempotency_key) < 8:
        raise CompatRefusal("idempotency_key_required", "a key of at least 8 characters is needed", 400)
    # length-prefixed fields: no value can contain a separator that merges two fields into one
    parts = (org_id, user_id, route, idempotency_key)
    digest = hashlib.sha256("".join(f"{len(x.encode())}:{x}" for x in parts).encode()).hexdigest()
    return "compat:" + digest[:48]


def _request_id(value: str) -> str:
    if not isinstance(value, str) or not REQUEST_ID_RE.fullmatch(value):
        raise CompatRefusal("bad_request_id", "request_id must match [A-Za-z0-9._:-]{8,128}", 400)
    return value


def _int(value, field: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CompatRefusal("not_integer_krw", f"{field} must be an integer (KRW has no fractions)", 422)
    if not lo <= value <= hi:
        raise CompatRefusal("out_of_range", f"{field} must be between {lo} and {hi}", 422)
    return value


def _items(items) -> list:
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_ITEMS:
        raise CompatRefusal("bad_items", f"1..{MAX_ITEMS} line items are required", 422)
    out = []
    for item in items:
        if not isinstance(item, dict):
            raise CompatRefusal("bad_items", "each line item must be an object", 422)
        extra = set(item) - {"name", "quantity", "unit_price"}
        if extra:
            raise CompatRefusal("unsupported_line_field",
                                "line fields the PG engine does not store: " + ",".join(sorted(extra)))
        name = item.get("name")
        if not isinstance(name, str) or not 1 <= len(name) <= 150:
            raise CompatRefusal("bad_items", "line name must be 1..150 characters", 422)
        out.append({"name": name, "quantity": _int(item.get("quantity"), "quantity", 1, MAX_QTY),
                    "unit_price": _int(item.get("unit_price"), "unit_price", 0, MAX_PRICE)})
    return out


# ---------------------------------------------------------------- customers -> partners
def partner_from_customer(body: dict, request_id: str, *, partner_id: str | None = None,
                          expected_version: int | None = None) -> dict:
    """PUT/POST /api/customers -> POST {pg}/partners (upsert). Updating needs the PG version."""
    if (partner_id is None) != (expected_version is None):
        raise CompatRefusal("version_required_for_update",
                            "an update must carry both the partner id and its current version", 422)
    digits = re.sub(r"[\s-]", "", body.get("business_number") or "")
    if digits and not re.fullmatch(r"[0-9]{10}", digits):
        raise CompatRefusal("business_number_not_10_digits",
                            "PG stores only a 10-digit business number; the legacy free text is not carried", 422)
    out = {"request_id": _request_id(request_id), "name": body.get("name") or "",
           "business_number": digits, "contact_name": body.get("contact_name") or "",
           "email": body.get("email") or "", "phone": body.get("phone") or ""}
    if not 1 <= len(out["name"]) <= 120:
        raise CompatRefusal("bad_name", "name must be 1..120 characters", 422)
    if partner_id is not None:
        out["partner_id"], out["expected_version"] = partner_id, expected_version
    return out


# ------------------------------------------------------------------------------ quotes
def quote_create(body: dict, request_id: str) -> dict:
    """POST /api/quotes -> POST {pg}/quotes. ``customer_id`` becomes ``partner_id``."""
    vat = body.get("vat_mode", "taxable")
    if vat not in ("taxable", "exempt"):
        raise CompatRefusal("bad_vat_mode", "vat_mode must be taxable or exempt", 422)
    title = body.get("title")
    if not isinstance(title, str) or not 1 <= len(title) <= 150:
        raise CompatRefusal("bad_title", "title must be 1..150 characters", 422)
    return {"request_id": _request_id(request_id), "partner_id": body.get("customer_id") or "",
            "title": title, "vat_mode": vat, "items": _items(body.get("items"))}


def quote_update(body: dict, request_id: str, *, expected_version: int,
                 current_partner_id: str, current_vat_mode: str) -> dict:
    """PUT /api/quotes/{id} -> PUT {pg}/quotes/{id}. PG cannot change the partner or VAT mode of an
    existing quote; a legacy edit that tries to is refused instead of ignored."""
    if body.get("customer_id") not in (None, current_partner_id):
        raise CompatRefusal("pg_quote_partner_is_immutable", "the customer of an existing quote cannot change")
    if body.get("vat_mode") not in (None, current_vat_mode):
        raise CompatRefusal("pg_quote_vat_mode_is_immutable", "the VAT mode of an existing quote cannot change")
    title = body.get("title")
    if not isinstance(title, str) or not 1 <= len(title) <= 150:
        raise CompatRefusal("bad_title", "title must be 1..150 characters", 422)
    return {"request_id": _request_id(request_id), "expected_version": _int(expected_version, "version", 1, 2**31 - 1),
            "title": title, "items": _items(body.get("items"))}


def quote_transition(body: dict, request_id: str, *, expected_version: int,
                     actor_id: str | None = None, submitted_by: str | None = None) -> dict:
    """POST /api/quotes/{id}/status -> POST {pg}/quotes/{id}/transition.

    Approving (legacy ``accepted``) needs the acting user and the quote's submitter: the same person
    may not do both. Missing information is a refusal, never a pass."""
    legacy = body.get("status")
    if legacy not in QUOTE_STATUS_MAP:
        raise CompatRefusal("unknown_quote_status", "status must be sent, accepted or rejected", 422)
    if legacy == "accepted":
        quote_approval_guard(actor_id, submitted_by)
    return {"request_id": _request_id(request_id), "expected_version": _int(expected_version, "version", 1, 2**31 - 1),
            "to": QUOTE_STATUS_MAP[legacy]}


def quote_approval_guard(actor_id: str | None, submitted_by: str | None) -> None:
    """Two-person rule for quote approval (application level; the engine does not enforce it)."""
    if not actor_id or not submitted_by:
        raise CompatRefusal("quote_approval_identity_unknown",
                            "the approver and the submitter must both be known to approve a quote", 409)
    if actor_id == submitted_by:
        raise CompatRefusal("quote_second_person_required",
                            "a quote must be approved by a different administrator than the one who submitted it", 409)


# ---------------------------------------------------------------------- orders / money
def order_from_quote(body: dict, request_id: str) -> dict:
    """POST /api/orders/from-quote -> POST {pg}/orders. ``due_date`` has no PG column."""
    if body.get("due_date") not in (None, ""):
        raise CompatRefusal("due_date_not_stored_in_pg",
                            "cinema_pg_orders has no due date; carrying it would need a schema change "
                            "that has not been approved, and dropping it would lose the value")
    return {"request_id": _request_id(request_id), "quote_id": body.get("quote_id") or ""}


def payment_for_invoice(body: dict, request_id: str, *, today: date | None = None) -> dict:
    """POST /api/invoices/{id}/payments -> POST {pg}/invoices/{id}/payments. ``note`` has no PG column."""
    if body.get("note"):
        raise CompatRefusal("note_not_stored_in_pg", "cinema_pg_payments has no note column")
    paid = body.get("paid_at")
    paid_on = paid.isoformat() if isinstance(paid, date) else paid
    if not isinstance(paid_on, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", paid_on):
        raise CompatRefusal("bad_paid_on", "paid_at must be YYYY-MM-DD", 422)
    if date.fromisoformat(paid_on) > (today or date.today()):
        raise CompatRefusal("future_payment", "PG refuses a payment dated in the future", 422)
    return {"request_id": _request_id(request_id), "amount_krw": _int(body.get("amount"), "amount", 1, 100_000_000_000),
            "paid_on": paid_on, "reference": str(body.get("reference") or "")[:120]}


# --------------------------------------------------- steps with NO honest PG equivalent
UNSUPPORTED = {
    "invoice_from_order": ("pg_requires_confirmed_delivery_and_statement",
                           "PG invoices come from a confirmed statement, which comes from a delivery with uploaded "
                           "evidence confirmed by a second user. No delivery or statement is fabricated."),
    "statement_from_order": ("pg_statement_needs_confirmed_delivery",
                             "PG statements are created from a confirmed delivery, not from an order."),
    "order_status_set": ("pg_order_status_is_derived",
                         "PG order status follows deliveries and cannot be set directly."),
    "order_acknowledge": ("pg_has_no_order_acknowledgement", "PG has no acknowledgement step."),
    "order_change": ("pg_order_lines_are_fixed", "PG order lines come from the approved quote and are guarded."),
    "invoice_adjustment": ("pg_has_no_adjustment_tables", "complex settlement has no PostgreSQL tables yet."),
}


def unsupported(step: str) -> CompatRefusal:
    code, detail = UNSUPPORTED[step]
    return CompatRefusal(code, detail, 409)


# ------------------------------------------------------------ PG engine error -> stable refusal
# (sqlstate, message fragment, code, http status, Korean user message). Each fragment and SQLSTATE
# is copied from a RAISE in scripts/review/cinema_pg_write_engine.sql; a test fails if the engine
# text drifts. Anything not listed becomes a generic 502 WITHOUT the raw database message.
PG_ERROR_MAP = (
    ("42501", "approver must differ from the person who recorded the delivery", "delivery_second_person_required", 409,
     "납품 확정은 납품을 기록한 사람과 다른 관리자가 해야 합니다."),
    ("42501", "administrator approval role required", "admin_required", 403, "관리자 권한이 필요합니다."),
    ("42501", "valid session required", "session_required", 401, "로그인이 필요합니다."),
    ("40001", "version is stale", "stale_version", 409, "다른 사용자가 먼저 수정했습니다. 새로 고침 후 다시 시도하세요."),
    ("23505", "request id was already used for a different request", "idempotency_conflict", 409,
     "같은 요청 번호가 다른 내용으로 이미 사용되었습니다."),
    ("23505", "duplicate payment reference for this invoice", "duplicate_payment_reference", 409,
     "이 청구서에 같은 입금 참조가 이미 있습니다."),
    ("23514", "overpayment blocked", "overpayment", 409, "청구 잔액을 초과하는 입금입니다."),
    ("23514", "payments require a confirmed invoice", "invoice_not_confirmed", 409, "확정된 청구서에만 입금을 기록할 수 있습니다."),
    ("23514", "only an approved quote can become an order", "quote_not_approved", 409, "승인된 견적만 수주로 전환할 수 있습니다."),
    ("23514", "delivery evidence file must be uploaded to the server first", "evidence_required", 422,
     "납품 증빙 파일을 먼저 서버에 올려야 합니다."),
    ("23514", "statements require a confirmed delivery", "delivery_not_confirmed", 409, "확정된 납품에서만 명세를 만들 수 있습니다."),
    ("23514", "invoices require a confirmed statement", "statement_not_confirmed", 409, "확정된 명세에서만 청구서를 만들 수 있습니다."),
    ("P0002", "not found", "not_found", 404, "대상을 찾을 수 없습니다."),
)


def map_pg_error(sqlstate: str, message: str) -> CompatRefusal:
    """Translate an engine error into a stable refusal. Unknown errors never leak the raw message."""
    for state, fragment, code, status, ko in PG_ERROR_MAP:
        if sqlstate == state and fragment in (message or ""):
            return CompatRefusal(code, ko, status)
    return CompatRefusal("pg_engine_error", "the database refused the request", 502)
