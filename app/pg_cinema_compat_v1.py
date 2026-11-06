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
import unicodedata
from datetime import date

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
PG_QUOTE_TARGETS = {"submitted", "approved", "rejected", "cancelled"}
# legacy quote status -> PG transition target. 'sent' is the UI's word for submitting a draft.
QUOTE_STATUS_MAP = {"sent": "submitted", "accepted": "approved", "rejected": "rejected"}
MAX_ITEMS, MAX_QTY, MAX_PRICE = 40, 100_000, 1_000_000_000      # PG request limits
# Column limits copied from the CHECKs in scripts/review/cinema_pg_write_engine.sql (a test pins them).
# A value the engine would reject must be refused HERE as a 422, not reach PG and come back as a 502.
PG_TEXT_LIMITS = {"partner_name": 120, "contact_name": 80, "email": 254, "phone": 40,
                  "quote_title": 150, "item_name": 150, "payment_reference": 80}


class CompatRefusal(Exception):
    """The legacy request cannot be expressed in the PG engine without loss or invention."""

    def __init__(self, code: str, detail: str, http_status: int = 409):
        super().__init__(code)
        self.code, self.detail, self.http_status = code, detail, http_status

    def as_dict(self) -> dict:
        return {"code": self.code, "detail": self.detail}


def _storable(value) -> bool:
    """True for a str that PostgreSQL ``text`` and UTF-8 can carry: no NUL and no lone surrogate.
    (``json.loads('"\\ud800"')`` yields a lone surrogate, which would crash ``.encode()`` with a 500.)"""
    if not isinstance(value, str) or "\x00" in value:
        return False
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def derive_request_id(org_id: str, user_id: str, route: str, idempotency_key: str) -> str:
    """Stable PG ``request_id`` for a retried call. Without a client key there is no honest way to
    make a retry idempotent, so the caller must pass a fresh random key and accept that."""
    if not _storable(idempotency_key) or len(idempotency_key) < 8 or len(idempotency_key) > 256:
        raise CompatRefusal("idempotency_key_required", "a text key of 8..256 characters is needed", 400)
    if not all(_storable(x) and x for x in (org_id, user_id, route)):
        raise CompatRefusal("bad_request_scope", "organisation, user and route must be non-empty text", 400)
    # length-prefixed fields: no value can contain a separator that merges two fields into one
    parts = (org_id, user_id, route, idempotency_key)
    digest = hashlib.sha256("".join(f"{len(x.encode())}:{x}" for x in parts).encode()).hexdigest()
    return "compat:" + digest[:48]


def _request_id(value: str) -> str:
    if not isinstance(value, str) or not REQUEST_ID_RE.fullmatch(value):
        raise CompatRefusal("bad_request_id", "request_id must match [A-Za-z0-9._:-]{8,128}", 400)
    return value


def _body(body) -> dict:
    """Every translator reads fields with ``.get``; anything but a JSON object is a client error (422),
    never an unhandled AttributeError that a route would turn into a 500."""
    if not isinstance(body, dict):
        raise CompatRefusal("bad_body", "the request body must be a JSON object", 422)
    return body


def _text(body: dict, field: str, *, required: bool = False, max_len: int = 255) -> str:
    """A text field: absent/None/'' -> ''; anything that is not a string, or is too long, is refused
    (a number or list is never coerced to text). ``required`` also refuses a value that is blank after the
    engine's ``btrim`` (spaces only), because the engine would refuse it with an unmapped CHECK error."""
    value = body.get(field)
    if value is None or value == "":
        if required:
            raise CompatRefusal("bad_" + field, f"{field} is required", 422)
        return ""
    if not _storable(value) or len(value) > max_len:
        raise CompatRefusal("bad_" + field, f"{field} must be text of at most {max_len} characters", 422)
    if required and not value.strip(" "):
        raise CompatRefusal("bad_" + field, f"{field} must not be blank", 422)
    return value


def _name(value, code: str, max_len: int) -> str:
    """A required name/title: text, NUL/surrogate free, 1..max_len characters and not blank after btrim."""
    if not _storable(value) or not 1 <= len(value) <= max_len or not value.strip(" "):
        raise CompatRefusal(code, f"must be 1..{max_len} characters and not blank", 422)
    return value


def _entity_id(value, code: str) -> str:
    """An id passed by the caller (not the body): non-empty text of at most 64 characters, no controls."""
    if not _storable(value) or not 1 <= len(value) <= 64 or any(
            unicodedata.category(ch).startswith("C") for ch in value):
        raise CompatRefusal(code, "id must be 1..64 characters of text", 422)
    return value


def _identity(value) -> str | None:
    """Canonical form of a user id for the same-person comparison, or None when it is unusable.
    Usable = a non-empty string without surrounding whitespace or control characters. The canonical form is
    NFKC + casefold, so ' U1', 'u1 ' (rejected as unusable) and fullwidth/case variants cannot make one
    person look like two."""
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if any(unicodedata.category(ch).startswith("C") for ch in value):
        return None
    return unicodedata.normalize("NFKC", value).casefold()


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
        name = _name(item.get("name"), "bad_items", PG_TEXT_LIMITS["item_name"])
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
    body = _body(body)
    digits = re.sub(r"[\s-]", "", _text(body, "business_number", max_len=64))
    if digits and not re.fullmatch(r"[0-9]{10}", digits, re.ASCII):
        raise CompatRefusal("business_number_not_10_digits",
                            "PG stores only a 10-digit business number; the legacy free text is not carried", 422)
    lim = PG_TEXT_LIMITS
    out = {"request_id": _request_id(request_id),
           "name": _text(body, "name", required=True, max_len=lim["partner_name"]),
           "business_number": digits, "contact_name": _text(body, "contact_name", max_len=lim["contact_name"]),
           "email": _text(body, "email", max_len=lim["email"]), "phone": _text(body, "phone", max_len=lim["phone"])}
    if partner_id is not None:
        out["partner_id"] = _entity_id(partner_id, "bad_partner_id")
        out["expected_version"] = _int(expected_version, "version", 1, 2**31 - 1)
    return out


# ------------------------------------------------------------------------------ quotes
def quote_create(body: dict, request_id: str) -> dict:
    """POST /api/quotes -> POST {pg}/quotes. ``customer_id`` becomes ``partner_id``."""
    body = _body(body)
    vat = body.get("vat_mode", "taxable")
    if not isinstance(vat, str) or vat not in ("taxable", "exempt"):
        raise CompatRefusal("bad_vat_mode", "vat_mode must be taxable or exempt", 422)
    title = _name(body.get("title"), "bad_title", PG_TEXT_LIMITS["quote_title"])
    return {"request_id": _request_id(request_id), "partner_id": _text(body, "customer_id", required=True, max_len=64),
            "title": title, "vat_mode": vat, "items": _items(body.get("items"))}


def quote_update(body: dict, request_id: str, *, expected_version: int,
                 current_partner_id: str, current_vat_mode: str) -> dict:
    """PUT /api/quotes/{id} -> PUT {pg}/quotes/{id}. PG cannot change the partner or VAT mode of an
    existing quote; a legacy edit that tries to is refused instead of ignored."""
    body = _body(body)
    if body.get("customer_id") not in (None, current_partner_id):
        raise CompatRefusal("pg_quote_partner_is_immutable", "the customer of an existing quote cannot change")
    if body.get("vat_mode") not in (None, current_vat_mode):
        raise CompatRefusal("pg_quote_vat_mode_is_immutable", "the VAT mode of an existing quote cannot change")
    title = _name(body.get("title"), "bad_title", PG_TEXT_LIMITS["quote_title"])
    return {"request_id": _request_id(request_id), "expected_version": _int(expected_version, "version", 1, 2**31 - 1),
            "title": title, "items": _items(body.get("items"))}


def quote_transition(body: dict, request_id: str, *, expected_version: int,
                     actor_id: str | None = None, submitted_by: str | None = None) -> dict:
    """POST /api/quotes/{id}/status -> POST {pg}/quotes/{id}/transition.

    Approving (legacy ``accepted``) needs the acting user and the quote's submitter: the same person
    may not do both. Missing information is a refusal, never a pass."""
    legacy = _body(body).get("status")
    if not isinstance(legacy, str) or legacy not in QUOTE_STATUS_MAP:
        raise CompatRefusal("unknown_quote_status", "status must be sent, accepted or rejected", 422)
    if legacy == "accepted":
        quote_approval_guard(actor_id, submitted_by)
    return {"request_id": _request_id(request_id), "expected_version": _int(expected_version, "version", 1, 2**31 - 1),
            "to": QUOTE_STATUS_MAP[legacy]}


def quote_approval_guard(actor_id, submitted_by) -> None:
    """Two-person rule for quote approval (application level; the engine does not enforce it).
    Fail-closed: a missing, non-text, blank, padded or control-character identity is "unknown" and refuses;
    two identities that are equal after NFKC + casefold are the same person and refuse."""
    actor, submitter = _identity(actor_id), _identity(submitted_by)
    if actor is None or submitter is None:
        raise CompatRefusal("quote_approval_identity_unknown",
                            "the approver and the submitter must both be known to approve a quote", 409)
    if actor == submitter:
        raise CompatRefusal("quote_second_person_required",
                            "a quote must be approved by a different administrator than the one who submitted it", 409)


# ---------------------------------------------------------------------- orders / money
def order_from_quote(body: dict, request_id: str) -> dict:
    """POST /api/orders/from-quote -> POST {pg}/orders. ``due_date`` has no PG column."""
    body = _body(body)
    if body.get("due_date") not in (None, ""):
        raise CompatRefusal("due_date_not_stored_in_pg",
                            "cinema_pg_orders has no due date; carrying it would need a schema change "
                            "that has not been approved, and dropping it would lose the value")
    return {"request_id": _request_id(request_id), "quote_id": _text(body, "quote_id", required=True, max_len=64)}


def payment_for_invoice(body: dict, request_id: str, *, today: date | None = None) -> dict:
    """POST /api/invoices/{id}/payments -> POST {pg}/invoices/{id}/payments. ``note`` has no PG column."""
    body = _body(body)
    if body.get("note") not in (None, ""):      # same rule as due_date: 0/False/[] are values too
        raise CompatRefusal("note_not_stored_in_pg", "cinema_pg_payments has no note column")
    paid = body.get("paid_at")
    paid_on = paid.isoformat() if isinstance(paid, date) else paid
    if not isinstance(paid_on, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", paid_on, re.ASCII):
        raise CompatRefusal("bad_paid_on", "paid_at must be YYYY-MM-DD", 422)
    try:
        paid_date = date.fromisoformat(paid_on)
    except ValueError:
        raise CompatRefusal("bad_paid_on", "paid_at is not a real calendar date", 422) from None
    if paid_date > (today or date.today()):
        raise CompatRefusal("future_payment", "PG refuses a payment dated in the future", 422)
    return {"request_id": _request_id(request_id), "amount_krw": _int(body.get("amount"), "amount", 1, 100_000_000_000),
            "paid_on": paid_on,
            "reference": _text(body, "reference", required=True, max_len=PG_TEXT_LIMITS["payment_reference"])}


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


# Constraint violations raised by the PROPOSED migrations (not by an engine RAISE). The name must appear as
# ``CONSTRAINT <name>`` in the named SQL file; a test checks it. Harmless while the migration is not applied.
PG_CONSTRAINT_ERRORS = (
    ("23514", "cinema_pg_quote_two_person", "quote_second_person_required", 409,
     "견적은 제출한 사람과 다른 관리자가 승인해야 합니다.",
     "scripts/review/cinema_pg_v223_quote_two_person_proposal.sql"),
)


def map_pg_error(sqlstate: str, message: str) -> CompatRefusal:
    """Translate an engine error into a stable refusal. Unknown errors never leak the raw message."""
    for state, name, code, status, ko, _file in PG_CONSTRAINT_ERRORS:
        if sqlstate == state and f'"{name}"' in (message or ""):
            return CompatRefusal(code, ko, status)
    for state, fragment, code, status, ko in PG_ERROR_MAP:
        if sqlstate == state and fragment in (message or ""):
            return CompatRefusal(code, ko, status)
    return CompatRefusal("pg_engine_error", "the database refused the request", 502)
