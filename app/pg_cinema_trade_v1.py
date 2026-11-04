"""CINEMA <-> PostgreSQL trade write API (review candidate; NOT mounted by default).

Thin FastAPI adapter over the SQL functions in scripts/review/cinema_pg_write_engine.sql.
All business rules (state machine, quantities, VAT, separation of duty, idempotency,
tenant isolation) live in PostgreSQL; this layer only

  * requires a server-verified session + CSRF (supplied by the integrator, never by the browser),
  * runs each request in ONE transaction as the least-privileged role `jw_cinema_writer`
    (SET LOCAL ROLE) with `jw.session_hash` set for that transaction only,
  * maps SQLSTATE to HTTP status without leaking internals.

Honesty: a 200 response means the database committed the change. It does not mean a bank
settled a payment or that goods were physically delivered; those are human-attested
internal records (see the `basis` flags returned by the trace endpoint).

Requires a login role (not a superuser, not BYPASSRLS) that is a member of
`jw_cinema_writer`. Review-only until that connection exists and the E2E gates pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Protocol

from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Query, Request, Response
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

WRITER_ROLE = "jw_cinema_writer"
_REQ_ID = r"^[A-Za-z0-9._:-]{8,128}$"
MAX_EVIDENCE_BYTES = 5 * 1024 * 1024
EVIDENCE_TYPES = ("application/pdf", "image/png", "image/jpeg")


@dataclass(frozen=True)
class VerifiedSession:
    session_hash: str
    csrf_verified: bool


class SQLGateway(Protocol):
    def query(self, session_hash: str, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]: ...


class PsycopgWriterGateway:
    """One transaction per call: SET LOCAL ROLE -> set_config(local) -> statement."""

    def __init__(self, connect: Callable[[], Any]):
        self._connect = connect

    def query(self, session_hash: str, sql: str, params: tuple[Any, ...]) -> list[dict[str, Any]]:
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(f"SET LOCAL ROLE {WRITER_ROLE}")
                    cur.execute("SELECT set_config('jw.session_hash', %s, true)", (session_hash,))
                    cur.execute(sql, params)
                    columns = [col.name for col in cur.description] if cur.description else []
                    return [dict(zip(columns, row)) for row in cur.fetchall()] if columns else []


# ---------------------------------------------------------------- request models
class _Base(BaseModel):
    request_id: str = Field(pattern=_REQ_ID)


class PartnerIn(_Base):
    partner_id: str | None = Field(default=None, max_length=64)
    name: str = Field(min_length=1, max_length=120)
    business_number: str = Field(default="", pattern=r"^([0-9]{10})?$")
    contact_name: str = Field(default="", max_length=80)
    email: str = Field(default="", max_length=254)
    phone: str = Field(default="", max_length=40)
    expected_version: int | None = Field(default=None, ge=1)


class LineIn(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    quantity: int = Field(ge=1, le=100000)
    unit_price: int = Field(ge=0, le=1_000_000_000)  # integer KRW only


class QuoteCreate(_Base):
    partner_id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=150)
    vat_mode: str = Field(pattern=r"^(taxable|exempt)$")
    items: list[LineIn] = Field(min_length=1, max_length=40)


class QuoteUpdate(_Base):
    expected_version: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=150)
    items: list[LineIn] = Field(min_length=1, max_length=40)


class QuoteTransition(_Base):
    expected_version: int = Field(ge=1)
    to: str = Field(pattern=r"^(submitted|approved|rejected|cancelled)$")


class OrderCreate(_Base):
    quote_id: str = Field(min_length=1, max_length=64)


class DeliveryLine(BaseModel):
    order_item_id: str = Field(min_length=1, max_length=64)
    quantity: int = Field(ge=1, le=100000)


class DeliveryRecord(_Base):
    lines: list[DeliveryLine] = Field(min_length=1, max_length=40)
    evidence_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_name: str = Field(min_length=1, max_length=180)


class Reason(_Base):
    reason: str = Field(min_length=1, max_length=300)


class Plain(_Base):
    pass


class PaymentIn(_Base):
    amount_krw: int = Field(ge=1, le=100_000_000_000)
    paid_on: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    reference: str = Field(default="", max_length=120)


# --------------------------------------------------------------------- SQL map
def _fn(name: str, arity: int) -> str:
    return f"SELECT jw_dev.{name}({', '.join(['%s'] * arity)}) AS result"


# Optional per-collection SELECT expression; default is the whole row. Evidence is listed WITHOUT file bytes.
READ_SELECT = {
    "evidence": "jsonb_build_object('id',t.id,'content_sha256',t.content_sha256,'size_bytes',t.size_bytes,"
                "'content_type',t.content_type,'file_name',t.file_name,'uploaded_by',t.uploaded_by,'created_at',t.created_at)",
}

READ_TABLES = {
    "partners": ("cinema_pg_partners", "created_at DESC, id"),
    "quotes": ("cinema_pg_quotes", "created_at DESC, id"),
    "orders": ("cinema_pg_orders", "created_at DESC, id"),
    "deliveries": ("cinema_pg_deliveries", "recorded_at DESC, id"),
    "statements": ("cinema_pg_statements", "created_at DESC, id"),
    "invoices": ("cinema_pg_invoices", "created_at DESC, id"),
    "payments": ("cinema_pg_payments", "recorded_at DESC, id"),
    # line tables and reversals: needed by the UI to rebuild a deal from server state
    "quote-items": ("cinema_pg_quote_items", "quote_id, position"),
    "order-items": ("cinema_pg_order_items", "order_id, position"),
    "delivery-items": ("cinema_pg_delivery_items", "delivery_id, order_item_id"),
    "payment-reversals": ("cinema_pg_payment_reversals", "reversed_at, payment_id"),
    "evidence": ("cinema_pg_evidence_files", "created_at DESC, id"),
}


def create_router(gateway: SQLGateway, authorize: Callable[[Request], VerifiedSession]) -> APIRouter:
    """`authorize` MUST validate the signed session and CSRF token server-side."""
    router = APIRouter(prefix="/api/pg-stage/cinema-trade", tags=["cinema-trade-stage"])

    def verified(request: Request) -> VerifiedSession:
        identity = authorize(request)
        if not isinstance(identity, VerifiedSession) or len(identity.session_hash) < 16:
            raise HTTPException(401, "Verified session required")
        if request.method not in ("GET", "HEAD", "OPTIONS") and not identity.csrf_verified:
            raise HTTPException(403, "CSRF verification required")
        return identity

    def invoke(request: Request, sql: str, params: tuple[Any, ...],
               identity: VerifiedSession | None = None) -> list[dict[str, Any]]:
        identity = identity or verified(request)
        try:
            return gateway.query(identity.session_hash, sql, params)
        except HTTPException:
            raise
        except Exception as exc:  # mapped below; details are never echoed verbatim
            raise _map_error(exc) from exc

    def write(request: Request, name: str, *params: Any) -> dict[str, Any]:
        rows = invoke(request, _fn(name, len(params)), params)
        if not rows or rows[0].get("result") is None:
            raise HTTPException(503, "Trade datastore returned no result")
        return rows[0]["result"]

    # ------------------------------------------------------------- partners
    @router.post("/partners")
    def partner_upsert(request: Request, body: PartnerIn):
        return write(request, "cinema_pg_partner_upsert", body.request_id, body.partner_id, body.name,
                     body.business_number, body.contact_name, body.email, body.phone, body.expected_version)

    # --------------------------------------------------------------- quotes
    @router.post("/quotes")
    def quote_create(request: Request, body: QuoteCreate):
        return write(request, "cinema_pg_quote_create", body.request_id, body.partner_id, body.title,
                     body.vat_mode, _items_json(body.items))

    @router.put("/quotes/{quote_id}")
    def quote_update(request: Request, quote_id: str, body: QuoteUpdate):
        return write(request, "cinema_pg_quote_update", body.request_id, quote_id, body.expected_version,
                     body.title, _items_json(body.items))

    @router.post("/quotes/{quote_id}/transition")
    def quote_transition(request: Request, quote_id: str, body: QuoteTransition):
        return write(request, "cinema_pg_quote_transition", body.request_id, quote_id,
                     body.expected_version, body.to)

    # --------------------------------------------------------------- orders
    @router.post("/orders")
    def order_create(request: Request, body: OrderCreate):
        return write(request, "cinema_pg_order_create", body.request_id, body.quote_id)

    # ----------------------------------------------------------- deliveries
    @router.post("/orders/{order_id}/deliveries")
    def delivery_record(request: Request, order_id: str, body: DeliveryRecord):
        lines = [{"order_item_id": l.order_item_id, "quantity": l.quantity} for l in body.lines]
        return write(request, "cinema_pg_delivery_record", body.request_id, order_id, _json(lines),
                     body.evidence_sha256, body.evidence_name)

    @router.post("/deliveries/{delivery_id}/confirm")
    def delivery_confirm(request: Request, delivery_id: str, body: Plain):
        return write(request, "cinema_pg_delivery_confirm", body.request_id, delivery_id)

    @router.post("/deliveries/{delivery_id}/cancel")
    def delivery_cancel(request: Request, delivery_id: str, body: Reason):
        return write(request, "cinema_pg_delivery_cancel", body.request_id, delivery_id, body.reason)

    @router.post("/deliveries/{delivery_id}/reverse")
    def delivery_reverse(request: Request, delivery_id: str, body: Reason):
        return write(request, "cinema_pg_delivery_reverse", body.request_id, delivery_id, body.reason)

    # ----------------------------------------------------------- statements
    @router.post("/deliveries/{delivery_id}/statements")
    def statement_create(request: Request, delivery_id: str, body: Plain):
        return write(request, "cinema_pg_statement_create", body.request_id, delivery_id)

    @router.post("/statements/{statement_id}/confirm")
    def statement_confirm(request: Request, statement_id: str, body: Plain):
        return write(request, "cinema_pg_statement_confirm", body.request_id, statement_id)

    @router.post("/statements/{statement_id}/void")
    def statement_void(request: Request, statement_id: str, body: Reason):
        return write(request, "cinema_pg_statement_void", body.request_id, statement_id, body.reason)

    # ------------------------------------------------------------- invoices
    @router.post("/statements/{statement_id}/invoices")
    def invoice_create(request: Request, statement_id: str, body: Plain):
        return write(request, "cinema_pg_invoice_create", body.request_id, statement_id)

    @router.post("/invoices/{invoice_id}/review")
    def invoice_review(request: Request, invoice_id: str, body: Plain):
        return write(request, "cinema_pg_invoice_review", body.request_id, invoice_id)

    @router.post("/invoices/{invoice_id}/confirm")
    def invoice_confirm(request: Request, invoice_id: str, body: Plain):
        return write(request, "cinema_pg_invoice_confirm", body.request_id, invoice_id)

    @router.post("/invoices/{invoice_id}/void")
    def invoice_void(request: Request, invoice_id: str, body: Reason):
        return write(request, "cinema_pg_invoice_void", body.request_id, invoice_id, body.reason)

    # ------------------------------------------------------------- payments
    @router.post("/invoices/{invoice_id}/payments")
    def payment_record(request: Request, invoice_id: str, body: PaymentIn):
        return write(request, "cinema_pg_payment_record", body.request_id, invoice_id, body.amount_krw,
                     body.paid_on, body.reference)

    @router.post("/payments/{payment_id}/reverse")
    def payment_reverse(request: Request, payment_id: str, body: Reason):
        return write(request, "cinema_pg_payment_reverse", body.request_id, payment_id, body.reason)

    # ------------------------------------------------------------- evidence
    @router.post("/evidence")
    async def evidence_put(request: Request, request_id: str = Query(pattern=_REQ_ID),
                           name: str = Query(min_length=1, max_length=180)):
        """Raw file body (application/pdf | image/png | image/jpeg, 1 byte..5 MB). The DATABASE recomputes
        the SHA-256 and checks type/magic bytes; the browser-supplied hash is never trusted."""
        identity = verified(request)            # authenticate + CSRF BEFORE reading any body bytes
        ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype not in EVIDENCE_TYPES:
            raise HTTPException(415, "Unsupported evidence type")
        declared = request.headers.get("content-length", "")
        if declared.isdigit() and int(declared) > MAX_EVIDENCE_BYTES:
            raise HTTPException(413, "Evidence file is too large")
        chunks, total = [], 0
        async for chunk in request.stream():
            total += len(chunk)
            if total > MAX_EVIDENCE_BYTES:
                raise HTTPException(413, "Evidence file is too large")
            chunks.append(chunk)
        if total == 0:
            raise HTTPException(422, "Evidence file is empty")
        rows = await run_in_threadpool(
            invoke, request, "SELECT jw_dev.cinema_pg_evidence_put(%s,%s,%s,%s) AS result",
            (request_id, name, ctype, b"".join(chunks)), identity)
        if not rows or rows[0].get("result") is None:
            raise HTTPException(503, "Trade datastore returned no result")
        return rows[0]["result"]

    @router.post("/evidence/{evidence_id}/open")
    def evidence_open(request: Request, evidence_id: str, body: Plain):
        """Audited download. POST (not GET) because opening writes an audit row that delivery
        confirmation depends on, and so that CSRF protection applies."""
        rows = invoke(request, "SELECT * FROM jw_dev.cinema_pg_evidence_open(%s,%s)", (body.request_id, evidence_id))
        if not rows:
            raise HTTPException(404, "Not found")
        row = rows[0]
        content = bytes(row["o_content"])
        if row["o_content_type"] not in EVIDENCE_TYPES:
            raise HTTPException(503, "Trade datastore unavailable")
        return Response(content=content, media_type=row["o_content_type"], headers={
            "Content-Disposition": "attachment; filename*=UTF-8''" + quote(str(row["o_file_name"]), safe=""),
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store",
            "X-Evidence-SHA256": str(row["o_sha256"])})

    # ---------------------------------------------------------------- reads
    @router.get("/trace/{trade_no}")
    def trace(request: Request, trade_no: str):
        rows = invoke(request, "SELECT jw_dev.cinema_pg_trade_trace(%s) AS result", (trade_no,))
        return rows[0]["result"] if rows else {}

    @router.get("/integrity")
    def integrity(request: Request):
        return invoke(request, "SELECT check_name, entity_id, detail FROM jw_dev.cinema_pg_integrity_check()", ())

    @router.get("/{kind}")
    def listing(request: Request, kind: str, limit: int = Query(50, ge=1, le=200),
                offset: int = Query(0, ge=0, le=100000)):
        if kind not in READ_TABLES:
            raise HTTPException(404, "Unknown collection")
        table, order = READ_TABLES[kind]  # fixed allow-list: never interpolates user input
        select = READ_SELECT.get(kind, "to_jsonb(t)")
        return invoke(request,
                      f"SELECT {select} AS row FROM jw_dev.{table} t ORDER BY {order} LIMIT %s OFFSET %s",
                      (limit, offset))

    return router


# ------------------------------------------------------------------- helpers
def _json(value: Any):
    from psycopg.types.json import Jsonb  # imported lazily: review modules must import without a DB driver
    return Jsonb(value)


def _items_json(items: list[LineIn]):
    return _json([{"name": i.name, "quantity": i.quantity, "unit_price": i.unit_price} for i in items])


_STATUS = {
    "42501": (403, "Not permitted"),
    "23514": (422, "Request rejected by trade rules"),
    "22023": (422, "Request rejected by trade rules"),
    "P0002": (404, "Not found"),
    "23505": (409, "Conflict with an existing record"),
    "40001": (409, "Concurrent change; reload and retry"),
    "40P01": (409, "Concurrent change; reload and retry"),
    "55P03": (409, "Resource busy; retry"),
}


def _map_error(exc: Exception) -> HTTPException:
    code = getattr(exc, "sqlstate", None)
    status, text = _STATUS.get(code, (503, "Trade datastore unavailable"))
    # SQL diagnostics are untrusted strings and can include user values or secrets.
    # Never reflect message_primary, SQL text, IDs, roles, or constraint details
    # into HTTP responses. Typed SQLSTATE -> fixed public message only.
    return HTTPException(status, text)
