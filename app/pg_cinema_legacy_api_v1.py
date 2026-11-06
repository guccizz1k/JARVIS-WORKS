"""Legacy (V22.2 UI) API contract served from the CINEMA PostgreSQL engine. OFF by default.

This is the WIRED part of the server-side compatibility layer: the request translation in
``pg_cinema_compat_v1`` and the response shapes in ``pg_cinema_compat_view_v1`` are executed against the
real engine functions of ``scripts/review/cinema_pg_write_engine.sql``.

Mounting (``register_legacy_api_v1``) needs BOTH
  * ``JW_PG_CINEMA_LEGACY_API_V1 == ISOLATED_DEV_LEGACY_CONTRACT_ONLY`` and
  * the existing CINEMA trade gate (``pg_cinema_register_v1.cinema_trade_enabled``), which itself needs the
    V8.4/V8.5/V9.0 PostgreSQL stage gates and a non-production environment.

Per-company switch: ``JW_PG_CINEMA_LEGACY_ORGS`` is a comma separated allow-list of org ids, read on EVERY
request. An org that is not listed (the default: nobody) gets ``409 pg_store_disabled_for_org`` from every
route here, before any read or write. Removing an org is the rollback: nothing is deleted, and listing it
again shows the same records.

Per request, inside ONE PostgreSQL transaction running as ``jw_cinema_writer``:
  1. identity (actor, org, role, CSRF token) comes from ``jw_dev.stage_identity_v84()`` - never from the client;
  2. unsafe methods compare ``X-CSRF-Token`` with the stored token (constant time);
  3. the org must be on the allow-list;
  4. reads use the writer role's RLS-limited SELECT, writes call the engine functions; a write and the
     record it returns, or a write and its side record (order due date, payment note), commit together.

Store routing: ``pg_<32 hex>`` ids are PostgreSQL records. Any other id belongs to the legacy store and is
refused with ``409 legacy_store_record`` (it is never looked up here, never 404, never re-created).
A malformed ``pg_`` id is ``422``. Steps without an honest PG equivalent (invoice straight from an order,
setting an order status, ...) are refused with the stable codes of ``pg_cinema_compat_v1.UNSUPPORTED``.
"""
from __future__ import annotations

import hmac
import json
import os
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable, Protocol, TypeVar

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from . import pg_cinema_compat_v1 as compat
from . import pg_cinema_compat_view_v1 as view

GATE_ENV = "JW_PG_CINEMA_LEGACY_API_V1"
GATE_VALUE = "ISOLATED_DEV_LEGACY_CONTRACT_ONLY"
ORGS_ENV = "JW_PG_CINEMA_LEGACY_ORGS"
WRITER_ROLE = "jw_cinema_writer"
SESSION_COOKIE = "__Host-jw_session"
NATIVE_PREFIX = "/api/pg-stage/cinema-legacy"
KST = timezone(timedelta(hours=9))
_ORG_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
T = TypeVar("T")
_INVALID_BODY = ("invalid-json",)   # not a dict: compat._body() refuses it with 422 bad_body

# Korean text for the refusals a user can actually hit from the legacy screens.
KO = {
    "pg_store_disabled_for_org": "이 회사는 PostgreSQL 거래 저장소가 꺼져 있습니다.",
    "legacy_store_record": "이 문서는 기존 저장소에 있습니다. 기존 화면에서 처리해 주세요.",
    "bad_id": "문서 번호 형식이 올바르지 않습니다.",
    "quote_second_person_required": "견적은 제출한 사람과 다른 관리자가 승인해야 합니다.",
    "quote_approval_identity_unknown": "승인자와 제출자를 확인할 수 없어 승인할 수 없습니다.",
    "due_date_not_stored_in_pg": "납기일 저장 기능이 PostgreSQL에 아직 적용되지 않아 요청을 거부했습니다.",
    "note_not_stored_in_pg": "입금 메모 저장 기능이 PostgreSQL에 아직 적용되지 않아 요청을 거부했습니다.",
    "csrf_failed": "보안 토큰이 없거나 잘못되었습니다",
    "session_required": "로그인이 필요합니다",
}


# --------------------------------------------------------------------------- configuration
def legacy_api_gate_on(env: dict | None = None) -> bool:
    env = os.environ if env is None else env
    return env.get(GATE_ENV) == GATE_VALUE


def enabled_orgs(env: dict | None = None) -> frozenset[str]:
    """The per-company allow-list. Malformed configuration enables NOBODY (fail closed)."""
    env = os.environ if env is None else env
    raw = env.get(ORGS_ENV, "")
    names = [x.strip() for x in raw.split(",") if x.strip()]
    if not names or any(not _ORG_RE.fullmatch(n) for n in names) or len(names) > 1000:
        return frozenset()
    return frozenset(names)


# --------------------------------------------------------------------------- transaction seam
class TxGateway(Protocol):
    def run(self, session_hash: str, work: Callable[[Any], T]) -> T: ...


class WriterTx:
    """One transaction: SET LOCAL ROLE jw_cinema_writer, transaction-local session hash, then ``work``.

    ``connect`` must return a psycopg connection. Production wiring (``register_legacy_api_v1``) uses the
    V9.0 validated cursor instead (``ValidatedLegacyTx``); this class is the same writer-role path for a
    disposable PostgreSQL in CI."""

    def __init__(self, connect: Callable[[], Any]):
        self._connect = connect

    def run(self, session_hash: str, work: Callable[[Any], T]) -> T:
        with self._connect() as conn:
            with conn.transaction():
                with conn.cursor() as cur:
                    cur.execute(f"SET LOCAL ROLE {WRITER_ROLE}")
                    cur.execute("SELECT set_config('jw.session_hash', %s, true)", (session_hash,))
                    return work(cur)


class ValidatedLegacyTx:
    """Production path: the reviewed V9.0 validated cursor (unsafe-login detection, PG session lookup),
    owner-separation and S4 single-ledger checks of ``pg_cinema_register_v1``, then the writer role."""

    def run(self, session_hash: str, work: Callable[[Any], T]) -> T:
        from . import pg_cinema_register_v1 as reg
        with reg._v90._pg_validated_cursor(session_hash) as (cur, identity):
            cur.execute("SELECT pg_catalog.pg_has_role(session_user, %s, 'MEMBER')", (reg.OWNER_ROLE,))
            if cur.fetchone() != (False,):
                raise HTTPException(503, "Trade login role is not separated from the owner role")
            org = identity[2]
            cur.execute(reg.S4_LEGACY_COLLISION_SQL, (org, org, org, org))
            if cur.fetchone() != (False,):
                raise HTTPException(409, "Existing legacy trades require verified reconciliation")
            cur.execute(f"SET LOCAL ROLE {WRITER_ROLE}")
            return work(cur)


# --------------------------------------------------------------------------- small helpers
def _refuse(code: str, status: int = 409, detail: str | None = None) -> HTTPException:
    return HTTPException(status, {"code": code, "detail": detail or KO.get(code, code)})


def _session_hash(request: Request) -> str:
    import hashlib
    token = request.cookies.get(SESSION_COOKIE, "")
    if not 30 <= len(token) <= 512:
        raise _refuse("session_required", 401)
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _rows(cur, sql: str, params: tuple = ()) -> list[dict]:
    cur.execute(sql, params)
    cols = [c.name for c in cur.description] if cur.description else []
    return [dict(zip(cols, r, strict=True)) for r in cur.fetchall()] if cols else []


def _one(cur, sql: str, params: tuple = ()) -> dict | None:
    rows = _rows(cur, sql, params)
    return rows[0] if rows else None


def _ts(col: str) -> str:
    """timestamptz -> ISO text with offset, which ``view.kst`` parses."""
    return f"to_json({col})#>>'{{}}' AS {col.split('.')[-1]}"


def _pg_id(value: str, kind: str = "document") -> str:
    """Raw engine id for a ``pg_`` id; legacy ids and malformed ids are refused before any query."""
    try:
        store, raw = view.parse_public_id(value)
    except view.ViewError:
        raise _refuse("bad_id", 422) from None
    if store != "pg":
        raise _refuse("legacy_store_record", 409)
    return raw


def _fn_exists(cur, signature: str) -> bool:
    cur.execute("SELECT to_regprocedure(%s) IS NOT NULL", (signature,))
    return bool(cur.fetchone()[0])


def _jsonb(value):
    from psycopg.types.json import Jsonb
    return Jsonb(value)


def _call(cur, fn: str, *args) -> dict:
    placeholders = ",".join(["%s"] * len(args))
    cur.execute(f"SELECT jw_dev.{fn}({placeholders})", args)
    result = cur.fetchone()[0]
    return result if isinstance(result, dict) else json.loads(result)


def _entity_id(result: dict) -> str:
    entity = result.get("entity") or {}
    if not isinstance(entity.get("id"), str):
        raise HTTPException(502, {"code": "pg_engine_error", "detail": "the database returned no id"})
    return entity["id"]


def _today() -> date:
    return datetime.now(KST).date()


def _legacy_date(value, code: str) -> str | None:
    """'' / None -> None; else a real YYYY-MM-DD calendar date (no coercion)."""
    if value in (None, ""):
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value, re.ASCII):
        raise _refuse(code, 422, "date must be YYYY-MM-DD")
    try:
        date.fromisoformat(value)
    except ValueError:
        raise _refuse(code, 422, "not a real calendar date") from None
    return value


# --------------------------------------------------------------------------- read models
def _partners(cur, raw_id: str | None = None) -> list[dict]:
    sql = ("SELECT id, org_id, name, business_number, contact_name, email, phone, version, "
           + _ts("created_at") + " FROM jw_dev.cinema_pg_partners")
    if raw_id is not None:
        return _rows(cur, sql + " WHERE id=%s", (raw_id,))
    return _rows(cur, sql + " ORDER BY created_at DESC, id")


def _items(cur, table: str, parent_col: str, parent_ids: list[str], extra: str = "") -> dict[str, list]:
    if not parent_ids:
        return {}
    rows = _rows(cur, f"SELECT id, {parent_col}, position, name, quantity, unit_price{extra} "
                      f"FROM jw_dev.{table} WHERE {parent_col} = ANY(%s) ORDER BY position", (parent_ids,))
    out: dict[str, list] = {}
    for r in rows:
        out.setdefault(r[parent_col], []).append(r)
    return out


def _quotes(cur, raw_id: str | None = None) -> list[dict]:
    sql = ("SELECT q.id, q.org_id, q.trade_no, q.partner_id, q.title, q.status, q.vat_mode, q.version, "
           "q.submitted_by, p.name AS partner_name, " + _ts("q.created_at") + ", " + _ts("q.updated_at") +
           " FROM jw_dev.cinema_pg_quotes q JOIN jw_dev.cinema_pg_partners p "
           "ON p.org_id=q.org_id AND p.id=q.partner_id")
    rows = _rows(cur, sql + (" WHERE q.id=%s" if raw_id else " ORDER BY q.created_at DESC, q.id"),
                 (raw_id,) if raw_id else ())
    items = _items(cur, "cinema_pg_quote_items", "quote_id", [r["id"] for r in rows])
    for r in rows:
        r["items"] = items.get(r["id"], [])
    return rows


def _quote_out(row: dict) -> dict:
    return view.quote_view(row, partner_name=row["partner_name"])


def _orders(cur, raw_id: str | None = None, with_terms: bool = False) -> list[dict]:
    terms = (", (SELECT t.due_date::text FROM jw_dev.cinema_pg_order_terms t "
             "WHERE t.org_id=o.org_id AND t.order_id=o.id) AS due_date") if with_terms else ", NULL::text AS due_date"
    sql = ("SELECT o.id, o.org_id, o.trade_no, o.quote_id, o.partner_id, o.vat_mode, o.status, "
           "q.title, p.name AS partner_name, " + _ts("o.created_at") + ", " + _ts("o.updated_at") +
           ", EXISTS(SELECT 1 FROM jw_dev.cinema_pg_deliveries d WHERE d.org_id=o.org_id AND d.order_id=o.id "
           "AND d.status='confirmed') AS any_confirmed" + terms +
           " FROM jw_dev.cinema_pg_orders o JOIN jw_dev.cinema_pg_quotes q ON q.org_id=o.org_id AND q.id=o.quote_id"
           " JOIN jw_dev.cinema_pg_partners p ON p.org_id=o.org_id AND p.id=o.partner_id")
    rows = _rows(cur, sql + (" WHERE o.id=%s" if raw_id else " ORDER BY o.created_at DESC, o.id"),
                 (raw_id,) if raw_id else ())
    items = _items(cur, "cinema_pg_order_items", "order_id", [r["id"] for r in rows], ", source_quote_item_id")
    for r in rows:
        r["items"] = items.get(r["id"], [])
    return rows


def _order_out(row: dict) -> dict:
    return view.order_view(row, partner_name=row["partner_name"], title=row["title"],
                           due_date=row["due_date"], any_confirmed_delivery=bool(row["any_confirmed"]))


INVOICE_STATUS_TO_LEGACY = {"confirmed": "issued", "voided": "cancelled", "draft": "draft", "reviewed": "draft"}


def _invoices(cur, raw_id: str | None = None, with_terms: bool = False, with_notes: bool = False) -> list[dict]:
    terms = (", (SELECT t.pay_by::text FROM jw_dev.cinema_pg_invoice_terms t "
             "WHERE t.org_id=i.org_id AND t.invoice_id=i.id) AS pay_by") if with_terms else ", NULL::text AS pay_by"
    sql = ("SELECT i.id, i.org_id, i.trade_no, i.order_id, i.invoice_no, i.subtotal_krw, i.vat_krw, i.total_krw, "
           "i.status, o.partner_id, o.vat_mode, p.name AS partner_name, " + _ts("i.created_at") + terms +
           " FROM jw_dev.cinema_pg_invoices i JOIN jw_dev.cinema_pg_orders o ON o.org_id=i.org_id AND o.id=i.order_id"
           " JOIN jw_dev.cinema_pg_partners p ON p.org_id=o.org_id AND p.id=o.partner_id")
    rows = _rows(cur, sql + (" WHERE i.id=%s" if raw_id else " ORDER BY i.created_at DESC, i.id"),
                 (raw_id,) if raw_id else ())
    ids = [r["id"] for r in rows]
    pays = _payments(cur, ids, with_notes) if ids else {}
    for r in rows:
        r["payments"] = pays.get(r["id"], [])
    return rows


def _payments(cur, invoice_ids: list[str], with_notes: bool) -> dict[str, list]:
    note = (", (SELECT n.note FROM jw_dev.cinema_pg_payment_notes n WHERE n.org_id=pm.org_id "
            "AND n.payment_id=pm.id) AS note") if with_notes else ", NULL::text AS note"
    rows = _rows(cur, "SELECT pm.id, pm.org_id, pm.invoice_id, pm.amount_krw, pm.paid_on::text AS paid_on, "
                      "pm.reference, " + _ts("pm.recorded_at") + ", (SELECT to_json(r.reversed_at)#>>'{}' FROM "
                      "jw_dev.cinema_pg_payment_reversals r WHERE r.payment_id=pm.id) AS reversed_at" + note +
                      " FROM jw_dev.cinema_pg_payments pm WHERE pm.invoice_id = ANY(%s) "
                      "ORDER BY pm.paid_on DESC, pm.recorded_at DESC, pm.id DESC", (invoice_ids,))
    out: dict[str, list] = {}
    for r in rows:
        out.setdefault(r["invoice_id"], []).append(r)
    return out


def _invoice_out(row: dict, today: date | None = None) -> dict:
    """Legacy invoice shape the V22.2 invoice screen reads (doc_no, money, paid, balance, payment_status...).
    Money is the ENGINE's stored subtotal/VAT/total (never recomputed into a different number)."""
    if row["status"] not in INVOICE_STATUS_TO_LEGACY:
        raise view.ViewError(f"unknown invoice status {row['status']!r}")
    payments = [view.payment_view(p, note=p.get("note"), reversed_at=p.get("reversed_at")) for p in row["payments"]]
    paid = sum(p["amount"] for p in payments if p["reversed_at"] is None)
    total = int(row["total_krw"])
    balance = total - paid
    pay_by = row.get("pay_by") or ""
    if balance <= 0:
        status = "paid"
    elif pay_by and pay_by < (today or _today()).isoformat():
        status = "overdue"
    else:
        status = "unpaid"    # without a recorded pay-by date it can never be called overdue
    pub = view.public_id(row["id"])
    return {"id": pub, "org_id": row["org_id"], "order_id": view.public_id(row["order_id"]),
            "customer_id": view.public_id(row["partner_id"]), "customer_name_snapshot": row["partner_name"],
            "customer_name": row["partner_name"], "doc_no": row["invoice_no"], "trade_no": row["trade_no"],
            "status": INVOICE_STATUS_TO_LEGACY[row["status"]], "pg_status": row["status"],
            "vat_mode": row["vat_mode"], "due_date": pay_by, "created_at": view.kst(row["created_at"]),
            "money": {"subtotal": int(row["subtotal_krw"]), "vat": int(row["vat_krw"]), "total": total},
            "paid": paid, "balance": balance,
            "settlement": {"adjusted_total": total, "balance": balance, "adjustments": []},
            "payment_status": status, "payments": payments, "source": "pg"}


# --------------------------------------------------------------------------- router
def create_legacy_router(tx: TxGateway, session_hash: Callable[[Request], str] = _session_hash,
                         org_enabled: Callable[[str], bool] | None = None,
                         today: Callable[[], date] = _today) -> APIRouter:
    org_ok = org_enabled or (lambda org: org in enabled_orgs())
    router = APIRouter()

    def _psycopg_errors():
        try:
            import psycopg
            return (psycopg.Error,)
        except ImportError:   # pragma: no cover - psycopg is a stage dependency
            return ()

    pg_errors = _psycopg_errors()

    async def handle(request: Request, write: bool, work: Callable[[Any, dict], Any], status: int = 200,
                     body: Any = None):
        hashed = session_hash(request)
        csrf = request.headers.get("X-CSRF-Token", "")
        idem = request.headers.get("Idempotency-Key") or request.headers.get("X-Idempotency-Key") or ""

        def in_tx(cur):
            row = _one(cur, "SELECT actor_id, org_id, actor_role, csrf_token FROM jw_dev.stage_identity_v84()")
            if not row or not row["actor_id"] or not row["org_id"]:
                raise _refuse("session_required", 401)
            if write and (not row["csrf_token"] or not hmac.compare_digest(str(row["csrf_token"]), csrf)):
                raise _refuse("csrf_failed", 403)
            if not org_ok(row["org_id"]):
                raise _refuse("pg_store_disabled_for_org", 409)
            ident = {"actor": row["actor_id"], "org": row["org_id"], "role": row["actor_role"]}

            def rid(route: str) -> str:
                # A client key makes a retry idempotent; without one each call is a fresh request (honest).
                key = idem or secrets.token_urlsafe(24)
                return compat.derive_request_id(ident["org"], ident["actor"], route, key)
            ident["rid"] = rid
            return work(cur, ident)

        try:
            result = await run_in_threadpool(tx.run, hashed, in_tx)
        except compat.CompatRefusal as exc:
            return JSONResponse({"code": exc.code, "detail": KO.get(exc.code, exc.detail)}, exc.http_status)
        except HTTPException as exc:
            if isinstance(exc.detail, dict):
                return JSONResponse(exc.detail, exc.status_code)
            raise
        except view.ViewError:
            return JSONResponse({"code": "pg_view_inconsistent", "detail": "the database returned an unexpected shape"}, 502)
        except pg_errors as exc:  # type: ignore[misc]
            mapped = compat.map_pg_error(getattr(exc, "sqlstate", "") or "", str(exc))
            return JSONResponse({"code": mapped.code, "detail": mapped.detail}, mapped.http_status)
        return JSONResponse(result, status)

    async def read_json(request: Request) -> Any:
        """Unparseable JSON becomes a non-object sentinel: every translator refuses it with 422 bad_body,
        AFTER authentication (an anonymous caller learns nothing from the body check)."""
        try:
            return await request.json()
        except (ValueError, UnicodeDecodeError):
            return _INVALID_BODY

    def found(rows: list[dict]) -> dict:
        if not rows:
            raise _refuse("not_found", 404, "대상을 찾을 수 없습니다.")
        return rows[0]

    # ------------------------------------------------------------------ customers (partners)
    @router.get("/api/customers")
    async def customers(request: Request):
        return await handle(request, False, lambda cur, i: [view.customer_view(p) for p in _partners(cur)])

    @router.post("/api/customers")
    async def customer_create(request: Request):
        body = await read_json(request)
        def work(cur, i):
            args = compat.partner_from_customer(body, i["rid"]("POST /api/customers"))
            res = _call(cur, "cinema_pg_partner_upsert", args["request_id"], None, args["name"],
                        args["business_number"], args["contact_name"], args["email"], args["phone"], None)
            return view.customer_view(found(_partners(cur, _entity_id(res))))
        return await handle(request, True, work, 201)

    @router.put("/api/customers/{customer_id}")
    async def customer_update(customer_id: str, request: Request):
        body = await read_json(request)
        def work(cur, i):
            raw = _pg_id(customer_id)
            current = found(_partners(cur, raw))
            version = body.get("version", current["version"]) if isinstance(body, dict) else current["version"]
            args = compat.partner_from_customer(body, i["rid"](f"PUT /api/customers/{raw}"),
                                                partner_id=raw, expected_version=version)
            _call(cur, "cinema_pg_partner_upsert", args["request_id"], raw, args["name"], args["business_number"],
                  args["contact_name"], args["email"], args["phone"], args["expected_version"])
            return view.customer_view(found(_partners(cur, raw)))
        return await handle(request, True, work)

    # ------------------------------------------------------------------ quotes
    @router.get("/api/quotes")
    async def quotes(request: Request):
        return await handle(request, False, lambda cur, i: [_quote_out(q) for q in _quotes(cur)])

    @router.get("/api/quotes/{quote_id}")
    async def quote_get(quote_id: str, request: Request):
        return await handle(request, False, lambda cur, i: _quote_out(found(_quotes(cur, _pg_id(quote_id)))))

    @router.post("/api/quotes")
    async def quote_create(request: Request):
        body = await read_json(request)
        def work(cur, i):
            b = dict(body) if isinstance(body, dict) else body
            if isinstance(b, dict) and isinstance(b.get("customer_id"), str):
                b["customer_id"] = _pg_id(b["customer_id"])
            args = compat.quote_create(b, i["rid"]("POST /api/quotes"))
            res = _call(cur, "cinema_pg_quote_create", args["request_id"], args["partner_id"], args["title"],
                        args["vat_mode"], _jsonb(args["items"]))
            return _quote_out(found(_quotes(cur, _entity_id(res))))
        return await handle(request, True, work, 201)

    @router.put("/api/quotes/{quote_id}")
    async def quote_update(quote_id: str, request: Request):
        body = await read_json(request)
        def work(cur, i):
            raw = _pg_id(quote_id)
            q = found(_quotes(cur, raw))
            b = dict(body) if isinstance(body, dict) else body
            if isinstance(b, dict) and isinstance(b.get("customer_id"), str):
                b["customer_id"] = _pg_id(b["customer_id"])
            version = b.get("version", q["version"]) if isinstance(b, dict) else q["version"]
            if isinstance(b, dict):
                b.pop("version", None)
            args = compat.quote_update(b, i["rid"](f"PUT /api/quotes/{raw}"), expected_version=version,
                                       current_partner_id=q["partner_id"], current_vat_mode=q["vat_mode"])
            _call(cur, "cinema_pg_quote_update", args["request_id"], raw, args["expected_version"], args["title"],
                  _jsonb(args["items"]))
            return _quote_out(found(_quotes(cur, raw)))
        return await handle(request, True, work)

    @router.post("/api/quotes/{quote_id}/status")
    async def quote_status(quote_id: str, request: Request):
        body = await read_json(request)
        def work(cur, i):
            raw = _pg_id(quote_id)
            # No FOR UPDATE: the writer role has SELECT only (by design). The version read here is passed
            # as expected_version, so a concurrent (re)submission makes the engine refuse with 40001, and the
            # database two-person CHECK (when migrated) refuses a same-person approval regardless.
            locked = _one(cur, "SELECT version, submitted_by FROM jw_dev.cinema_pg_quotes WHERE id=%s", (raw,))
            if not locked:
                raise _refuse("not_found", 404, "대상을 찾을 수 없습니다.")
            version = body.get("version", locked["version"]) if isinstance(body, dict) else locked["version"]
            args = compat.quote_transition(body, i["rid"](f"POST /api/quotes/{raw}/status"),
                                           expected_version=version, actor_id=i["actor"],
                                           submitted_by=locked["submitted_by"])
            _call(cur, "cinema_pg_quote_transition", args["request_id"], raw, args["expected_version"], args["to"])
            return _quote_out(found(_quotes(cur, raw)))
        return await handle(request, True, work)

    # ------------------------------------------------------------------ orders
    @router.get("/api/orders")
    async def orders(request: Request):
        def work(cur, i):
            terms = _fn_exists(cur, "jw_dev.cinema_pg_order_terms_set(text,text,date)")
            return [_order_out(o) for o in _orders(cur, with_terms=terms)]
        return await handle(request, False, work)

    @router.get("/api/orders/{order_id}")
    async def order_get(order_id: str, request: Request):
        def work(cur, i):
            raw = _pg_id(order_id)
            terms = _fn_exists(cur, "jw_dev.cinema_pg_order_terms_set(text,text,date)")
            return _order_out(found(_orders(cur, raw, with_terms=terms)))
        return await handle(request, False, work)

    @router.post("/api/orders/from-quote")
    async def order_from_quote(request: Request):
        body = await read_json(request)
        def work(cur, i):
            b = dict(compat._body(body))
            due = _legacy_date(b.pop("due_date", None), "bad_due_date")
            terms = _fn_exists(cur, "jw_dev.cinema_pg_order_terms_set(text,text,date)")
            if due and not terms:
                raise compat.CompatRefusal("due_date_not_stored_in_pg", "order terms migration not applied")
            if isinstance(b.get("quote_id"), str):
                b["quote_id"] = _pg_id(b["quote_id"])
            route = "POST /api/orders/from-quote"
            args = compat.order_from_quote(b, i["rid"](route))
            order_raw = _entity_id(_call(cur, "cinema_pg_order_create", args["request_id"], args["quote_id"]))
            if due:   # same transaction: the order and its due date commit together or not at all
                _call(cur, "cinema_pg_order_terms_set", compat.derive_request_id(
                    i["org"], i["actor"], route + ":due_date", args["request_id"]), order_raw, due)
            return _order_out(found(_orders(cur, order_raw, with_terms=terms)))
        return await handle(request, True, work, 201)

    # ------------------------------------------------------------------ invoices / payments
    def _inv_flags(cur) -> tuple[bool, bool]:
        return (_fn_exists(cur, "jw_dev.cinema_pg_invoice_terms_set(text,text,date)"),
                _fn_exists(cur, "jw_dev.cinema_pg_payment_note_set(text,text,text)"))

    @router.get("/api/invoices")
    async def invoices(request: Request):
        def work(cur, i):
            terms, notes = _inv_flags(cur)
            return [_invoice_out(r, today()) for r in _invoices(cur, with_terms=terms, with_notes=notes)]
        return await handle(request, False, work)

    @router.get("/api/invoices/{invoice_id}")
    async def invoice_get(invoice_id: str, request: Request):
        def work(cur, i):
            raw = _pg_id(invoice_id)
            terms, notes = _inv_flags(cur)
            return _invoice_out(found(_invoices(cur, raw, with_terms=terms, with_notes=notes)), today())
        return await handle(request, False, work)

    @router.get("/api/invoices/{invoice_id}/payments")
    async def invoice_payments(invoice_id: str, request: Request):
        def work(cur, i):
            raw = _pg_id(invoice_id)
            terms, notes = _inv_flags(cur)
            inv = _invoice_out(found(_invoices(cur, raw, with_terms=terms, with_notes=notes)), today())
            return [{k: p[k] for k in ("id", "amount", "paid_at", "note", "created_at", "reversed_at")}
                    for p in inv["payments"]]
        return await handle(request, False, work)

    @router.post("/api/invoices/{invoice_id}/payments")
    async def payment_record(invoice_id: str, request: Request):
        body = await read_json(request)
        def work(cur, i):
            raw = _pg_id(invoice_id)
            b = dict(compat._body(body))
            note = b.pop("note", None)
            terms, notes = _inv_flags(cur)
            if note not in (None, ""):
                if not notes:
                    raise compat.CompatRefusal("note_not_stored_in_pg", "payment note migration not applied")
                if not isinstance(note, str) or not compat._storable(note) or not 1 <= len(note.strip(" ")) <= 500:
                    raise compat.CompatRefusal("bad_note", "note must be 1..500 characters of text", 422)
            route = f"POST /api/invoices/{raw}/payments"
            args = compat.payment_for_invoice(b, i["rid"](route), today=today())
            pay_raw = _entity_id(_call(cur, "cinema_pg_payment_record", args["request_id"], raw,
                                       args["amount_krw"], args["paid_on"], args["reference"]))
            if note not in (None, ""):   # the payment and its note commit together
                _call(cur, "cinema_pg_payment_note_set", compat.derive_request_id(
                    i["org"], i["actor"], route + ":note", args["request_id"]), pay_raw, note)
            return _invoice_out(found(_invoices(cur, raw, with_terms=terms, with_notes=notes)), today())
        return await handle(request, True, work, 201)

    # PG-native, not a legacy route: the invoice pay-by date that makes "overdue" computable.
    @router.post(NATIVE_PREFIX + "/invoices/{invoice_id}/pay-by")
    async def invoice_pay_by(invoice_id: str, request: Request):
        body = await read_json(request)
        def work(cur, i):
            raw = _pg_id(invoice_id)
            pay_by = _legacy_date(compat._body(body).get("due_date"), "bad_due_date")
            if not pay_by:
                raise compat.CompatRefusal("bad_due_date", "due_date is required", 422)
            terms, notes = _inv_flags(cur)
            if not terms:
                raise compat.CompatRefusal("due_date_not_stored_in_pg", "invoice terms migration not applied")
            _call(cur, "cinema_pg_invoice_terms_set", i["rid"](f"POST pay-by {raw}"), raw, pay_by)
            return _invoice_out(found(_invoices(cur, raw, with_terms=terms, with_notes=notes)), today())
        return await handle(request, True, work)

    # ------------------------------------------------------------------ explicit refusals (no PG equivalent)
    async def refuse(request: Request, step: str, doc_id: str | None):
        def work(cur, i):
            if doc_id is not None:
                _pg_id(doc_id)          # a legacy id is routed to the legacy store first
            raise compat.unsupported(step)
        return await handle(request, True, work)

    @router.post("/api/invoices/from-order")
    async def invoice_from_order(request: Request):
        body = await read_json(request)
        order = body.get("order_id") if isinstance(body, dict) else None
        return await refuse(request, "invoice_from_order", order if isinstance(order, str) else None)

    @router.post("/api/orders/{order_id}/status")
    async def order_status(order_id: str, request: Request):
        return await refuse(request, "order_status_set", order_id)

    @router.post("/api/orders/{order_id}/acknowledge")
    async def order_acknowledge(order_id: str, request: Request):
        return await refuse(request, "order_acknowledge", order_id)

    @router.put("/api/orders/{order_id}")
    async def order_change(order_id: str, request: Request):
        return await refuse(request, "order_change", order_id)
    return router


# --------------------------------------------------------------------------- registration
def register_legacy_api_v1(app) -> bool:
    """Mount only after the separate opt-in AND the CINEMA trade gate. Returns whether it was mounted."""
    from . import pg_cinema_register_v1 as reg
    if not (legacy_api_gate_on() and reg.cinema_trade_enabled()):
        return False
    raw = os.environ.get(ORGS_ENV, "")
    if raw.strip() and not enabled_orgs():
        raise RuntimeError("BLOCKED: malformed JW_PG_CINEMA_LEGACY_ORGS")
    app.include_router(create_legacy_router(ValidatedLegacyTx()))
    return True
