#!/usr/bin/env python3
"""V22.3 HTTP E2E: the legacy UI API contract served by the CINEMA PostgreSQL engine. DISPOSABLE PG ONLY.

  JW_CINEMA_PG_DISPOSABLE=1 PGHOST=127.0.0.1 ... python3 -m scripts.ci_cinema_pg_legacy_api_e2e_v223

What runs for real: a FastAPI app with ``app.pg_cinema_legacy_api_v1`` (legacy paths) and the existing
``app.pg_cinema_trade_v1`` router (delivery/statement/invoice steps that have no legacy route), over HTTP
(Starlette TestClient), against a throw-away PostgreSQL database holding the unchanged engine, its fixture
tenants A/B/C, and the two V22.3 migration CANDIDATES (two-person quote CHECK, order/invoice/payment terms).
Each request runs as ``jw_cinema_writer`` with the session hash of a real hashed cookie.

What does NOT run here (stated, not implied): the production connection path (``ValidatedLegacyTx`` over the
V9.0 TLS ``verify-full`` cursor with a dedicated login role), the legacy SQLite app, a browser, HTTPS, MFA
login. Synthetic data only; nothing is applied to Supabase.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import threading
from datetime import date, timedelta
from pathlib import Path

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app import pg_cinema_legacy_api_v1 as legacy  # noqa: E402
from app.pg_cinema_trade_v1 import PsycopgWriterGateway, VerifiedSession, create_router  # noqa: E402
from scripts import ci_cinema_pg_sql_gate as gate  # noqa: E402

TWO_PERSON = ROOT / "scripts/review/cinema_pg_v223_quote_two_person_proposal.sql"
TERMS = ROOT / "scripts/review/cinema_pg_v223_terms_proposal.sql"
EXPECTED_CHECKS = 74
results: list[tuple[str, bool, str]] = []
DB = ""
ORGS = {"value": "ci-a,ci-b"}       # C is never enabled; A is toggled for the rollback test


def rec(name: str, ok: bool, detail: str = "") -> bool:
    results.append((name, bool(ok), detail))
    print(("PASS" if ok else "FAIL"), name, detail[:300] if not ok else "")
    return bool(ok)


def connect():
    return psycopg.connect(dbname=DB, autocommit=False)


def sql(statement: str, params: tuple = ()):
    with psycopg.connect(dbname=DB, autocommit=True) as c:
        cur = c.execute(statement, params)
        return cur.fetchall() if cur.description else None


def scalar(statement: str, params: tuple = ()):
    rows = sql(statement, params)
    return rows[0][0] if rows else None


# ------------------------------------------------------------------ app under test
def trade_authorize(request: Request) -> VerifiedSession:
    """Native router auth for the E2E: real hashed cookie -> PG session + CSRF check in PG."""
    hashed = legacy._session_hash(request)
    with connect() as c, c.transaction(), c.cursor() as cur:
        cur.execute("SET LOCAL ROLE jw_cinema_writer")
        cur.execute("SELECT set_config('jw.session_hash', %s, true)", (hashed,))
        cur.execute("SELECT csrf_token FROM jw_dev.stage_identity_v84()")
        row = cur.fetchone()
    if not row:
        raise HTTPException(401, "session required")
    ok = request.method in ("GET", "HEAD") or secrets.compare_digest(row[0] or "", request.headers.get("X-CSRF-Token", ""))
    return VerifiedSession(session_hash=hashed, csrf_verified=ok)


class Clock:
    today = date.today()


def build_app() -> FastAPI:
    app = FastAPI()
    app.include_router(legacy.create_legacy_router(
        legacy.WriterTx(connect),
        org_enabled=lambda org: org in legacy.enabled_orgs({legacy.ORGS_ENV: ORGS["value"]}),
        today=lambda: Clock.today))
    app.include_router(create_router(PsycopgWriterGateway(connect), trade_authorize))
    return app


class User:
    def __init__(self, client: TestClient, uid: str):
        self.token = secrets.token_urlsafe(32)
        self.csrf = secrets.token_urlsafe(24)
        self.uid = uid
        self.c = client
        sql("INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at) "
            "VALUES (%s,%s,%s,(now()+interval '2 hours')::text,%s,now()::text)",
            ("e2e-" + secrets.token_hex(6), hashlib.sha256(self.token.encode()).hexdigest(), uid, self.csrf))

    def req(self, method: str, path: str, body=None, csrf: bool = True, key: str | None = None,
            raw: bytes | None = None, ctype: str | None = None):
        headers = {"Cookie": f"{legacy.SESSION_COOKIE}={self.token}"}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        if key:
            headers["Idempotency-Key"] = key
        if raw is not None:
            headers["Content-Type"] = ctype or "application/octet-stream"
            return self.c.request(method, path, content=raw, headers=headers)
        return self.c.request(method, path, json=body, headers=headers)


def code(resp) -> str:
    try:
        return resp.json().get("code", "")
    except (ValueError, AttributeError):
        return ""


def rid() -> str:
    return "e2e-" + secrets.token_hex(8)


def raw_of(pub: str) -> str:
    assert pub.startswith("pg_"), pub
    return pub[3:]


# ------------------------------------------------------------------ the scenario
def run() -> None:
    client = TestClient(build_app(), base_url="https://testserver")
    a1, a2, am = User(client, "ci-ua"), User(client, "ci-ua2"), User(client, "ci-ua3")
    b1, c1 = User(client, "ci-ub"), User(client, "ci-uc")
    expired = User(client, "ci-ua")
    sql("UPDATE jw_dev.sessions SET expires_at=(now()-interval '1 minute')::text WHERE token_hash=%s",
        (hashlib.sha256(expired.token.encode()).hexdigest(),))

    # ---- authentication, CSRF, per-company switch
    anon = client.get("/api/quotes")
    rec("E2E.A01_no_cookie_is_401", anon.status_code == 401, anon.text)
    r = expired.req("GET", "/api/quotes")
    rec("E2E.A02_expired_session_is_401", r.status_code == 401, r.text)
    r = c1.req("GET", "/api/quotes")
    rec("E2E.A03_company_not_on_allowlist_is_refused", r.status_code == 409 and code(r) == "pg_store_disabled_for_org", r.text)
    bn = "".join(secrets.choice("0123456789") for _ in range(10))
    body = {"name": "E2E 거래처", "business_number": f"{bn[:3]}-{bn[3:5]}-{bn[5:]}", "email": "p@invalid.test"}
    r = a1.req("POST", "/api/customers", body, csrf=False)
    rec("E2E.A04_write_without_csrf_is_403", r.status_code == 403, r.text)
    bad = User.__new__(User); bad.__dict__.update(a1.__dict__); bad.csrf = "x" * 32
    r = bad.req("POST", "/api/customers", body)
    rec("E2E.A05_write_with_wrong_csrf_is_403", r.status_code == 403, r.text)
    before = scalar("SELECT count(*) FROM jw_dev.cinema_pg_partners")
    rec("E2E.A06_refused_writes_left_no_rows", scalar("SELECT count(*) FROM jw_dev.cinema_pg_partners") == before)

    # ---- customers: create, legacy shape, tenant isolation
    r = a1.req("POST", "/api/customers", body)
    cust = r.json() if r.status_code == 201 else {}
    rec("E2E.C01_customer_created_201_pg_id", r.status_code == 201 and str(cust.get("id", "")).startswith("pg_"), r.text)
    legacy_customer_keys = {"id", "org_id", "name", "business_number", "contact_name", "email", "phone", "created_at"}
    rec("E2E.C02_customer_has_legacy_keys_and_normalized_number",
        legacy_customer_keys <= set(cust) and cust.get("business_number") == bn and cust.get("org_id") == "ci-a", str(cust))
    r = a1.req("POST", "/api/customers", {"name": "중복 사업자", "business_number": bn})
    rec("E2E.C02b_duplicate_business_number_is_409_not_502", r.status_code == 409 and code(r) == "duplicate_business_number", r.text)
    r = b1.req("POST", "/api/customers", {"name": "B사 같은 번호", "business_number": bn})
    rec("E2E.C02c_same_number_in_another_company_is_allowed", r.status_code == 201, r.text)
    r = b1.req("GET", "/api/customers")
    rec("E2E.C03_other_company_does_not_see_it", r.status_code == 200 and all(x["id"] != cust.get("id") for x in r.json()), r.text[:200])
    r = b1.req("PUT", f"/api/customers/{cust.get('id')}", {"name": "탈취"})
    rec("E2E.C04_other_company_cannot_update_it", r.status_code == 404 and
        scalar("SELECT name FROM jw_dev.cinema_pg_partners WHERE id=%s", (raw_of(cust["id"]),)) == "E2E 거래처", r.text)
    r = a1.req("PUT", f"/api/customers/{cust.get('id')}", {"name": "E2E 거래처 수정", "phone": "02-000-0000"})
    rec("E2E.C05_owner_company_updates_with_version", r.status_code == 200 and r.json().get("name") == "E2E 거래처 수정"
        and r.json().get("version") == 2, r.text)
    r = a1.req("GET", "/api/quotes/0123456789abcdef0123456789abcdef")
    rec("E2E.C06_legacy_store_id_routed_away_not_404", r.status_code == 409 and code(r) == "legacy_store_record", r.text)
    r = a1.req("GET", "/api/quotes/pg_XYZ")
    rec("E2E.C07_malformed_pg_id_is_422", r.status_code == 422 and code(r) == "bad_id", r.text)
    r = a1.req("POST", "/api/quotes", {"customer_id": "0123456789abcdef0123456789abcdef", "title": "x",
                                       "items": [{"name": "a", "quantity": 1, "unit_price": 1}]})
    rec("E2E.C08_quote_for_legacy_customer_refused_not_created", r.status_code == 409 and code(r) == "legacy_store_record", r.text)

    # ---- quotes: create, update, send, two-person approval (app + DB level)
    items = [{"name": "필름 스캔", "quantity": 3, "unit_price": 10_000}, {"name": "색보정", "quantity": 1, "unit_price": 5}]
    r = a1.req("POST", "/api/quotes", {"customer_id": cust["id"], "title": "E2E 견적", "vat_mode": "taxable", "items": items})
    q = r.json() if r.status_code == 201 else {}
    rec("E2E.Q01_quote_created_draft_with_legacy_money", r.status_code == 201 and q.get("status") == "draft" and
        q.get("money") == {"subtotal": 30005, "vat": 3001, "total": 33006} and q.get("customer_id") == cust["id"], r.text)
    rec("E2E.Q02_quote_legacy_keys", {"id", "doc_no", "title", "status", "vat_mode", "items", "money", "customer_name",
                                      "customer_id", "created_at", "updated_at"} <= set(q), str(sorted(q)))
    r = a1.req("PUT", f"/api/quotes/{q['id']}", {"title": "E2E 견적 v2", "items": items[:1]})
    rec("E2E.Q03_draft_update", r.status_code == 200 and r.json()["title"] == "E2E 견적 v2" and r.json()["money"]["subtotal"] == 30000, r.text)
    r = a1.req("PUT", f"/api/quotes/{q['id']}", {"title": "t", "vat_mode": "exempt", "items": items[:1]})
    rec("E2E.Q04_immutable_vat_change_refused", r.status_code == 409 and code(r) == "pg_quote_vat_mode_is_immutable", r.text)
    r = a1.req("POST", f"/api/quotes/{q['id']}/status", {"status": "sent"})
    rec("E2E.Q05_sent_maps_to_submitted", r.status_code == 200 and r.json()["status"] == "sent" and
        scalar("SELECT status FROM jw_dev.cinema_pg_quotes WHERE id=%s", (raw_of(q["id"]),)) == "submitted", r.text)
    r = a1.req("POST", f"/api/quotes/{q['id']}/status", {"status": "accepted"})
    rec("E2E.Q06_submitter_cannot_approve_app_level", r.status_code == 409 and code(r) == "quote_second_person_required", r.text)
    r = am.req("POST", f"/api/quotes/{q['id']}/status", {"status": "accepted"})
    rec("E2E.Q07_member_cannot_approve", r.status_code == 403 and code(r) == "admin_required", r.text)
    r = b1.req("POST", f"/api/quotes/{q['id']}/status", {"status": "accepted"})
    rec("E2E.Q08_other_company_cannot_approve", r.status_code == 404, r.text)
    # DB level: bypass the app guard entirely and call the engine as the submitter.
    r2 = a1.req("POST", "/api/quotes", {"customer_id": cust["id"], "title": "DB 2인", "vat_mode": "exempt", "items": items[:1]})
    q2 = r2.json()
    a1.req("POST", f"/api/quotes/{q2['id']}/status", {"status": "sent"})
    with connect() as c, c.transaction(), c.cursor() as cur:
        cur.execute("SET LOCAL ROLE jw_cinema_writer")
        cur.execute("SELECT set_config('jw.session_hash', %s, true)", (hashlib.sha256(a1.token.encode()).hexdigest(),))
        cur.execute("SAVEPOINT s")
        try:
            cur.execute("SELECT jw_dev.cinema_pg_quote_transition(%s,%s,%s,'approved')", (rid(), raw_of(q2["id"]), 2))
            state = "OK"
        except psycopg.Error as exc:
            state = exc.sqlstate or "?"
            cur.execute("ROLLBACK TO SAVEPOINT s")
    rec("E2E.Q09_submitter_self_approval_refused_by_database_constraint", state == "23514", state)
    r = a2.req("POST", f"/api/quotes/{q['id']}/status", {"status": "accepted"})
    rec("E2E.Q10_second_admin_approves", r.status_code == 200 and r.json()["status"] == "accepted", r.text)
    r = a2.req("PUT", f"/api/quotes/{q['id']}", {"title": "승인 후 수정", "items": items})
    rec("E2E.Q11_approved_quote_content_locked", r.status_code == 409 and code(r) == "quote_not_editable" and
        scalar("SELECT title FROM jw_dev.cinema_pg_quotes WHERE id=%s", (raw_of(q["id"]),)) == "E2E 견적 v2", r.text)

    # ---- order from quote with due date (atomic side table)
    Clock.today = date(2000, 1, 1)          # router believes 2000; the database knows the real date
    r = a1.req("POST", "/api/orders/from-quote", {"quote_id": q["id"], "due_date": "2001-01-01"})
    orders_after = scalar("SELECT count(*) FROM jw_dev.cinema_pg_orders WHERE quote_id=%s", (raw_of(q["id"]),))
    Clock.today = date.today()
    rec("E2E.O01_db_refused_due_date_rolls_back_the_order_too", r.status_code >= 400 and orders_after == 0 and
        scalar("SELECT status FROM jw_dev.cinema_pg_quotes WHERE id=%s", (raw_of(q["id"]),)) == "approved", f"{r.status_code} {r.text} orders={orders_after}")
    due = (date.today() + timedelta(days=14)).isoformat()
    r = a1.req("POST", "/api/orders/from-quote", {"quote_id": q["id"], "due_date": due}, key="order-key-0001")
    order = r.json() if r.status_code == 201 else {}
    rec("E2E.O02_order_created_with_due_date_preserved", r.status_code == 201 and order.get("due_date") == due and
        order.get("quote_id") == q["id"] and order.get("status") == "received", r.text)
    r = a1.req("POST", "/api/orders/from-quote", {"quote_id": q["id"], "due_date": due}, key="order-key-0001")
    rec("E2E.O03_same_idempotency_key_replays_same_order", r.status_code == 201 and r.json().get("id") == order.get("id") and
        scalar("SELECT count(*) FROM jw_dev.cinema_pg_orders WHERE quote_id=%s", (raw_of(q["id"]),)) == 1, r.text)
    r = a1.req("POST", "/api/orders/from-quote", {"quote_id": q["id"], "due_date": "2026-02-30"})
    rec("E2E.O04_impossible_due_date_422", r.status_code == 422, r.text)
    r = a1.req("GET", "/api/quotes/" + q["id"])
    rec("E2E.O05_ordered_quote_still_reads_accepted", r.status_code == 200 and r.json()["status"] == "accepted", r.text)
    r = a1.req("POST", f"/api/orders/{order.get('id')}/status", {"status": "fulfilled"})
    rec("E2E.O06_order_status_set_refused_explicitly", r.status_code == 409 and code(r) == "pg_order_status_is_derived", r.text)
    r = a1.req("POST", "/api/invoices/from-order", {"order_id": order.get("id"), "due_date": due})
    rec("E2E.O07_invoice_from_order_refused_no_fabricated_delivery", r.status_code == 409 and
        code(r) == "pg_requires_confirmed_delivery_and_statement" and
        scalar("SELECT count(*) FROM jw_dev.cinema_pg_deliveries WHERE order_id=%s", (raw_of(order["id"]),)) == 0, r.text)
    r = a1.req("PUT", f"/api/orders/{order.get('id')}", {"items": []})
    rec("E2E.O08_order_line_change_refused", r.status_code == 409 and code(r) == "pg_order_lines_are_fixed", r.text)

    # ---- delivery -> statement -> invoice through the existing native router
    base = "/api/pg-stage/cinema-trade"
    ev = a1.req("POST", f"{base}/evidence?request_id={rid()}&name=e2e.pdf", raw=b"%PDF-1.4 e2e synthetic", ctype="application/pdf")
    ev_ent = (ev.json() or {}).get("entity", {}) if ev.status_code == 200 else {}
    item_id = scalar("SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id=%s", (raw_of(order["id"]),))
    d = a1.req("POST", f"{base}/orders/{raw_of(order['id'])}/deliveries",
               {"request_id": rid(), "lines": [{"order_item_id": item_id, "quantity": 3}],
                "evidence_sha256": ev_ent.get("content_sha256", "0" * 64), "evidence_name": "e2e.pdf"})
    delivery = (d.json() or {}).get("entity", {}) if d.status_code == 200 else {}
    rec("E2E.D01_delivery_recorded_with_server_evidence", ev.status_code == 200 and d.status_code == 200 and delivery.get("id"), ev.text[:150] + d.text[:150])
    r = a1.req("POST", f"{base}/deliveries/{delivery.get('id')}/confirm", {"request_id": rid()})
    rec("E2E.D02_recorder_cannot_confirm_own_delivery", r.status_code in (403, 409), r.text)
    a2.req("POST", f"{base}/evidence/{ev_ent.get('id')}/open", {"request_id": rid()})
    r = a2.req("POST", f"{base}/deliveries/{delivery.get('id')}/confirm", {"request_id": rid()})
    rec("E2E.D03_other_admin_confirms_after_opening_evidence", r.status_code == 200, r.text)
    r = a1.req("GET", "/api/orders/" + order["id"])
    rec("E2E.D04_order_reads_processing_after_confirmed_delivery", r.status_code == 200 and r.json()["status"] in ("processing", "fulfilled"), r.text)
    s = am.req("POST", f"{base}/deliveries/{delivery.get('id')}/statements", {"request_id": rid()})
    st = (s.json() or {}).get("entity", {}) if s.status_code == 200 else {}
    a1.req("POST", f"{base}/statements/{st.get('id')}/confirm", {"request_id": rid()})
    i = am.req("POST", f"{base}/statements/{st.get('id')}/invoices", {"request_id": rid()})
    inv_raw = ((i.json() or {}).get("entity", {}) if i.status_code == 200 else {}).get("id")
    rec("E2E.D05_statement_and_draft_invoice_created", bool(st.get("id")) and bool(inv_raw), s.text[:150] + i.text[:150])
    inv_pub = "pg_" + str(inv_raw)
    pay_by = (date.today() + timedelta(days=30)).isoformat()
    r = a1.req("POST", f"{legacy.NATIVE_PREFIX}/invoices/{inv_pub}/pay-by", {"due_date": pay_by})
    rec("E2E.D06_pay_by_date_stored", r.status_code == 200 and r.json()["due_date"] == pay_by, r.text)
    a1.req("POST", f"{base}/invoices/{inv_raw}/review", {"request_id": rid()})
    r = a1.req("POST", f"{base}/invoices/{inv_raw}/confirm", {"request_id": rid()})
    rec("E2E.D07_invoice_confirmed", r.status_code == 200, r.text)

    # ---- invoices and payments through the legacy routes
    r = a1.req("GET", "/api/invoices/" + inv_pub)
    inv = r.json() if r.status_code == 200 else {}
    rec("E2E.P01_invoice_legacy_shape_engine_money", r.status_code == 200 and inv.get("money") == {"subtotal": 30000, "vat": 3000, "total": 33000}
        and inv.get("balance") == 33000 and inv.get("payment_status") == "unpaid" and inv.get("status") == "issued"
        and inv.get("order_id") == order["id"], r.text)
    rec("E2E.P02_invoice_keys_the_invoice_screen_reads", {"id", "doc_no", "customer_name", "money", "paid", "balance",
        "payment_status", "settlement", "order_id", "due_date"} <= set(inv) and "adjusted_total" in inv.get("settlement", {}), str(sorted(inv)))
    pay = {"amount": 10_000, "paid_at": date.today().isoformat(), "reference": "BANK-E2E-1", "note": "부분 입금, 한글 메모"}
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments", pay, key="pay-key-000001")
    rec("E2E.P03_payment_with_note_201", r.status_code == 201 and r.json()["paid"] == 10_000 and r.json()["balance"] == 23_000
        and r.json()["payments"][0]["note"] == "부분 입금, 한글 메모", r.text)
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments", pay, key="pay-key-000001")
    rec("E2E.P04_retry_same_key_is_one_payment", r.status_code == 201 and
        scalar("SELECT count(*) FROM jw_dev.cinema_pg_payments WHERE invoice_id=%s", (inv_raw,)) == 1, r.text)
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments", {**pay, "amount": 11_000}, key="pay-key-000001")
    rec("E2E.P05_same_key_different_amount_conflict", r.status_code == 409 and code(r) == "idempotency_conflict", r.text)
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments", {**pay, "reference": "BANK-E2E-2", "amount": 999_999})
    rec("E2E.P06_overpayment_refused", r.status_code == 409 and code(r) == "overpayment", r.text)
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments",
               {**pay, "reference": "BANK-E2E-3", "paid_at": (date.today() + timedelta(days=2)).isoformat()})
    rec("E2E.P07_future_payment_refused", r.status_code == 422 and code(r) == "future_payment", r.text)
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments", {"amount": 1, "paid_at": date.today().isoformat(), "reference": "  "})
    rec("E2E.P08_blank_reference_422_not_502", r.status_code == 422 and code(r) == "bad_reference", r.text)
    r = b1.req("POST", f"/api/invoices/{inv_pub}/payments", {**pay, "reference": "BANK-B"})
    rec("E2E.P09_other_company_cannot_pay_it", r.status_code in (404, 409) and
        scalar("SELECT count(*) FROM jw_dev.cinema_pg_payments WHERE invoice_id=%s", (inv_raw,)) == 1, r.text)
    # note insert fails at the DB -> the payment must not survive (atomic pair)
    before_p = scalar("SELECT count(*) FROM jw_dev.cinema_pg_payments WHERE invoice_id=%s", (inv_raw,))
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments", {**pay, "reference": "BANK-E2E-4", "amount": 1, "note": "x" * 501})
    rec("E2E.P10_invalid_note_refused_and_no_payment_written", r.status_code == 422 and
        scalar("SELECT count(*) FROM jw_dev.cinema_pg_payments WHERE invoice_id=%s", (inv_raw,)) == before_p, r.text)

    # ---- concurrency: 8 parallel identical requests -> exactly one payment
    outcomes: list[int] = []
    lock = threading.Lock()
    def worker():
        resp = a1.req("POST", f"/api/invoices/{inv_pub}/payments",
                      {"amount": 500, "paid_at": date.today().isoformat(), "reference": "BANK-RACE"}, key="race-key-00001")
        with lock:
            outcomes.append(resp.status_code)
    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    race_rows = scalar("SELECT count(*) FROM jw_dev.cinema_pg_payments WHERE invoice_id=%s AND reference='BANK-RACE'", (inv_raw,))
    rec("E2E.R01_parallel_retries_create_exactly_one_payment", race_rows == 1 and all(s in (201, 409) for s in outcomes)
        and 201 in outcomes, f"rows={race_rows} statuses={sorted(outcomes)}")
    r = a1.req("GET", "/api/invoices/" + inv_pub)
    rec("E2E.R02_balance_consistent_after_race", r.status_code == 200 and r.json()["paid"] == 10_500 and r.json()["balance"] == 22_500, r.text)

    # ---- overdue is computed only from a recorded pay-by date
    Clock.today = date.today() + timedelta(days=31)
    r = a1.req("GET", "/api/invoices/" + inv_pub)
    Clock.today = date.today()
    rec("E2E.R03_overdue_after_pay_by_date", r.status_code == 200 and r.json()["payment_status"] == "overdue", r.text)
    r = a1.req("POST", f"/api/invoices/{inv_pub}/payments", {"amount": 22_500, "paid_at": date.today().isoformat(), "reference": "BANK-REST"})
    rec("E2E.R04_final_payment_marks_paid", r.status_code == 201 and r.json()["balance"] == 0 and r.json()["payment_status"] == "paid", r.text)

    # ---- every fixture row of the engine test (all states) maps to the legacy shape without guessing
    for path in ("/api/customers", "/api/quotes", "/api/orders", "/api/invoices"):
        r = a1.req("GET", path)
        rec(f"E2E.L_{path.split('/')[-1]}_list_maps_every_row", r.status_code == 200 and isinstance(r.json(), list) and len(r.json()) >= 1, r.text[:200])
    r = b1.req("GET", "/api/invoices")
    rec("E2E.L_other_company_invoice_list_excludes_A", r.status_code == 200 and all(x["id"] != inv_pub for x in r.json()), r.text[:200])

    # ---- per-company rollback: switch A off, nothing changes, switch on, same data
    snapshot = {p: a1.req("GET", p).json() for p in ("/api/customers", "/api/quotes", "/api/orders", "/api/invoices")}
    counts = sql("SELECT (SELECT count(*) FROM jw_dev.cinema_pg_quotes),(SELECT count(*) FROM jw_dev.cinema_pg_payments),"
                 "(SELECT count(*) FROM jw_dev.cinema_pg_order_terms),(SELECT count(*) FROM jw_dev.cinema_pg_payment_notes)")
    ORGS["value"] = "ci-b"
    off = [a1.req("GET", p) for p in snapshot]
    w_off = a1.req("POST", "/api/customers", {"name": "꺼진 상태 쓰기"})
    rec("E2E.K01_switch_off_refuses_reads_and_writes", all(x.status_code == 409 and code(x) == "pg_store_disabled_for_org" for x in off + [w_off]),
        str([x.status_code for x in off + [w_off]]))
    rec("E2E.K02_switch_off_does_not_delete_or_write", sql("SELECT (SELECT count(*) FROM jw_dev.cinema_pg_quotes),(SELECT count(*) FROM jw_dev.cinema_pg_payments),"
        "(SELECT count(*) FROM jw_dev.cinema_pg_order_terms),(SELECT count(*) FROM jw_dev.cinema_pg_payment_notes)") == counts)
    r = b1.req("GET", "/api/customers")
    rec("E2E.K03_other_company_unaffected_by_A_switch", r.status_code == 200, r.text[:100])
    ORGS["value"] = "ci-a,ci-b"
    back = {p: a1.req("GET", p).json() for p in snapshot}
    rec("E2E.K04_switch_on_again_returns_identical_data", back == snapshot)
    ORGS["value"] = "ci-a,BAD ORG!"
    r = a1.req("GET", "/api/quotes")
    rec("E2E.K05_malformed_allowlist_enables_nobody", r.status_code == 409 and code(r) == "pg_store_disabled_for_org", r.text)
    ORGS["value"] = "ci-a,ci-b"

    # ---- odd inputs never become 500
    odd = [("POST", "/api/customers", ["not", "an", "object"]), ("POST", "/api/quotes", {"customer_id": cust["id"], "title": "\x00"}),
           ("POST", f"/api/quotes/{q['id']}/status", {"status": ["accepted"]}), ("POST", "/api/orders/from-quote", {"quote_id": 5}),
           ("POST", f"/api/invoices/{inv_pub}/payments", {"amount": "10", "paid_at": "2026-01-01", "reference": "R"})]
    statuses = [a1.req(m, p, b).status_code for m, p, b in odd]
    rec("E2E.X01_malformed_bodies_are_4xx_never_5xx", all(400 <= s < 500 for s in statuses), str(statuses))
    r = a1.c.request("POST", "/api/customers", content=b"{not json", headers={
        "Cookie": f"{legacy.SESSION_COOKIE}={a1.token}", "X-CSRF-Token": a1.csrf, "Content-Type": "application/json"})
    rec("E2E.X02_invalid_json_is_422", r.status_code == 422, r.text)

    # ---- engine integrity after the whole run
    found_issues = []
    for user in (a1, b1):
        hashed = hashlib.sha256(user.token.encode()).hexdigest()
        found_issues += legacy.WriterTx(connect).run(hashed, lambda cur: cur.execute(
            "SELECT check_name, entity_id FROM jw_dev.cinema_pg_integrity_check()").fetchall())
    rec("E2E.Z01_engine_integrity_check_reports_nothing", found_issues == [], str(found_issues[:5]))
    rec("E2E.Z02_no_bank_confirmed_payment_fabricated", scalar("SELECT count(*) FROM jw_dev.cinema_pg_payments WHERE bank_confirmed") == 0)


def main() -> int:
    global DB
    gate.local_server_or_die()
    server = gate.Psql("postgres").sql("SHOW server_version_num").stdout.strip()
    allow16 = "--allow-pg16-local" in sys.argv
    if not server.isdigit() or (int(server) < 170000 and not allow16):
        print("BLOCKED: PostgreSQL 17 required (use --allow-pg16-local only for a local supplemental run)")
        return 2
    DB = "jw_cinema_e2e_" + secrets.token_hex(4)
    admin = gate.Psql("postgres")
    if admin.sql(f"CREATE DATABASE {DB}").returncode != 0:
        raise SystemExit("BLOCKED: cannot create disposable database")
    try:
        db = gate.Psql(DB)
        for role in ("jw_app_dev", "jw_auth_stage_v85", "anon", "authenticated", "service_role"):
            admin.sql(f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='{role}') "
                      f"THEN CREATE ROLE {role} NOLOGIN NOINHERIT NOBYPASSRLS; END IF; END $$")
        for path in gate.BASE_FILES:
            if db.file(path).returncode != 0:
                raise SystemExit(f"FAIL: base schema {path}")
        steps = ((gate.ENGINE, True), (gate.TESTS, False), (str(TWO_PERSON), False), (str(TERMS), False))
        for path, single in steps:
            p = db.file(path, single_transaction=single)
            rec(f"E2E.S_{Path(path).stem}_applied", p.returncode == 0, p.stderr.strip()[-300:])
            if p.returncode != 0:
                raise SystemExit(f"FAIL: {path}")
        run()
    finally:
        if os.environ.get("JW_CINEMA_KEEP_DB") != "1":
            admin.sql(f"DROP DATABASE IF EXISTS {DB} WITH (FORCE)")
    failed = [n for n, ok, _ in results if not ok]
    names = [n for n, _, _ in results]
    dup = sorted({n for n in names if names.count(n) > 1})
    ok = not failed and not dup and len(results) == EXPECTED_CHECKS
    print(json.dumps({"server_version_num": server, "total": len(results), "expected": EXPECTED_CHECKS,
                      "failed": failed, "duplicates": dup}, ensure_ascii=False))
    print(("PASS" if ok else "FAIL") + f": {len(results)} checks, {len(failed)} failed, expected exactly {EXPECTED_CHECKS}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
