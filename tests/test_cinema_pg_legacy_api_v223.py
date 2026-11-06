"""Offline tests of app.pg_cinema_legacy_api_v1 (the wired legacy-contract PG router).

The behavioural proof against a real PostgreSQL is scripts/ci_cinema_pg_legacy_api_e2e_v223.py (74 checks,
PG17 in CI). These tests pin what can be decided without a database: gates, the per-company allow-list,
that authentication / CSRF / company switch / store routing are decided BEFORE any business SQL, and that
every legacy path served here exists in app/main.py with the same method and success status.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import pg_cinema_compat_v1 as compat
from app import pg_cinema_legacy_api_v1 as legacy

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "t" * 40
PG = "pg_" + "a" * 32


class FakeCur:
    def __init__(self, identity):
        self.identity, self.log, self._last, self.description = identity, [], None, None

    def execute(self, sql, params=()):
        self.log.append(sql)
        if "stage_identity_v84" in sql:
            self._rows = [self.identity] if self.identity else []
            self.description = [type("C", (), {"name": n})() for n in ("actor_id", "org_id", "actor_role", "csrf_token")]
        else:
            raise AssertionError("business SQL reached: " + sql[:60])
        return self

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._rows[0] if self._rows else None


class FakeTx:
    def __init__(self, identity=("u1", "org-a", "admin", "csrf-1")):
        self.identity, self.cursors = identity, []

    def run(self, session_hash, work):
        cur = FakeCur(self.identity)
        self.cursors.append(cur)
        return work(cur)


def client(tx, orgs=("org-a",)):
    app = FastAPI()
    app.include_router(legacy.create_legacy_router(tx, org_enabled=lambda o: o in orgs))
    return TestClient(app, base_url="https://testserver")


def call(c, method, path, body=None, csrf="csrf-1", cookie=TOKEN):
    headers = {}
    if cookie:
        headers["Cookie"] = f"{legacy.SESSION_COOKIE}={cookie}"
    if csrf:
        headers["X-CSRF-Token"] = csrf
    return c.request(method, path, json=body, headers=headers)


# ------------------------------------------------------------------ configuration
@pytest.mark.parametrize("raw,expected", [
    ("", frozenset()), ("  ", frozenset()), ("org-a", {"org-a"}), ("org-a, org-b ,", {"org-a", "org-b"}),
    ("org-a,BAD ORG", frozenset()), ("org-a,x;drop", frozenset()), ("a" * 65, frozenset()),
])
def test_allow_list_is_strict_and_fails_closed(raw, expected):
    assert legacy.enabled_orgs({legacy.ORGS_ENV: raw}) == frozenset(expected)


def test_gate_value_is_exact():
    assert legacy.legacy_api_gate_on({legacy.GATE_ENV: legacy.GATE_VALUE})
    for value in ("", "1", "true", legacy.GATE_VALUE.lower(), legacy.GATE_VALUE + " "):
        assert not legacy.legacy_api_gate_on({legacy.GATE_ENV: value})


def test_register_requires_both_gates(monkeypatch):
    from app import pg_cinema_register_v1 as reg
    app = FastAPI()
    monkeypatch.setenv(legacy.GATE_ENV, legacy.GATE_VALUE)
    monkeypatch.setattr(reg, "cinema_trade_enabled", lambda: False)
    assert legacy.register_legacy_api_v1(app) is False
    monkeypatch.setattr(reg, "cinema_trade_enabled", lambda: True)
    monkeypatch.delenv(legacy.GATE_ENV)
    assert legacy.register_legacy_api_v1(app) is False
    assert TestClient(app, base_url="https://testserver").get("/api/quotes").status_code == 404
    monkeypatch.setenv(legacy.GATE_ENV, legacy.GATE_VALUE)
    monkeypatch.setenv(legacy.ORGS_ENV, "org-a,BAD ORG")
    with pytest.raises(RuntimeError, match="malformed"):
        legacy.register_legacy_api_v1(app)
    monkeypatch.setenv(legacy.ORGS_ENV, "")
    assert legacy.register_legacy_api_v1(app) is True
    assert TestClient(app, base_url="https://testserver").get("/api/quotes").status_code == 401   # mounted


def test_v202_registers_the_legacy_api_separately_and_preflights_its_gate():
    src = (ROOT / "app/pg_review_integrated_v202.py").read_text(encoding="utf-8")
    assert "cinema_legacy_api.register_legacy_api_v1(app)" in src
    assert "BLOCKED: legacy-contract PG API needs its own gate and the CINEMA trade gate" in src


# ------------------------------------------------------------------ decided before business SQL
def test_no_cookie_is_401_and_opens_no_transaction():
    tx = FakeTx()
    r = call(client(tx), "GET", "/api/quotes", cookie=None)
    assert r.status_code == 401 and tx.cursors == []


def test_unknown_session_is_401():
    r = call(client(FakeTx(identity=None)), "GET", "/api/quotes")
    assert r.status_code == 401 and r.json()["code"] == "session_required"


@pytest.mark.parametrize("csrf", [None, "", "csrf-2", "csrf-1 "])
def test_write_without_matching_csrf_is_403(csrf):
    tx = FakeTx()
    r = call(client(tx), "POST", "/api/customers", {"name": "N"}, csrf=csrf)
    assert r.status_code == 403 and r.json()["code"] == "csrf_failed"
    assert all("stage_identity_v84" in s for cur in tx.cursors for s in cur.log)


def test_company_off_refuses_reads_and_writes():
    for method, path, body in (("GET", "/api/quotes", None), ("POST", "/api/customers", {"name": "N"}),
                               ("GET", f"/api/invoices/{PG}", None)):
        r = call(client(FakeTx(), orgs=()), method, path, body)
        assert r.status_code == 409 and r.json()["code"] == "pg_store_disabled_for_org", path


@pytest.mark.parametrize("path", [
    "/api/quotes/0123456789abcdef0123456789abcdef", "/api/orders/legacy-1", f"/api/invoices/{'b' * 32}",
])
def test_legacy_ids_are_routed_to_the_legacy_store(path):
    r = call(client(FakeTx()), "GET", path)
    assert r.status_code == 409 and r.json()["code"] == "legacy_store_record"


@pytest.mark.parametrize("bad", ["pg_", "pg_XYZ", "PG_" + "a" * 32 + "x", "pg_" + "A" * 32, "pg_" + "a" * 31])
def test_malformed_pg_ids_are_422(bad):
    r = call(client(FakeTx()), "GET", f"/api/quotes/{bad}")
    assert r.status_code == 422 and r.json()["code"] == "bad_id"


@pytest.mark.parametrize("method,path,body,expected", [
    ("POST", "/api/invoices/from-order", {"order_id": PG}, "pg_requires_confirmed_delivery_and_statement"),
    ("POST", f"/api/orders/{PG}/status", {"status": "fulfilled"}, "pg_order_status_is_derived"),
    ("POST", f"/api/orders/{PG}/acknowledge", {}, "pg_has_no_order_acknowledgement"),
    ("PUT", f"/api/orders/{PG}", {"items": []}, "pg_order_lines_are_fixed"),
])
def test_unsupported_steps_are_explicit_refusals_without_business_sql(method, path, body, expected):
    r = call(client(FakeTx()), method, path, body)
    assert r.status_code == 409 and r.json()["code"] == expected


def test_invalid_json_is_422_after_authentication():
    tx = FakeTx()
    c = client(tx)
    r = c.request("POST", "/api/customers", content=b"{nope", headers={
        "Cookie": f"{legacy.SESSION_COOKIE}={TOKEN}", "X-CSRF-Token": "csrf-1", "Content-Type": "application/json"})
    assert r.status_code == 422 and r.json()["code"] == "bad_body" and tx.cursors


# ------------------------------------------------------------------ contract parity with app/main.py
def _main_routes() -> dict[tuple[str, str], int]:
    tree = ast.parse((ROOT / "app/main.py").read_text(encoding="utf-8"))
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and getattr(dec.func.value, "id", "") == "app" and dec.args
                        and isinstance(dec.args[0], ast.Constant)):
                    status = next((k.value.value for k in dec.keywords if k.arg == "status_code"), 200)
                    path = re.sub(r"\{[^}]+\}", "{}", dec.args[0].value)
                    out[(dec.func.attr.upper(), path)] = status
    return out


def test_every_legacy_path_served_exists_in_main_with_same_method_and_status():
    main = _main_routes()
    router = legacy.create_legacy_router(FakeTx())
    served = []
    for route in router.routes:
        path = re.sub(r"\{[^}]+\}", "{}", route.path)
        if path.startswith(legacy.NATIVE_PREFIX):
            continue
        for method in route.methods:
            served.append((method, path))
            assert (method, path) in main, f"{method} {path} is not a legacy route"
    assert len(served) == 19
    creates = {("POST", "/api/customers"), ("POST", "/api/quotes"), ("POST", "/api/orders/from-quote"),
               ("POST", "/api/invoices/{}/payments")}
    assert {k for k in creates if main[k] == 201} == creates


def test_create_routes_answer_201_like_main():
    src = (ROOT / "app/pg_cinema_legacy_api_v1.py").read_text(encoding="utf-8")
    assert src.count("return await handle(request, True, work, 201)") == 4


# ------------------------------------------------------------------ new error mappings (found by the E2E)
def test_unique_index_mapping_is_declared_in_the_engine():
    engine = (ROOT / "scripts/review/cinema_pg_write_engine.sql").read_text(encoding="utf-8")
    for state, name, code, status, _ko, path in compat.PG_UNIQUE_INDEX_ERRORS:
        assert re.search(rf"CREATE UNIQUE INDEX {name}\b", (ROOT / path).read_text(encoding="utf-8"))
        err = compat.map_pg_error(state, f'duplicate key value violates unique constraint "{name}"')
        assert (err.code, err.http_status) == (code, status)
    assert compat.map_pg_error("23505", 'violates unique constraint "cinema_pg_partner_bn_uq_x"').code == "pg_engine_error"
    assert "only draft quotes can be edited" in engine
    assert compat.map_pg_error("23514", "only draft quotes can be edited").code == "quote_not_editable"


def test_e2e_check_count_is_exact():
    src = (ROOT / "scripts/ci_cinema_pg_legacy_api_e2e_v223.py").read_text(encoding="utf-8")
    assert "EXPECTED_CHECKS = 74" in src and "len(results) == EXPECTED_CHECKS" in src
