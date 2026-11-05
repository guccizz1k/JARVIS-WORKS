"""Static contract between the FastAPI adapter and the SQL engine.

FastAPI/psycopg are NOT imported (they are not needed to check the contract): the adapter is
parsed with `ast` and compared with the engine's function signatures. Runtime behaviour of the
adapter (HTTP, CSRF, transactions) is a separate gate that needs fastapi + psycopg + a database.
"""
import ast
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = (ROOT / "app" / "pg_cinema_trade_v1.py").read_text(encoding="utf-8")
SQL = (ROOT / "scripts" / "review" / "cinema_pg_write_engine.sql").read_text(encoding="utf-8")
TREE = ast.parse(ADAPTER)


def sql_arity():
    out = {}
    for m in re.finditer(r"^CREATE FUNCTION jw_dev\.(cinema_pg_\w+)\(([^)]*)\)", SQL, re.M):
        args = [a for a in m.group(2).split(",") if a.strip() and not a.strip().startswith("OUT ")]
        out[m.group(1)] = len(args)
    return out


def adapter_calls():
    calls = []
    for node in ast.walk(TREE):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "write"
                and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant)):
            calls.append((node.args[1].value, len(node.args) - 2))
    return calls


def test_adapter_compiles():
    compile(ADAPTER, "pg_cinema_trade_v1.py", "exec")


def test_every_write_call_targets_an_existing_function_with_matching_arity():
    arity, calls = sql_arity(), adapter_calls()
    assert len(calls) >= 18
    for name, n in calls:
        assert name in arity, name
        assert arity[name] == n, (name, arity[name], n)


def test_every_public_write_function_is_exposed():
    exposed = {name for name, _ in adapter_calls()}
    expected = set(re.findall(r"'(cinema_pg_\w+)'", SQL[SQL.index("$grants$"):]))
    expected -= {"cinema_pg_trade_trace", "cinema_pg_integrity_check"}
    direct = {"cinema_pg_evidence_put", "cinema_pg_evidence_open"}   # binary routes call SQL directly
    for name in direct:
        assert f"jw_dev.{name}(" in ADAPTER, name
    assert expected - direct <= exposed, expected - direct - exposed


def test_runs_as_least_privilege_role_inside_one_transaction():
    assert 'WRITER_ROLE = "jw_cinema_writer"' in ADAPTER
    assert "SET LOCAL ROLE" in ADAPTER and "conn.transaction()" in ADAPTER
    assert "set_config('jw.session_hash', %s, true)" in ADAPTER  # transaction-local, never session-wide


def test_session_and_csrf_are_enforced_before_any_sql():
    body = ADAPTER[ADAPTER.index("def verified"):ADAPTER.index("def write")]
    assert body.index("authorize(request)") < body.index("gateway.query")
    assert "csrf_verified" in body and "403" in body and "401" in body
    assert body.index("identity = identity or verified(request)") < body.index("gateway.query")


def test_no_tenant_or_identity_fields_are_accepted_from_the_browser():
    for forbidden in ("org_id", "actor_id", "session_hash", "role", "tenant"):
        for cls in [n for n in TREE.body if isinstance(n, ast.ClassDef) and n.name not in ("VerifiedSession",)]:
            fields = [t.target.id for t in cls.body if isinstance(t, ast.AnnAssign) and isinstance(t.target, ast.Name)]
            assert forbidden not in fields, (cls.name, forbidden)


def test_money_fields_are_integers_never_floats():
    for node in ast.walk(TREE):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and ("krw" in node.target.id or node.target.id in ("unit_price", "quantity")):
            assert ast.unparse(node.annotation) == "int", node.target.id


def test_list_endpoint_uses_fixed_allow_list_not_user_text():
    assert "READ_TABLES" in ADAPTER and 'if kind not in READ_TABLES' in ADAPTER
    for table, _ in re.findall(r'\("(cinema_pg_\w+)", "([^"]+)"\)', ADAPTER):
        assert table in SQL


def test_error_mapping_covers_engine_sqlstates():
    used = set(re.findall(r"ERRCODE='([0-9A-Z]{5})'", SQL))
    mapped = set(re.findall(r'"([0-9A-Z]{5})":\s*\(', ADAPTER))
    assert used <= mapped, used - mapped


def test_adapter_is_not_mounted_by_import():
    assert not re.search(r"^\s*app\s*=|include_router\(|uvicorn", ADAPTER, re.M)


def test_evidence_upload_authenticates_before_reading_any_body_and_caps_size():
    body = ADAPTER[ADAPTER.index("async def evidence_put"):ADAPTER.index('@router.post("/evidence/{evidence_id}/open")')]
    assert body.index("verified(request)") < body.index("request.stream()")
    assert "MAX_EVIDENCE_BYTES" in body and "413" in body and "415" in body and "422" in body
    assert "total > MAX_EVIDENCE_BYTES" in body          # streamed cap, not only the Content-Length header


def test_evidence_download_is_post_csrf_audited_attachment_nosniff():
    body = ADAPTER[ADAPTER.index('@router.post("/evidence/{evidence_id}/open")'):ADAPTER.index("# ---------------------------------------------------------------- reads")]
    assert "attachment" in body and "nosniff" in body and "no-store" in body
    assert "@router.get" not in body


def test_evidence_listing_never_selects_file_bytes():
    assert "READ_SELECT" in ADAPTER
    expr = ADAPTER[ADAPTER.index("READ_SELECT = {"):ADAPTER.index("READ_TABLES = {")]
    assert "'file_name'" in expr and "content," not in expr and "'content'" not in expr
