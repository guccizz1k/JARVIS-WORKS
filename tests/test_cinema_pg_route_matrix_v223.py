"""Route matrix tool: synthetic parser cases plus drift detection against the real tree.

The real-tree tests read source text only; they need neither FastAPI nor a database.
"""
from pathlib import Path

import pytest

from scripts import ci_cinema_pg_route_matrix_v223 as rm

ROOT = Path(__file__).resolve().parents[1]


def write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def test_decorator_routes_with_module_constant_prefix_and_add_api_route(tmp_path):
    write(tmp_path, "main.py", '''
from fastapi import FastAPI
app = FastAPI()
@app.get("/api/quotes")
def list_quotes(): ...
@app.post("/api/quotes/{quote_id}/status")
async def set_status(quote_id): ...
''')
    write(tmp_path, "pg_thing.py", '''
from fastapi import APIRouter
_PREFIX = "/api/pg-stage/thing"
def create_router():
    router = APIRouter(prefix=_PREFIX)
    @router.get("/items/{item_id}")
    def one(item_id): ...
    router.add_api_route("/items", lambda: 1, methods=["POST", "PUT"])
    return router
''')
    got = {(r["method"], r["path"], r["layer"]) for r in rm.extract_routes(tmp_path)}
    assert ("GET", "/api/quotes", "legacy") in got
    assert ("POST", "/api/quotes/{quote_id}/status", "legacy") in got
    assert ("GET", "/api/pg-stage/thing/items/{item_id}", "pg-stage") in got
    assert ("POST", "/api/pg-stage/thing/items", "pg-stage") in got
    assert ("PUT", "/api/pg-stage/thing/items", "pg-stage") in got


def test_register_routes_function_in_a_legacy_module_is_found(tmp_path):
    write(tmp_path, "automation_v60.py", '''
def register_routes(app, conn):
    @app.get("/api/automation/summary")
    def summary(): ...
''')
    (route,) = rm.extract_routes(tmp_path)
    assert (route["method"], route["path"], route["layer"], route["resolved"]) == \
        ("GET", "/api/automation/summary", "legacy", True)


def test_dynamic_server_path_is_reported_unresolved_not_dropped(tmp_path):
    write(tmp_path, "main.py", '''
@app.get(make_path())
def f(): ...
''')
    (route,) = rm.extract_routes(tmp_path)
    assert route["resolved"] is False and route["path"] == "?"


def calls_for(tmp_path, js):
    (tmp_path / "x.js").write_text(js, encoding="utf-8")
    return rm.extract_ui_calls(tmp_path)


def test_api_helper_takes_method_as_second_positional_argument(tmp_path):
    got = {(c["method"], c["path"]) for c in calls_for(tmp_path, '''
async function api(path,method='GET',data){ return fetch('/api'+path,{method}); }
api('/quotes');
api('/quotes','POST',{a:1});
api(`/orders/${id}/status`,'POST',{});
api('/customers/'+encodeURIComponent(cid)+'/x','PUT');
''')}
    assert got == {("GET", "/api/quotes"), ("POST", "/api/quotes"),
                   ("POST", "/api/orders/{}/status"), ("PUT", "/api/customers/{}/x")}


def test_helper_definition_and_its_own_fetch_are_not_counted_as_calls(tmp_path):
    assert calls_for(tmp_path, "async function api(path,method='GET'){return fetch('/api'+path,{method})}") == []


def test_fetch_defaults_to_get_and_reads_explicit_method(tmp_path):
    got = {(c["method"], c["path"]) for c in calls_for(tmp_path, '''
fetch('/api/a/'+encodeURIComponent(id)+'/xlsx',{credentials:'same-origin'});
fetch('/api/imports/preview',{method:'POST',body});
fetch('/static/app.css');
''')}
    assert got == {("GET", "/api/a/{}/xlsx"), ("POST", "/api/imports/preview")}


def test_assigned_path_variable_uses_the_whole_right_hand_side(tmp_path):
    (call,) = calls_for(tmp_path, '''
const base='/messenger/threads/'+tid+'/messages/page';
api(base+'?limit=50');
''')
    assert call["path"] == "/api/messenger/threads/{}/messages/page" and call["resolved"]


def test_trailing_query_suffix_is_not_a_path_segment(tmp_path):
    (call,) = calls_for(tmp_path, "api('/order-analytics'+(query.size?'?'+query:''));")
    assert call["path"] == "/api/order-analytics"


def test_unknown_path_or_method_is_unresolved_never_matched(tmp_path):
    calls = calls_for(tmp_path, "api(somePath);\napi('/a','PO'+'ST');")
    assert calls and all(c["resolved"] is False for c in calls)


def _routes(*items):
    return [{"module": "m", "method": m, "path": p, "handler": "h", "line": 1,
             "layer": "legacy", "resolved": True} for m, p in items]


def _calls(*items):
    return [{"file": "a.js", "line": i, "method": m, "path": p, "resolved": True, "via": "api()"}
            for i, (m, p) in enumerate(items, 1)]


def test_matrix_statuses():
    matrix = rm.build_matrix(
        _routes(("GET", "/api/q/{id}"), ("POST", "/api/u/{id}/disable"), ("POST", "/api/u/{id}/enable")),
        _calls(("GET", "/api/q/{}"), ("POST", "/api/q/{}"), ("GET", "/api/none"), ("POST", "/api/u/{}/{}")))
    status = {(r["method"], r["path"]): r["status"] for r in matrix["ui_calls"]}
    assert status[("GET", "/api/q/{}")] == "SERVED"
    assert status[("POST", "/api/q/{}")] == "METHOD_MISMATCH"
    assert status[("GET", "/api/none")] == "NO_SERVER_ROUTE"
    assert status[("POST", "/api/u/{}/{}")] == "SERVED_DYNAMIC"
    unresolved = rm.build_matrix(_routes(), [{"file": "a.js", "line": 3, "method": "?", "path": "?",
                                              "resolved": False, "via": "api()"}])
    assert unresolved["ui_calls"][0]["status"] == "UNRESOLVED"


# ------------------------------------------------ drift detection on the real tree
@pytest.fixture(scope="module")
def real():
    routes = rm.extract_routes(ROOT / "app")
    return routes, rm.build_matrix(routes, rm.extract_ui_calls(ROOT / "app" / "static"))


def test_every_server_route_path_in_the_real_tree_is_statically_resolved(real):
    routes, _ = real
    assert [r for r in routes if not r["resolved"]] == []
    assert len(routes) > 100


def test_every_v222_ui_call_resolves_to_a_registered_route(real):
    _, matrix = real
    bad = [(r["status"], r["method"], r["path"], r["file"], r["line"]) for r in matrix["ui_calls"]
           if r["status"] not in ("SERVED", "SERVED_DYNAMIC")]
    assert bad == []


def test_core_mapping_only_names_routes_that_really_exist(real):
    routes, _ = real
    assert rm.mapping_problems(routes) == []
    assert {row[4] for row in rm.CORE_MAPPING} == {"READ", "ADAPT", "GAP"}


def test_markdown_report_mentions_every_ui_call_and_every_mapping_row(real):
    _, matrix = real
    text = rm.render_markdown(matrix)
    assert text.count("\n| ") >= len(matrix["ui_calls"]) + len(rm.CORE_MAPPING)
    assert "Semantics are NOT compared" in text


def test_mapping_drift_is_detected_when_a_route_disappears(real):
    routes, _ = real
    without_quotes = [r for r in routes if r["path"] != "/api/quotes"]
    assert any(p.startswith("legacy missing") for p in rm.mapping_problems(without_quotes))
    without_pg = [r for r in routes if not r["path"].endswith("/partners")]
    assert any(p.startswith("pg missing") for p in rm.mapping_problems(without_pg))
