#!/usr/bin/env python3
"""Route parity matrix: what the V22.2 UI calls vs what the server really registers.

Standard library only (ast + a small JS argument scanner). It does NOT import the
application, so it runs without FastAPI. It reads source text only; it never opens a
database and never starts a server.

It exists because a regex over ``app/main.py`` undercounted the legacy surface: most legacy
``/api`` routes are registered by ``register_routes(app, ...)`` functions in other modules,
and the UI helper is ``api(path, method='GET', data)`` (method is the 2nd positional argument).

Confidence is stated per row. A call whose path cannot be resolved statically is listed as
``UNRESOLVED`` and is never silently counted as matched. Dynamic registration that this
tool cannot see would show up as UI calls without a route, i.e. as a gap, not as a pass.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

HTTP = {"get", "post", "put", "patch", "delete", "head", "options"}
# Modules whose routes serve the legacy (SQLite-backed) UI API. Everything else under app/
# that registers routes belongs to the isolated PostgreSQL stage.
LEGACY_MODULES = {"main", "messenger", "automation_v60", "automation_v62", "evidence_v64",
                  "reconciliation_v65", "reconciliation_lines_v66", "exceptions_v67",
                  "complex_settlement_v69", "ops_integrity_v71", "import_batch_v63"}


def norm(path: str) -> str:
    """Normalise path parameters so '/q/{id}', '/q/${id}' and '/q/{x:path}' compare equal."""
    path = re.sub(r"\$\{[^}]*\}", "{}", path)
    path = re.sub(r"\{[^}]*\}", "{}", path)
    return path.split("?")[0].rstrip("/") or "/"


# ------------------------------------------------------------------ server side (ast)
def _const_str(node, consts: dict) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.JoinedStr):          # f-string: constants + placeholders
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                out.append(str(part.value))
            elif isinstance(part, ast.FormattedValue):
                inner = _const_str(part.value, consts)
                out.append(inner if inner is not None else "{}")
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _const_str(node.left, consts), _const_str(node.right, consts)
        return a + b if a is not None and b is not None else None
    return None


def extract_routes(app_dir: Path) -> list[dict]:
    routes: list[dict] = []
    for file in sorted(Path(app_dir).glob("*.py")):
        try:
            tree = ast.parse(file.read_text(encoding="utf-8"))
        except SyntaxError:
            routes.append({"module": file.stem, "method": "?", "path": "?", "handler": "?",
                           "line": 0, "layer": "unparsed", "resolved": False})
            continue
        consts = {n.targets[0].id: n.value.value for n in tree.body
                  if isinstance(n, ast.Assign) and len(n.targets) == 1
                  and isinstance(n.targets[0], ast.Name)
                  and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str)}
        layer = "legacy" if file.stem in LEGACY_MODULES else "pg-stage"

        def scan(scope_nodes, prefixes: dict):
            for node in scope_nodes:
                if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                    call = node.value
                    fn = call.func
                    name = fn.id if isinstance(fn, ast.Name) else getattr(fn, "attr", "")
                    if name == "APIRouter" and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                        prefix = ""
                        for kw in call.keywords:
                            if kw.arg == "prefix":
                                prefix = _const_str(kw.value, consts)
                        prefixes = {**prefixes, node.targets[0].id: prefix}
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    for deco in node.decorator_list:
                        if (isinstance(deco, ast.Call) and isinstance(deco.func, ast.Attribute)
                                and deco.func.attr in HTTP and deco.args):
                            owner = deco.func.value.id if isinstance(deco.func.value, ast.Name) else ""
                            rel = _const_str(deco.args[0], consts)
                            pre = prefixes.get(owner, "")
                            routes.append(_row(file.stem, deco.func.attr.upper(), pre, rel,
                                               node.name, deco.lineno, layer))
                    scan(node.body, dict(prefixes))
                elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                    call = node.value
                    if isinstance(call.func, ast.Attribute) and call.func.attr == "add_api_route" and call.args:
                        owner = call.func.value.id if isinstance(call.func.value, ast.Name) else ""
                        rel = _const_str(call.args[0], consts)
                        handler = call.args[1].id if len(call.args) > 1 and isinstance(call.args[1], ast.Name) else "?"
                        methods = ["GET"]
                        for kw in call.keywords:
                            if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                                methods = [e.value.upper() for e in kw.value.elts
                                           if isinstance(e, ast.Constant) and isinstance(e.value, str)]
                        for m in methods:
                            routes.append(_row(file.stem, m, prefixes.get(owner, ""), rel,
                                               handler, call.lineno, layer))
                elif hasattr(node, "body") and isinstance(getattr(node, "body"), list):
                    scan(node.body, dict(prefixes))
                    for extra in ("orelse", "finalbody"):
                        if isinstance(getattr(node, extra, None), list):
                            scan(getattr(node, extra), dict(prefixes))

        scan(tree.body, {})
    # an identical (method, path) registered twice in different modules is kept and flagged
    return routes


def _row(module, method, prefix, rel, handler, line, layer) -> dict:
    resolved = rel is not None and prefix is not None
    path = (prefix or "") + (rel or "") if resolved else "?"
    return {"module": module, "method": method, "path": path, "handler": handler, "line": line,
            "layer": layer, "resolved": resolved}


# ------------------------------------------------------------------ client side (JS)
def _scan_string(text: str, i: int):
    """Return (value, next_index) for a JS string/template literal starting at text[i]."""
    quote = text[i]
    i += 1
    out = []
    while i < len(text):
        c = text[i]
        if c == "\\":
            out.append(text[i + 1:i + 2])
            i += 2
            continue
        if quote == "`" and c == "$" and text[i + 1:i + 2] == "{":
            depth, j = 1, i + 2
            while j < len(text) and depth:
                depth += {"{": 1, "}": -1}.get(text[j], 0)
                j += 1
            out.append("{}")
            i = j
            continue
        if c == quote:
            return "".join(out), i + 1
        out.append(c)
        i += 1
    return "".join(out), i


def _split_args(text: str, start: int):
    """Split the argument list that begins right after '(' at ``start``; string aware."""
    args, depth, cur, i = [], 0, [], start
    while i < len(text):
        c = text[i]
        if c in "'\"`":
            _, j = _scan_string(text, i)
            cur.append(text[i:j])
            i = j
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                args.append("".join(cur).strip())
                return args, i
            depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
        i += 1
    args.append("".join(cur).strip())
    return args, i


def _eval_path(expr: str, names: dict | None = None) -> tuple[str, bool]:
    """Evaluate a path expression made of literals joined by '+'. Returns (path, resolved).

    ``names`` maps identifiers that are assigned exactly one string literal in the same
    file (for example ``const base='/messenger/messages'``) to that literal. A trailing
    non-literal appended directly after a word character (``'/x'+query``) is a query string
    suffix, not a path segment, and is dropped."""
    names = names or {}
    parts, i, buf, depth, resolved_all = [], 0, [], 0, True
    pieces = []
    while i < len(expr):
        c = expr[i]
        if c in "'\"`":
            value, j = _scan_string(expr, i)
            buf.append(("lit", value))
            i = j
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if c == "+" and depth == 0:
            pieces.append(buf)
            buf = []
        else:
            if not c.isspace():
                buf.append(("raw", c))
        i += 1
    pieces.append(buf)
    out = []
    for piece in pieces:
        lits = [v for k, v in piece if k == "lit"]
        raws = [v for k, v in piece if k == "raw"]
        if lits and not raws:
            out.append("".join(lits))
        elif piece:
            ident = "".join(raws)
            out.append(names[ident] if ident in names else "{}")
    path = "".join(out)
    path = re.sub(r"(?<=[A-Za-z0-9_-])\{\}$", "", path)      # '/order-analytics'+query
    path = path.split("?")[0]
    if not path.startswith("/"):
        resolved_all = False
    return path, resolved_all


CALL_RE = re.compile(r"(?<![\w.$])(api|fetch)\(")


def extract_ui_calls(static_dir: Path) -> list[dict]:
    calls: list[dict] = []
    for file in sorted(Path(static_dir).glob("*.js")):
        text = file.read_text(encoding="utf-8", errors="ignore")
        assigned: dict[str, set] = {}
        for am in re.finditer(r"""(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*((['"`]/)[^;\n]*)""", text):
            value, ok_value = _eval_path(am.group(2).rstrip().rstrip(","))
            if ok_value:                       # the WHOLE right-hand side, not just a first literal
                assigned.setdefault(am.group(1), set()).add(value)
        names = {k: next(iter(v)) for k, v in assigned.items() if len(v) == 1}
        for m in CALL_RE.finditer(text):
            kind = m.group(1)
            if text[max(0, m.start() - 9):m.start()].endswith("function "):
                continue                      # the definition of the helper, not a call
            args, _ = _split_args(text, m.end())
            if not args or not args[0]:
                continue
            path, ok = _eval_path(args[0], names)
            if path in ("/api", "/api{}"):
                continue                      # the helper's own fetch('/api'+path)
            line = text.count("\n", 0, m.start()) + 1
            if kind == "api":
                # api(path, method='GET', data)
                method, method_ok = "GET", True
                if len(args) > 1:
                    mm = re.fullmatch(r"""['"]([A-Za-z]+)['"]""", args[1])
                    if mm:
                        method = mm.group(1).upper()
                    else:
                        method, method_ok = "?", False
                full = "/api" + path if ok else "?"
                calls.append({"file": file.name, "line": line, "method": method, "path": full,
                              "resolved": ok and method_ok, "via": "api()"})
            else:
                if not path.startswith("/api"):
                    continue
                method = "GET"                   # fetch() default when no method key is given
                if len(args) > 1:
                    mm = re.search(r"""method\s*:\s*['"]([A-Za-z]+)['"]""", args[1])
                    if mm:
                        method = mm.group(1).upper()
                    elif re.search(r"\bmethod\s*:", args[1]):
                        method = "?"
                calls.append({"file": file.name, "line": line, "method": method,
                              "path": path, "resolved": ok and method != "?", "via": "fetch()"})
    return calls


# ------------------------------------------------------------------------- matrix
def _dynamic_candidates(by_key: dict, key: tuple) -> list:
    """UI path with a '{}' that may stand for a fixed word (e.g. /users/{}/{operation})."""
    method, path = key
    want = path.split("/")
    out = []
    for (m, p), rows in by_key.items():
        got = p.split("/")
        if m == method and len(got) == len(want) and all(
                w == g or w == "{}" for w, g in zip(want, got)):
            out.append(((m, p), rows))
    return out


def build_matrix(routes: list[dict], calls: list[dict]) -> dict:
    by_key: dict[tuple, list[dict]] = {}
    for r in routes:
        if r["resolved"]:
            by_key.setdefault((r["method"], norm(r["path"])), []).append(r)
    rows, seen = [], set()
    for c in calls:
        if not c["resolved"]:
            key = ("UNRESOLVED", c["file"], c["line"])
        else:
            key = (c["method"], norm(c["path"]))
        if key in seen:
            continue
        seen.add(key)
        if not c["resolved"]:
            rows.append({**c, "status": "UNRESOLVED", "layer": None, "module": None})
            continue
        hit = by_key.get(key)
        if hit:
            rows.append({**c, "status": "SERVED", "layer": hit[0]["layer"], "module": hit[0]["module"]})
        elif "{}" in key[1] and _dynamic_candidates(by_key, key):
            cands = _dynamic_candidates(by_key, key)
            rows.append({**c, "status": "SERVED_DYNAMIC", "layer": cands[0][1][0]["layer"],
                         "module": cands[0][1][0]["module"],
                         "candidates": sorted(p for (_, p), _ in cands)[:6]})
        else:
            same_path = [m for (m, p) in by_key if p == key[1]]
            rows.append({**c, "status": "METHOD_MISMATCH" if same_path else "NO_SERVER_ROUTE",
                         "layer": None, "module": None})
    return {"routes": routes, "ui_calls": rows}


def summarize(matrix: dict) -> dict:
    routes = [r for r in matrix["routes"] if r["resolved"]]
    legacy = {(r["method"], norm(r["path"])) for r in routes if r["layer"] == "legacy" and r["path"].startswith("/api")}
    pg = {(r["method"], norm(r["path"])) for r in routes if r["layer"] == "pg-stage"}
    rows = matrix["ui_calls"]
    served = [r for r in rows if r["status"] in ("SERVED", "SERVED_DYNAMIC")]
    used_legacy = {(r["method"], norm(r["path"])) for r in served if r["layer"] == "legacy"}
    return {
        "server_routes_total": len(matrix["routes"]),
        "unresolved_server_routes": sum(1 for r in matrix["routes"] if not r["resolved"]),
        "legacy_api_routes": len(legacy), "pg_stage_routes": len(pg),
        "ui_distinct_calls": len(rows),
        "ui_served_by_legacy": sum(1 for r in served if r["layer"] == "legacy"),
        "ui_served_by_pg_stage": sum(1 for r in served if r["layer"] == "pg-stage"),
        "ui_served_dynamic_segment": sum(1 for r in rows if r["status"] == "SERVED_DYNAMIC"),
        "ui_no_server_route": sum(1 for r in rows if r["status"] == "NO_SERVER_ROUTE"),
        "ui_method_mismatch": sum(1 for r in rows if r["status"] == "METHOD_MISMATCH"),
        "ui_unresolved": sum(1 for r in rows if r["status"] == "UNRESOLVED"),
        "legacy_routes_not_called_by_ui": len(legacy - used_legacy),
    }


PGT = "/api/pg-stage/cinema-trade"
# Slice 1 of the server-side compatibility layer (core trade chain). Judged from route names,
# registered methods and the SQL guard columns ONLY; request/response shapes and business
# semantics are NOT yet compared (that needs both stacks running). Every referenced route is
# verified to exist by the tests, so this table cannot silently rot.
#   ADAPT = same business step exists in PG, request/response must be translated
#   READ  = list/read available through the generic PG listing route
#   GAP   = no PG counterpart for this step (or the PG process is different): decision needed
CORE_MAPPING = (
    ("GET", "/api/customers", "GET", PGT + "/{kind}", "READ", "kind=partners"),
    ("POST", "/api/customers", "POST", PGT + "/partners", "ADAPT", "partner upsert (version column)"),
    ("PUT", "/api/customers/{customer_id}", "POST", PGT + "/partners", "ADAPT", "same upsert, optimistic version"),
    ("GET", "/api/quotes", "GET", PGT + "/{kind}", "READ", "kind=quotes (+quote-items)"),
    ("GET", "/api/quotes/{quote_id}", "GET", PGT + "/{kind}", "READ", "no get-by-id route: filter the list or add one"),
    ("POST", "/api/quotes", "POST", PGT + "/quotes", "ADAPT", "line items, VAT mode"),
    ("PUT", "/api/quotes/{quote_id}", "PUT", PGT + "/quotes/{quote_id}", "ADAPT", "content guard triggers apply"),
    ("POST", "/api/quotes/{quote_id}/status", "POST", PGT + "/quotes/{quote_id}/transition", "ADAPT",
     "transition table cinema_pg_transitions (22 rows) decides which moves are legal"),
    ("GET", "/api/orders", "GET", PGT + "/{kind}", "READ", "kind=orders (+order-items)"),
    ("GET", "/api/orders/{order_id}", "GET", PGT + "/{kind}", "READ", "no get-by-id route"),
    ("POST", "/api/orders/from-quote", "POST", PGT + "/orders", "ADAPT", "quote must be in an approvable state"),
    ("PUT", "/api/orders/{order_id}", None, None, "GAP", "PG order columns are guarded; edit semantics undefined"),
    ("POST", "/api/orders/{order_id}/acknowledge", None, None, "GAP", "no acknowledge step in PG"),
    ("POST", "/api/orders/{order_id}/status", None, None, "GAP",
     "PG order status is driven by deliveries, not set directly"),
    ("POST", "/api/invoices/from-order", None, None, "GAP",
     "PG chain is order -> delivery -> confirm -> statement -> confirm -> invoice; legacy jumps straight to invoice"),
    ("POST", "/api/automation/statements/from-order", "POST", PGT + "/deliveries/{delivery_id}/statements",
     "GAP", "PG statements are built from a confirmed delivery, not from an order"),
    ("GET", "/api/invoices", "GET", PGT + "/{kind}", "READ", "kind=invoices"),
    ("GET", "/api/invoices/{invoice_id}", "GET", PGT + "/{kind}", "READ", "no get-by-id route"),
    ("GET", "/api/invoices/{invoice_id}/payments", "GET", PGT + "/{kind}", "READ", "kind=payments (+payment-reversals)"),
    ("POST", "/api/invoices/{invoice_id}/payments", "POST", PGT + "/invoices/{invoice_id}/payments", "ADAPT",
     "invoice must be confirmed first"),
    ("POST", "/api/invoices/{invoice_id}/payments/{payment_id}/reverse", "POST",
     PGT + "/payments/{payment_id}/reverse", "ADAPT", "path loses the invoice id"),
    ("GET", "/api/invoices/{invoice_id}/adjustments", None, None, "GAP", "complex settlement has no PG tables"),
    ("POST", "/api/invoices/{invoice_id}/adjustments", None, None, "GAP", "complex settlement has no PG tables"),
    ("POST", "/api/invoices/{invoice_id}/adjustments/{adjustment_id}/decision", None, None, "GAP",
     "complex settlement has no PG tables"),
)


def mapping_problems(routes: list[dict]) -> list[str]:
    """Names of CORE_MAPPING entries whose legacy or PG route is not actually registered."""
    have = {(r["method"], norm(r["path"])) for r in routes if r["resolved"]}
    bad = []
    for lm, lp, pm, pp, kind, _ in CORE_MAPPING:
        if (lm, norm(lp)) not in have:
            bad.append(f"legacy missing: {lm} {lp}")
        if pp is not None and (pm, norm(pp)) not in have:
            bad.append(f"pg missing: {pm} {pp}")
        if (pp is None) != (kind == "GAP" and pp is None):
            bad.append(f"inconsistent: {lm} {lp}")
    return bad


def render_markdown(matrix: dict) -> str:
    summary, rows = summarize(matrix), matrix["ui_calls"]
    out = ["# V22.3 P0-2 route parity (generated by scripts/ci_cinema_pg_route_matrix_v223.py)", "",
           "Source-only analysis (AST of `app/*.py`, scan of `app/static/*.js`); nothing was started "
           "and no database was opened. Semantics are NOT compared here.", "",
           "| measure | value |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in summary.items()]
    out += ["", "## UI calls (V22.2) and the route that serves them", "",
            "| method | path | status | module | UI file:line |", "|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (str(r.get("module")), r["path"], r["method"])):
        out.append(f"| {r['method']} | `{r['path']}` | {r['status']} | {r.get('module') or '-'} | {r['file']}:{r['line']} |")
    out += ["", "## Core trade chain: legacy step -> PostgreSQL stage step", "",
            "| legacy | PG stage | class | note |", "|---|---|---|---|"]
    for lm, lp, pm, pp, kind, note in CORE_MAPPING:
        out.append(f"| {lm} `{lp}` | {(pm + ' `' + pp + '`') if pp else '-'} | {kind} | {note} |")
    return "\n".join(out) + "\n"


def main(argv: list[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("--")]
    root = Path(args[0]).resolve() if args else Path(__file__).resolve().parents[1]
    matrix = build_matrix(extract_routes(root / "app"), extract_ui_calls(root / "app" / "static"))
    if "--markdown" in argv:
        print(render_markdown(matrix), end="")
        return 0
    print(json.dumps({"summary": summarize(matrix), **matrix}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
