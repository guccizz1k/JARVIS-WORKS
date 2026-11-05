"""Root UI selector (JW_ROOT_UI) for the candidate V22.2 entry. No browser, no FastAPI needed.

Proves: the default response is still the protected CINEMA page (marker header and
bridges intact); only an explicit ``v222`` opt-in returns the V22.2 workspace page;
any other value fails closed to CINEMA; the V22.2 page is Korean, dark-declared,
same-origin only and free of inline script (so app.main's default CSP applies);
every asset it references exists. It does not run a browser: the real-Chromium
proof is scripts/ci_cinema_pg_v222_root_browser.py.
"""
import importlib.util
import re
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INDEX = ROOT / "app" / "static" / "index.html"


def load_entry():
    stub = types.ModuleType("fastapi.responses")

    class HTMLResponse:
        def __init__(self, content, headers=None):
            self.body, self.headers = content, headers or {}

    stub.HTMLResponse = HTMLResponse
    pkg = types.ModuleType("fastapi")
    saved = {k: sys.modules.get(k) for k in ("fastapi", "fastapi.responses")}
    sys.modules["fastapi"], sys.modules["fastapi.responses"] = pkg, stub
    try:
        spec = importlib.util.spec_from_file_location("cinema_entry_root_switch", ROOT / "app" / "cinema_entry_v1.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for k, v in saved.items():
            if v is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = v


ENTRY = load_entry()


@pytest.fixture
def mode(monkeypatch):
    def set_mode(value):
        if value is None:
            monkeypatch.delenv("JW_ROOT_UI", raising=False)
        else:
            monkeypatch.setenv("JW_ROOT_UI", value)
        return ENTRY.cinema_main_response()
    return set_mode


def test_default_is_the_protected_cinema_page(mode):
    page = mode(None)
    assert page.headers["X-JW-Cinema-Main"] == "1"
    assert "cinemaBoot();\n})();" in page.body
    for marker in ("CINEMA server boundary", "server-backed adapter v2", "PostgreSQL trade-ledger bridge v3"):
        assert page.body.count(marker) == 1, marker


@pytest.mark.parametrize("value", ["", " ", "cinema", "legacy", "1", "true", "v22", "v2220", "v222x", "v-222"])
def test_anything_but_an_explicit_v222_fails_closed_to_cinema(mode, value):
    page = mode(value)
    assert page.headers.get("X-JW-Cinema-Main") == "1", value
    assert ENTRY.root_ui_mode() == "cinema", value


@pytest.mark.parametrize("value", ["v222", "V222", "  v222  "])
def test_explicit_opt_in_serves_the_v222_workspace(mode, value):
    page = mode(value)
    assert ENTRY.root_ui_mode() == "v222"
    assert page.body == INDEX.read_text(encoding="utf-8")
    assert "X-JW-Cinema-Main" not in page.headers  # lets app.main attach its default CSP
    assert page.headers["Cache-Control"] == "no-store"
    assert "cinemaBoot" not in page.body


def test_v222_page_links_the_cinematic_assets(mode):
    body = mode("v222").body
    assert '<link rel="stylesheet" href="/static/cinematic_v222.css">' in body
    assert '<script src="/static/cinematic_v222.js" defer></script>' in body
    assert body.index("/static/premium_v214.js") < body.index("/static/cinematic_v222.js")


def test_v222_page_is_korean_and_declares_dark_only(mode):
    body = mode("v222").body
    assert '<html lang="ko">' in body
    assert '<meta name="color-scheme" content="dark">' in body
    assert 'id="login-view"' in body and 'id="login-form"' in body


def test_v222_page_is_csp_compatible(mode):
    body = mode("v222").body
    assert not re.search(r"<script(?![^>]*\bsrc=)", body), "inline script would violate script-src 'self'"
    assert not re.search(r"\son[a-z]+\s*=", body, re.I), "inline event handler"
    refs = re.findall(r'(?:src|href)="([^"]+)"', body)
    assert refs and all(r.startswith("/static/") for r in refs), [r for r in refs if not r.startswith("/static/")]


def test_every_asset_referenced_by_the_v222_page_exists(mode):
    refs = re.findall(r'(?:src|href)="(/static/[^"]+)"', mode("v222").body)
    missing = [r for r in refs if not (ROOT / "app" / r.lstrip("/")).is_file()]
    assert not missing, missing


def test_main_route_wiring_is_untouched():
    main = (ROOT / "app" / "main.py").read_text(encoding="utf-8")
    assert "@app.get('/')\ndef index():\n    return cinema_main_response()" in main
    assert "@app.get('/_legacy-ui')" in main
    assert "FileResponse(ROOT/'static'/'index.html'" in main
