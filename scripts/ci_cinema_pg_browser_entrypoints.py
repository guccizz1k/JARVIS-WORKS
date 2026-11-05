"""Real Chromium entrypoint regression: modern CINEMA root and retained legacy UI.

The live root route / serves CINEMA, while original legacy authenticated UI is
served at /_legacy-ui. Reuse original historical V21.4–V21.9 browser tests
unchanged by directing ONLY their root navigation to the legacy route.

All services use the original isolated FastAPI+SQLite synthetic demo runner;
no Supabase, persistent DB, production secrets or real documents.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright

from scripts.ci_v202_bento_browser import ROOT
from scripts.ci_v213_real_auth_ui_browser import isolated_server as start_isolated


OUT = ROOT / "artifacts" / "cinema-pg-browser"


class _LegacyRootUrl(str):
    """Preserve /api/* paths while routing ONLY historical page loads."""

    def __add__(self, suffix):
        if suffix == "/":
            return str(self) + "/_legacy-ui"
        return str(self) + suffix


def legacy_server(directory):
    proc, log, url = start_isolated(directory)
    return proc, log, _LegacyRootUrl(url)


def smoke_cinema_root():
    """Verify actual CINEMA login DOM rather than historical login selectors."""
    from playwright.sync_api import Error

    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="jw-cinema-main-browser-") as tmp:
        proc, log, origin = start_isolated(tmp)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                try:
                    context = browser.new_context(
                        viewport={"width": 1440, "height": 900},
                        device_scale_factor=1,
                        reduced_motion="reduce",
                    )
                    page = context.new_page()
                    page_errors: list[str] = []
                    responses: list[tuple[int, str]] = []
                    page.on("pageerror", lambda exc: page_errors.append(str(exc)))
                    page.on("response", lambda resp: responses.append((resp.status, resp.url))
                            if resp.status >= 500 else None)
                    response = page.goto(origin + "/", wait_until="domcontentloaded")
                    assert response is not None and response.status == 200
                    # app.main security middleware deliberately strips the
                    # internal rendering marker before sending public HTTP.
                    assert "x-jw-cinema-main" not in response.headers
                    csp = response.headers.get("content-security-policy", "")
                    assert "sha256-" in csp and "frame-ancestors 'none'" in csp
                    page.locator("#login").wait_for(state="visible", timeout=18000)
                    assert page.locator("#gl").count() == 1
                    assert page.locator("#login-view.jw211-login").count() == 0
                    assert page.locator("#app").count() == 1
                    assert page.title() == "JARVIS WORKS"
                    assert page.evaluate("document.documentElement.getAttribute('data-theme')") == "dark"
                    assert page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                    assert not page_errors, page_errors
                    assert not responses, responses
                    page.screenshot(path=str(OUT / "cinema-root-login-pc.png"),
                                    animations="disabled")
                    (OUT / "cinema-entrypoint.json").write_text(json.dumps({
                        "route": "/",
                        "actual_browser": "Chromium",
                        "viewport": [1440, 900],
                        "internal_cinema_header_not_exposed": True,
                        "csp_inline_hash": True,
                        "cinema_login_visible": True,
                        "legacy_login_at_root": False,
                        "js_errors": len(page_errors),
                        "http_5xx": len(responses),
                        "scope": "synthetic FastAPI/UI; NOT authenticated CINEMA server integration",
                    }, indent=2))
                    context.close()
                finally:
                    browser.close()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            log.close()
    print("PASS_CINEMA_REAL_PC_ROOT_LOGIN_DOM", flush=True)



def cinema_authenticated_browser():
    """Exercise CINEMA's ACTUAL browser login through FastAPI cookies and CSRF.

    This does not prove PostgreSQL auth: the server fixture uses synthetic
    isolated SQLite as in the existing browser acceptance suite.
    """
    OUT.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="jw-cinema-root-auth-") as tmp:
        proc, log, origin = start_isolated(tmp)
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
                try:
                    checked = []
                    for email in ("demo@hanbit.example", "demo@bada.example"):
                        ctx = browser.new_context(
                            viewport={"width": 1440, "height": 900},
                            reduced_motion="reduce",
                        )
                        page = ctx.new_page()
                        errors: list[str] = []
                        page.on("pageerror", lambda err: errors.append(str(err)))
                        page.goto(origin + "/", wait_until="domcontentloaded")
                        page.locator("#login .lcard .form input[type=email]").wait_for(
                            state="visible", timeout=20000
                        )
                        assert page.evaluate("""async () => (
                          await fetch('/api/me',{credentials:'same-origin',cache:'no-store'})
                        ).status""") == 401
                        # The original source defaults to the registration tab
                        # before a server session is established. CINEMA bridge
                        # must preserve a usable LOGIN tab, but deny local-only
                        # registration and rely on verified server credentials.
                        page.locator("#login .tabs2 button").first.click()
                        form = page.locator("#login .lcard form")
                        form.locator("input[type=email]").fill(email)
                        form.locator("input[type=password]").fill("wrong-pass")
                        form.locator("button[type=submit]").click()
                        page.locator("#login .lerr").filter(
                            has_text="이메일 또는 비밀번호"
                        ).wait_for(state="visible", timeout=10000)
                        assert not page.locator("#app.on").count()
                        form.locator("input[type=password]").fill("Demo!2026secure")
                        form.locator("button[type=submit]").click()
                        page.locator("#app.on").wait_for(state="visible", timeout=25000)
                        user = page.evaluate("""async () => {
                          const r=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});
                          return {status:r.status,me:r.ok?await r.json():null};
                        }""")
                        assert user["status"] == 200 and user["me"]["email"] == email, user
                        assert user["me"]["org_id"]
                        assert not page.locator("#login").is_visible()
                        assert not errors, errors
                        page.reload(wait_until="domcontentloaded")
                        page.locator("#app.on").wait_for(state="visible", timeout=25000)
                        restored = page.evaluate("""async () => {
                          const r=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});
                          return r.ok?(await r.json()).org_id:null;
                        }""")
                        assert restored == user["me"]["org_id"]
                        assert not errors, errors
                        checked.append({"email": email, "org_id": restored,
                                        "server_login": True, "wrong_password_denied": True,
                                        "session_restored_after_reload": True})
                        ctx.close()
                    assert len({u["org_id"] for u in checked}) == 2, checked
                    (OUT / "cinema-authenticated-browser.json").write_text(
                        json.dumps({"scope": "isolated synthetic SQLite only; not PostgreSQL",
                                    "companies": len(checked),
                                    "login_and_reload": checked,
                                    "actual_chromium": True},
                                   indent=2, ensure_ascii=False)
                    )
                finally:
                    browser.close()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            log.close()
    print("PASS_CINEMA_ROOT_REAL_FASTAPI_AUTH_TWO_COMPANIES", flush=True)

def legacy_regression():
    """Run all proven original browser scripts, without mutating their files."""
    from scripts import (
        ci_v214_desktop_dark_browser as v214,
        ci_v216_browser_edges as v216,
        ci_v217_ocr_browser as v217,
        ci_v218_unsupported_ui_browser as v218,
        ci_v219_source_compare_browser as v219,
    )
    for mod in (v214, v216, v217, v218, v219):
        previous = mod.isolated_server
        try:
            mod.isolated_server = legacy_server
            mod.run()
        finally:
            mod.isolated_server = previous
    print("PASS_LEGACY_PC_AUTH_AND_SYNTHETIC_OCR_FIVE_SUITES", flush=True)


def main():
    if os.getenv("JW_ENV") != "review":
        raise RuntimeError("isolated review only")
    smoke_cinema_root()
    cinema_authenticated_browser()
    legacy_regression()


if __name__ == "__main__":
    main()
