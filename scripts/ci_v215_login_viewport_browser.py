"""V21.5: enforce login submit visibility at minimum supported PC heights.

Runs against actual isolated FastAPI with Playwright; never changes persistent DB.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from playwright.sync_api import sync_playwright

from scripts.ci_v213_real_auth_ui_browser import isolated_server, sign_in
from scripts.ci_v202_bento_browser import ROOT

OUT = ROOT / "artifacts/v215-login"
VIEWPORTS = ((1366, 768), (1440, 900), (1280, 800), (1920, 1080))


def check_first_screen(page, width, height):
    info = page.evaluate("""() => {
      const btn = document.querySelector('#login-form button[type=submit]');
      const art = document.querySelector('.jw211-login-infinity');
      const form = document.getElementById('login-form');
      const card = document.querySelector('#login-view .login-card');
      const b = btn.getBoundingClientRect(), a=art.getBoundingClientRect();
      const c = card.getBoundingClientRect();
      const x=b.left+b.width/2, y=b.top+b.height/2;
      const target=document.elementFromPoint(x,y);
      return {w:innerWidth,h:innerHeight,buttonTop:b.top,buttonBottom:b.bottom,
        buttonLeft:b.left,buttonRight:b.right,artHeight:a.height,
        cardTop:c.top,formVisible:!!form&&getComputedStyle(form).display!=='none',
        submitClickable:target===btn||btn.contains(target),
        xOverflow:document.documentElement.scrollWidth>innerWidth+1,
        theme:document.documentElement.dataset.jw206Theme};
    }""")
    assert info["w"] == width and info["h"] == height, info
    assert info["theme"] == "dark", info
    assert info["formVisible"] and info["cardTop"] >= 0, info
    assert info["artHeight"] >= 150, info
    assert info["buttonTop"] >= 0 and info["buttonBottom"] <= height - 8, info
    assert info["buttonLeft"] >= 0 and info["buttonRight"] <= width, info
    assert info["submitClickable"] and not info["xOverflow"], info
    return info


def run():
    assert os.environ.get("JW_ENV") == "review", "review-only server required"
    OUT.mkdir(parents=True, exist_ok=True)
    summary = []
    import tempfile
    with tempfile.TemporaryDirectory(prefix="jw-v215-") as tmp:
        proc, logfile, base = isolated_server(tmp)
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
                try:
                    for width, height in VIEWPORTS:
                        ctx = browser.new_context(viewport={"width": width, "height": height})
                        page = ctx.new_page()
                        errors = []
                        page.on("pageerror", lambda err: errors.append(str(err)))
                        page.goto(base + "/", wait_until="domcontentloaded")
                        page.locator("#login-view.jw211-login").wait_for(state="visible")
                        page.locator("#login-form button[type=submit]").wait_for(state="visible")
                        info = check_first_screen(page, width, height)
                        page.screenshot(path=str(OUT / f"login-{width}x{height}.png"))
                        # Authentication must still reach the real app after compact layout.
                        sign_in(page, "demo@hanbit.example")
                        assert page.locator("#app-shell").is_visible()
                        assert not errors, errors
                        summary.append(info)
                        ctx.close()
                finally:
                    browser.close()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except Exception:
                proc.kill()
            logfile.close()
    (OUT / "measurements.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    print("PASS V21.5 login visible and actually clickable before scrolling", summary)


if __name__ == "__main__":
    run()
