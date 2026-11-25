"""V21.6 real FastAPI + Chromium boundary review at laptop browser content heights.

No production or remote services; only ephemeral demo accounts. Screenshots and
measurements are test evidence, not a production sign-off.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import ROOT
from scripts.ci_v213_real_auth_ui_browser import isolated_server, sign_in

OUT = ROOT / "artifacts/v216-browser"
WINDOWS = (
    (1366, 620), (1366, 670), (1366, 768),
    (1280, 660), (1440, 900), (1440, 940), (1440, 970),
    (1920, 920), (1920, 970), (2560, 860),
)


def inspect_login(page, width, height):
    data = page.evaluate("""() => {
      const btn=document.querySelector('#login-form button[type=submit]');
      const glass=document.querySelector('.jw211-login-infinity');
      const b=btn.getBoundingClientRect(),a=glass.getBoundingClientRect();
      const pick=document.elementFromPoint(b.left+b.width/2,b.top+b.height/2);
      return {w:innerWidth,h:innerHeight,bottom:b.bottom,top:b.top,
        buttonWidth:b.width,glassHeight:a.height,visible:!!pick &&
          (pick===btn || btn.contains(pick)),
        xOverflow:document.documentElement.scrollWidth>innerWidth+1,
        theme:document.documentElement.dataset.jw206Theme,
        mobileNotice:getComputedStyle(document.querySelector('.jw214-desktop-notice')).display
      };
    }""")
    assert data["w"] == width and data["h"] == height, data
    assert data["theme"] == "dark" and data["mobileNotice"] == "none", data
    assert data["glassHeight"] > 100 and data["buttonWidth"] > 100, data
    assert data["top"] >= 0 and data["bottom"] <= height - 8, data
    assert data["visible"] and not data["xOverflow"], data
    return data


def run():
    assert os.getenv("JW_ENV") == "review"
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="jw-v216-") as temp:
        proc, log, url = isolated_server(temp)
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True, args=["--no-sandbox"])
                try:
                    for width, height in WINDOWS:
                        context = browser.new_context(viewport={"width":width,"height":height})
                        page = context.new_page()
                        errors=[]
                        page.on("pageerror",lambda ex:errors.append(str(ex)))
                        page.goto(url + "/", wait_until="domcontentloaded")
                        page.locator("#login-view.jw211-login").wait_for(state="visible")
                        measurements = inspect_login(page, width, height)
                        if (width,height) in ((1366,620),(1440,970),(2560,860)):
                            page.screenshot(path=str(OUT/f"before-login-{width}x{height}.png"))
                        # MFA must remain reachable even when optional details expand.
                        details = page.locator("#login-form details.jw211-extra-auth")
                        details.locator("summary").click()
                        assert details.get_attribute("open") is not None
                        assert page.locator('#login-form input[name="otp"]').is_visible()
                        submit = page.locator("#login-form button[type=submit]")
                        submit.scroll_into_view_if_needed()
                        assert submit.is_visible()
                        details.locator("summary").click()
                        # Test the original real authentication, not a simulated view.
                        sign_in(page, "demo@hanbit.example")
                        assert page.locator("#app-shell").is_visible()
                        assert not errors, errors
                        results.append(measurements)
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
    (OUT/"metrics.json").write_text(json.dumps(results,ensure_ascii=False,indent=2))
    print("PASS V21.6 realistic desktop window heights MFA and real login",results)


if __name__ == "__main__":
    run()
