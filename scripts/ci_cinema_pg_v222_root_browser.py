"""Real-Chromium acceptance for the candidate V22.2 root UI (JW_ROOT_UI=v222).

Drives the ACTUAL user entry path ``/`` (never ``/_legacy-ui``) through an isolated
FastAPI + temporary-SQLite server seeded with synthetic demo accounts:

  entry routing   `/` is the V22.2 page (default CSP, no CINEMA marker) when opted in,
                  and a control server proves the default `/` is still CINEMA
  login screen    Korean, dark-only (even with an OS light preference and a persisted
                  light setting), moving single-photon infinity, PC resolutions,
                  desktop-only notice below 1100 px
  login success   the real `jw214-auth-enter` entrance animation plays and ends
  workspace       V22.2 story present, business menu, every business route, left-rail
                  overlap (collapsed and open), document upload -> pending preview ->
                  manual approval (no silent registration, no accounting side effect)
  reduced-motion  no entrance animation, photon stays still, content usable
  health          JS page errors, HTTP 5xx, and MEASURED performance numbers
  recording       one continuous real-browser video -> H.264 MP4 -> decode-verified

Scope and honesty: this is synthetic SQLite, NOT PostgreSQL, and NOT Gate 2/3/4.
Every check is recorded PASS/FAIL individually with its measured value; a check that
did not run is absent, never PASS. Performance budgets below are PROVISIONAL and
uncalibrated (no baseline existed): the first CI run's measurements establish one.
"""
from __future__ import annotations

import contextlib
import io
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "v222-root-browser"
SHOTS = OUT / "screenshots"
DESKTOPS = ((1366, 768), (1440, 900), (1920, 1080))
EMAIL = "demo@hanbit.example"
PASSWORD = "Demo!2026secure"
HANGUL = re.compile(r"[가-힣]")
BUSINESS_ROUTES = ("imports", "quotes", "orders", "invoices", "automation", "messenger")
RAIL_ROUTES = ("customers", "audit", "security")
ALL_ROUTES = BUSINESS_ROUTES + ("dashboard",) + RAIL_ROUTES


def _budget(name: str, default: float) -> float:
    return float(os.environ.get(name, default))


BUDGET = {  # PROVISIONAL, uncalibrated. Override per run with the JW_V222_BUDGET_* variables.
    "dom_content_loaded_ms": _budget("JW_V222_BUDGET_DCL_MS", 5000),
    "login_to_home_ms": _budget("JW_V222_BUDGET_LOGIN_MS", 12000),
    "route_switch_ms_max": _budget("JW_V222_BUDGET_ROUTE_MS", 8000),
    "frame_median_ms": _budget("JW_V222_BUDGET_FRAME_MS", 200),
    "longest_long_task_ms": _budget("JW_V222_BUDGET_LONGTASK_MS", 2500),
}


class Checker:
    """Collects every check; a failure never hides the ones after it."""

    def __init__(self):
        self.rows: list[dict] = []

    def check(self, name, ok, detail=""):
        ok = bool(ok)
        self.rows.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": str(detail)[:600]})
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else " :: " + str(detail)[:240]), flush=True)
        return ok

    @contextlib.contextmanager
    def section(self, name):
        try:
            yield
        except Exception as exc:  # a crashed section is a FAIL, never a silent skip
            self.check(name + ":completed", False,
                       f"{type(exc).__name__}: {exc} | {traceback.format_exc()[-360:]}")

    @property
    def failed(self):
        return [r for r in self.rows if r["result"] == "FAIL"]


# --------------------------------------------------------------------------- helpers
LONGTASK_INIT = """try{window.__jwLong=[];new PerformanceObserver(l=>{for(const e of l.getEntries())
window.__jwLong.push(Math.round(e.duration))}).observe({type:'longtask',buffered:true})}catch(e){}"""

ENTRY_OBSERVER = """() => {
  const shell=document.getElementById('app-shell');
  const e=window.__jwEntry={added:0,t0:null,t1:null,names:[]};
  new MutationObserver(()=>{
    const on=shell.classList.contains('jw214-entry-playing');
    if(on&&e.t0===null){e.added++;e.t0=performance.now()}
    if(!on&&e.t0!==null&&e.t1===null){e.t1=performance.now()}
  }).observe(shell,{attributes:true,attributeFilter:['class']});
  document.addEventListener('animationstart',ev=>e.names.push(ev.animationName),true);
}"""

PHOTON_JS = """(sel)=>{
  const c=document.querySelector(sel);
  if(!c||!c.width||!c.height)return null;
  const w=c.width,h=c.height,d=c.getContext('2d').getImageData(0,0,w,h).data;
  let sx=0,sy=0,n=0,ax=0,ay=0,aw=0;
  for(let i=0;i<d.length;i+=4){
    const a=d[i+3];if(a<16)continue;
    const p=i>>2,px=p%w,py=(p/w)|0;ax+=px*a;ay+=py*a;aw+=a;
    if(a>=200&&d[i]>=230&&d[i+1]>=230&&d[i+2]>=230){sx+=px;sy+=py;n++}
  }
  return {w,h,core:n,cx:n?sx/n:null,cy:n?sy/n:null,lit:aw>0,wx:aw?ax/aw:null,wy:aw?ay/aw:null};
}"""

OVERLAP_JS = """() => {
  const R=el=>{const r=el.getBoundingClientRect();return {x:r.left,y:r.top,r:r.right,b:r.bottom,w:r.width,h:r.height}};
  const inter=(a,b)=>Math.max(0,Math.min(a.r,b.r)-Math.max(a.x,b.x))*Math.max(0,Math.min(a.b,b.b)-Math.max(a.y,b.y));
  const vis=el=>{const s=getComputedStyle(el),r=el.getBoundingClientRect();
    return s.visibility!=='hidden'&&s.display!=='none'&&r.width>1&&r.height>1&&r.bottom>0&&r.top<innerHeight};
  const rail=document.querySelector('.jw210-rail');if(!rail)return null;
  const rr=R(rail),nav=document.querySelector('.jw210-business-nav');
  const sel='.jw210-business-nav .jw210-nav-btn,.jw210-brand,#main-content :is(button,a[href],input,select,textarea,summary,h1,h2,h3)';
  const hits=[...document.querySelectorAll(sel)].filter(vis).map(el=>({
    what:((el.className&&String(el.className))||el.tagName).slice(0,48)+'|'+(el.textContent||'').trim().slice(0,20),
    area:Math.round(inter(rr,R(el)))})).filter(x=>x.area>4);
  return {rail:rr,navBar:nav?R(nav):null,navBarOverlapArea:nav?Math.round(inter(rr,R(nav))):0,controlOverlaps:hits};
}"""

FRAMES_JS = """(ms)=>new Promise(res=>{const t=[];let last=performance.now();const end=last+ms;
  const f=n=>{t.push(n-last);last=n;if(n<end)requestAnimationFrame(f);else{t.sort((a,b)=>a-b);
  res({frames:t.length,median_ms:t[t.length>>1],p95_ms:t[Math.floor(t.length*.95)],max_ms:t[t.length-1]})}};
  requestAnimationFrame(f)})"""


def shot(page, name):
    SHOTS.mkdir(parents=True, exist_ok=True)
    path = SHOTS / name
    page.screenshot(path=str(path))
    return path


def api_get(page, url):
    return page.evaluate("""async(u)=>{const r=await fetch(u,{credentials:'same-origin',cache:'no-store'});
        return r.ok?await r.json():{__status:r.status}}""", url)


def api_status(page, url):
    return page.evaluate("async(u)=>(await fetch(u,{credentials:'same-origin',cache:'no-store'})).status", url)


def lum_max(rgb: str) -> int:
    return max(int(v) for v in re.findall(r"\d+", rgb)[:3])


def attach_monitors(page, bucket):
    page.on("pageerror", lambda e: bucket["js_errors"].append(str(e)))
    page.on("response", lambda r: bucket["http_5xx"].append((r.status, r.url)) if r.status >= 500 else None)


def wait_for_js(page, expression, arg=None, timeout=30000):
    """Poll through Playwright CDP evaluation, preserving strict CSP without unsafe-eval.

    Playwright wait_for_function injects JS via eval and fails on the production
    script-src 'self' CSP; page.evaluate works without relaxing that policy.
    """
    deadline = time.monotonic() + timeout / 1000.0
    last_error = None
    while time.monotonic() < deadline:
        try:
            if page.evaluate(expression, arg):
                return True
        except Exception as exc:
            if page.is_closed():
                raise
            last_error = exc
        page.wait_for_timeout(80)
    raise AssertionError(
        f"Expected browser condition was not satisfied within {timeout}ms"
        + (f"; last evaluation error: {last_error!s}" if last_error is not None else "")
    )


def photon_track(page, selector, samples=5, gap_ms=420):
    wait_for_js(page, "(s)=>{const c=document.querySelector(s);return !!c&&c.width>0&&c.height>0}",
                           arg=selector, timeout=20000)
    points = []
    for _ in range(samples):
        points.append(page.evaluate(PHOTON_JS, selector))
        page.wait_for_timeout(gap_ms)
    return points


def photon_summary(points):
    lit = [p for p in points if p and p["lit"]]
    xy = [((p["cx"], p["cy"]) if p["core"] > 0 else (p["wx"], p["wy"])) for p in lit]
    path = sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in zip(xy, xy[1:]))
    return {"samples": len(points), "lit_samples": len(lit), "path_px": round(path, 1),
            "positions": [(round(x, 1), round(y, 1)) for x, y in xy]}


def check_photon(c, page, selector, tag, reduced):
    summary = photon_summary(photon_track(page, selector))
    if reduced:
        c.check(f"{tag}:photon_static_when_reduced_motion",
                summary["lit_samples"] >= 1 and summary["path_px"] <= 1.5, summary)
    else:
        c.check(f"{tag}:photon_moves", summary["lit_samples"] >= 4 and summary["path_px"] >= 12, summary)
    return summary


def open_route(page, route):
    if route == "dashboard":
        button = page.locator(".jw210-brand")
    elif route in RAIL_ROUTES:
        page.locator(".jw210-rail").hover()
        page.wait_for_timeout(300)
        button = page.locator(f'.jw210-rail-panel [data-jw210-page="{route}"]')
    else:
        button = page.locator(f'.jw210-business-nav [data-jw210-page="{route}"]')
    started = time.perf_counter()
    button.click(timeout=15000)
    wait_for_js(page, "(r)=>typeof state!=='undefined'&&state.page===r", arg=route, timeout=25000)
    page.locator("#main-content").wait_for(state="visible", timeout=10000)
    elapsed = (time.perf_counter() - started) * 1000
    size = page.viewport_size
    page.mouse.move(size["width"] // 2, size["height"] // 2)  # leave the rail so it collapses
    page.wait_for_timeout(260)
    return elapsed


# --------------------------------------------------------------------------- sections
def entry_path_checks(c, v222_url, default_url):
    def get(url):
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read().decode("utf-8")

    status, headers, body = get(v222_url + "/")
    csp = headers.get("content-security-policy", "")
    c.check("entry:root_is_v222_page", status == 200 and "cinematic_v222.css" in body and "cinemaBoot" not in body)
    c.check("entry:root_has_default_csp", "script-src 'self';" in csp and "sha256-" not in csp, csp)
    c.check("entry:cinema_marker_not_exposed", "x-jw-cinema-main" not in headers)
    c.check("entry:frame_and_cache_headers",
            headers.get("x-frame-options") == "DENY" and headers.get("cache-control") == "no-store", headers)
    legacy_status, _, legacy_body = get(v222_url + "/_legacy-ui")
    c.check("entry:legacy_route_unchanged_same_document", legacy_status == 200 and legacy_body == body)
    d_status, d_headers, d_body = get(default_url + "/")
    c.check("entry:default_root_still_cinema",
            d_status == 200 and 'canvas id="gl"' in d_body
            and "sha256-" in d_headers.get("content-security-policy", "") and "cinematic_v222" not in d_body)


def login_screen_checks(c, page, tag, reduced=False, mobile_notice=False):
    if mobile_notice:  # narrow PC window: the approved desktop-only notice replaces the workspace
        page.locator(".jw214-desktop-notice").wait_for(state="visible", timeout=15000)
        c.check(f"{tag}:desktop_only_notice_ko", "PC 전용" in page.locator(".jw214-desktop-notice").inner_text())
        c.check(f"{tag}:login_hidden_below_pc_width",
                page.evaluate("getComputedStyle(document.querySelector('#login-view')).visibility") == "hidden")
        return
    page.locator("#login-view.jw211-login").wait_for(state="visible", timeout=20000)
    selector = "#login-view .jw212-sculpt canvas"
    page.locator(selector).wait_for(state="attached", timeout=20000)
    c.check(f"{tag}:desktop_notice_hidden_at_pc_width", page.locator(".jw214-desktop-notice").is_hidden())
    c.check(f"{tag}:html_lang_ko", page.evaluate("document.documentElement.lang") == "ko")
    c.check(f"{tag}:login_text_is_korean", bool(HANGUL.search(page.locator("#login-view").inner_text())))
    c.check(f"{tag}:brand_subtitle_ko",
            page.locator(".jw211-login-brand small").inner_text() == "기업 업무 자동화 플랫폼")
    dark = page.evaluate("""()=>({bg:getComputedStyle(document.body).backgroundColor,
        theme:document.documentElement.dataset.jw206Theme,
        meta:document.querySelector('meta[name=color-scheme]')?.content,
        switches:document.querySelectorAll('.jw206-theme-switch,[data-jw206-theme-choice]').length})""")
    c.check(f"{tag}:dark_only", dark["theme"] == "dark" and dark["meta"] == "dark"
            and lum_max(dark["bg"]) <= 30 and dark["switches"] == 0, dark)
    c.check(f"{tag}:no_horizontal_overflow", page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"))
    c.check(f"{tag}:one_infinity_canvas", page.locator(selector).count() == 1)
    c.check(f"{tag}:legacy_svg_photon_paused",
            page.locator("#login-view .jw211-glass-photon").evaluate("x=>x.animationsPaused()"))
    return check_photon(c, page, selector, f"{tag}:login", reduced)


def login(c, page, tag, reduced=False, wrong_first=True):
    page.evaluate(ENTRY_OBSERVER)
    email, password = page.locator("#login-form [name=email]"), page.locator("#login-form [name=password]")
    if wrong_first:
        email.fill(EMAIL)
        password.fill("invalid-password")
        page.locator("#login-form button[type=submit]").click()
        page.locator("#toast.error.visible").wait_for(timeout=12000)
        c.check(f"{tag}:wrong_password_keeps_shell_closed", page.locator("#app-shell").is_hidden())
    email.fill(EMAIL)
    password.fill(PASSWORD)
    started = time.perf_counter()
    page.locator("#login-form button[type=submit]").click()
    page.locator(".jw210-home").wait_for(state="visible", timeout=30000)
    login_ms = (time.perf_counter() - started) * 1000
    c.check(f"{tag}:login_hides_login_view", page.locator("#login-view").is_hidden())
    if reduced:
        page.wait_for_timeout(1500)
    else:
        wait_for_js(page, "window.__jwEntry&&window.__jwEntry.t1!==null", timeout=15000)
    entry = page.evaluate("window.__jwEntry")
    if reduced:
        c.check(f"{tag}:entrance_animation_skipped_when_reduced",
                entry["added"] == 0 and "jw214-auth-enter" not in entry["names"], entry)
    else:
        duration = round(entry["t1"] - entry["t0"], 1)
        c.check(f"{tag}:entrance_animation_plays_and_ends",
                entry["added"] >= 1 and "jw214-auth-enter" in entry["names"] and 100 <= duration <= 8000,
                {**entry, "duration_ms": duration})
        entry["duration_ms"] = duration
    user = page.evaluate("({page:state.page,csrf:state.csrf.length,user:state.user})")
    c.check(f"{tag}:server_session_established",
            user["page"] == "dashboard" and user["csrf"] > 8 and user["user"]["email"] == EMAIL
            and bool(user["user"]["org_id"]), user["page"])
    c.check(f"{tag}:api_me_200", api_status(page, "/api/me") == 200)
    return login_ms, entry


def workspace_checks(c, page, tag, reduced=False):
    wait_for_js(page, """()=>{const s=document.querySelector('.jw210-infinity-stage');
        return s&&s.getBoundingClientRect().width>250&&!document.querySelector('#app-shell').classList.contains('jw214-entry-playing')}""",
                           timeout=15000)
    c.check(f"{tag}:is_v222_not_cinema",
            page.evaluate("typeof JW_CINEMATIC_V222==='object'&&typeof cinemaBoot==='undefined'")
            and page.locator("canvas#gl").count() == 0)
    story = page.locator(".jw222-scroll-story")
    story.wait_for(state="visible", timeout=15000)
    c.check(f"{tag}:v222_story_ko",
            page.locator(".jw222-scene h2").count() == 3
            and page.locator(".jw222-scene h2").first.inner_text().startswith("문서 한 장이"))
    c.check(f"{tag}:brand_subtitle_ko", page.locator(".jw210-brand-sub").inner_text() == "기업 업무 자동화 플랫폼")
    dark = page.evaluate("""()=>({bg:getComputedStyle(document.body).backgroundColor,
        theme:document.documentElement.dataset.jw206Theme,
        switches:document.querySelectorAll('.jw206-theme-switch,[data-jw206-theme-choice]').length})""")
    c.check(f"{tag}:workspace_dark_only", dark["theme"] == "dark" and lum_max(dark["bg"]) <= 30
            and dark["switches"] == 0, dark)
    c.check(f"{tag}:no_horizontal_overflow", page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"))
    labels = page.locator(".jw210-business-nav [data-jw210-page]")
    names = [labels.nth(i).get_attribute("data-jw210-page") for i in range(labels.count())]
    c.check(f"{tag}:business_menu_complete_and_ko",
            all(r in names for r in BUSINESS_ROUTES)
            and bool(HANGUL.search(page.locator(".jw210-business-nav").inner_text())), names)
    c.check(f"{tag}:workspace_infinity_canvas",
            page.locator(".jw210-infinity-stage .jw212-sculpt canvas").count() == 1)
    return check_photon(c, page, ".jw210-infinity-stage .jw212-sculpt canvas", f"{tag}:workspace", reduced)


def rail_overlap_checks(c, page, tag, label):
    page.mouse.move(page.viewport_size["width"] // 2, page.viewport_size["height"] // 2)
    page.wait_for_timeout(300)
    page.evaluate("window.scrollTo(0,0)")
    data = page.evaluate(OVERLAP_JS)
    c.check(f"{tag}:rail_present_{label}", data is not None)
    if data is None:
        return None
    c.check(f"{tag}:rail_does_not_cover_controls_{label}", not data["controlOverlaps"], data["controlOverlaps"][:4])
    return data


def rail_open_checks(c, page, tag):
    page.locator(".jw210-rail").hover()
    wait_for_js(page, "document.querySelector('.jw210-rail').getBoundingClientRect().width>150", timeout=5000)
    items = page.evaluate("""()=>[...document.querySelectorAll('.jw210-rail-item')].filter(e=>{
        const r=e.getBoundingClientRect(),s=getComputedStyle(e);return s.display!=='none'&&r.height>1})
        .map(e=>{const r=e.getBoundingClientRect();return {y:r.top,b:r.bottom,x:r.left,r:r.right,
        t:(e.textContent||'').trim()}})""")
    stacked = all(a["b"] <= b["y"] + 1 for a, b in zip(items, items[1:]))
    inside = all(i["x"] >= 0 and i["r"] <= page.viewport_size["width"] and i["y"] >= 0
                 and i["b"] <= page.viewport_size["height"] for i in items)
    c.check(f"{tag}:rail_open_items_do_not_overlap_each_other", len(items) >= 3 and stacked, items[:5])
    c.check(f"{tag}:rail_open_inside_viewport", inside)
    if tag.endswith("1440"):
        shot(page, "08-rail-open-1440.png")
    page.mouse.move(page.viewport_size["width"] // 2, page.viewport_size["height"] // 2)
    page.wait_for_timeout(350)
    c.check(f"{tag}:rail_collapses_again",
            page.evaluate("document.querySelector('.jw210-rail').getBoundingClientRect().width") < 120)


def route_sweep(c, page, tag, capture):
    timings = {}
    for route in ALL_ROUTES:
        timings[route] = round(open_route(page, route), 1)
        text = page.locator("#main-content").inner_text().strip()
        c.check(f"{tag}:route_{route}_renders_ko", bool(text) and bool(HANGUL.search(text)), text[:60])
        c.check(f"{tag}:route_{route}_no_error_toast_or_overflow",
                page.locator("#toast.error.visible").count() == 0
                and page.evaluate("document.documentElement.scrollWidth<=innerWidth+1"))
        rail_overlap_checks(c, page, tag, route)
        if capture:
            shot(page, f"05-route-{route}-1440.png")
    return timings


def document_flow(c, page, tag):
    from tests.test_evidence_v64 import xlsx  # generated in memory: never customer data
    open_route(page, "imports")
    page.locator("#evidence-v64-file").wait_for(state="visible", timeout=15000)
    records_before = len(api_get(page, "/api/evidence/records"))
    invoices_before = len(api_get(page, "/api/invoices"))
    source = xlsx(kind="영수증", company="가상 시연 기업", gross=11000,
                  reference="V222-ROOT-ACCEPT", date="2026-11-03")
    page.locator("#evidence-v64-file input[type=file]").set_input_files({
        "name": "가상_영수증_V222.xlsx",
        "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "buffer": source})
    page.locator("#evidence-v64-file button[type=submit]").click()
    page.locator("#evidence-v64-confirm").wait_for(state="visible", timeout=25000)
    preview = page.evaluate("({s:state.evidencePreview.status,r:state.evidencePreview.confirmation_required})")
    c.check(f"{tag}:doc_upload_creates_pending_preview", preview == {"s": "pending", "r": True}, preview)
    c.check(f"{tag}:doc_preview_registers_nothing",
            len(api_get(page, "/api/evidence/records")) == records_before)
    shot(page, "06-document-preview-1440.png")
    form = page.locator("#evidence-v64-confirm")
    form.locator('input[name="original_checked"]').check()
    form.locator('button[type=submit]').click()
    deadline, registered = time.monotonic() + 25, False
    while time.monotonic() < deadline and not registered:
        records = api_get(page, "/api/evidence/records")
        registered = isinstance(records, list) and len(records) == records_before + 1 and any(
            r.get("gross_amount") == 11000 and r.get("source_kind") == "receipt" for r in records)
        if not registered:
            page.wait_for_timeout(250)
    c.check(f"{tag}:doc_registered_only_after_manual_approval", registered)
    c.check(f"{tag}:doc_approval_creates_no_invoice", len(api_get(page, "/api/invoices")) == invoices_before)
    shot(page, "07-document-registered-1440.png")


def perf_checks(c, page, tag, login_ms, route_ms):
    nav = page.evaluate("""()=>{const n=performance.getEntriesByType('navigation')[0];
        const rs=performance.getEntriesByType('resource');
        return {dom_content_loaded_ms:Math.round(n.domContentLoadedEventEnd),load_ms:Math.round(n.loadEventEnd),
        resources:rs.length,transfer_kb:Math.round(rs.reduce((a,r)=>a+(r.transferSize||0),0)/1024)}}""")
    frames = page.evaluate(FRAMES_JS, 2000)
    longest = max(page.evaluate("window.__jwLong||[]") or [0])
    worst_route = max(route_ms.values()) if route_ms else 0
    measured = {**nav, "login_to_home_ms": round(login_ms), "frames": frames,
                "longest_long_task_ms": longest, "route_switch_ms_max": worst_route,
                "route_switch_ms": route_ms}
    c.check(f"{tag}:perf_dom_content_loaded", nav["dom_content_loaded_ms"] <= BUDGET["dom_content_loaded_ms"], nav)
    c.check(f"{tag}:perf_login_to_home", login_ms <= BUDGET["login_to_home_ms"], round(login_ms))
    c.check(f"{tag}:perf_route_switch_max", worst_route <= BUDGET["route_switch_ms_max"], route_ms)
    c.check(f"{tag}:perf_frame_median", frames["median_ms"] <= BUDGET["frame_median_ms"], frames)
    c.check(f"{tag}:perf_longest_long_task", longest <= BUDGET["longest_long_task_ms"], longest)
    return measured


def logout_check(c, page, tag):
    page.locator(".jw213-logout").click()
    page.locator("#login-view").wait_for(state="visible", timeout=15000)
    c.check(f"{tag}:logout_closes_shell_and_clears_password",
            page.locator("#app-shell").is_hidden() and page.locator('#login-form [name=password]').input_value() == "")
    c.check(f"{tag}:logout_revokes_server_session", api_status(page, "/api/me") == 401)


# --------------------------------------------------------------------------- MP4
def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def encode_and_verify_mp4(webm: Path, mp4: Path) -> dict:
    """Encode to H.264 and PROVE it plays: probe, full decode pass, frame content, motion."""
    from PIL import Image, ImageChops, ImageStat
    ffmpeg, ffprobe = shutil.which("ffmpeg"), shutil.which("ffprobe")
    if not ffmpeg or not ffprobe:
        raise RuntimeError("ffmpeg/ffprobe not available: MP4 NOT VERIFIED")
    enc = _run([ffmpeg, "-y", "-v", "error", "-i", str(webm), "-c:v", "libx264", "-preset", "veryfast",
                "-crf", "23", "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-an", str(mp4)])
    if enc.returncode != 0 or not mp4.is_file():
        raise RuntimeError("ffmpeg encode failed: " + enc.stderr[-300:])
    probe = json.loads(_run([ffprobe, "-v", "error", "-print_format", "json", "-show_streams",
                             "-show_format", str(mp4)]).stdout)
    video = next(s for s in probe["streams"] if s["codec_type"] == "video")
    duration = float(probe["format"]["duration"])
    decode = _run([ffmpeg, "-v", "error", "-i", str(mp4), "-f", "null", "-"])
    frames, stds = [], []
    for fraction in (0.05, 0.2, 0.4, 0.6, 0.8, 0.95):
        proc = subprocess.run([ffmpeg, "-v", "error", "-ss", f"{duration * fraction:.2f}", "-i", str(mp4),
                               "-frames:v", "1", "-f", "image2pipe", "-vcodec", "png", "-"], capture_output=True)
        image = Image.open(io.BytesIO(proc.stdout)).convert("RGB")
        frames.append(image)
        stds.append(round(sum(ImageStat.Stat(image.convert("L")).stddev), 2))
    changes = [bool(ImageChops.difference(a, b).getbbox()) for a, b in zip(frames, frames[1:])]
    result = {"codec": video["codec_name"], "pix_fmt": video["pix_fmt"], "width": video["width"],
              "height": video["height"], "duration_s": round(duration, 2), "bytes": mp4.stat().st_size,
              "full_decode_returncode": decode.returncode, "full_decode_stderr": decode.stderr.strip()[:200],
              "frame_stddev_at_5_20_40_60_80_95pct": stds, "consecutive_sample_frames_differ": changes}
    result["verified"] = (result["codec"] == "h264" and result["pix_fmt"] == "yuv420p" and duration >= 10
                          and decode.returncode == 0 and not decode.stderr.strip()
                          and all(s > 4 for s in stds) and sum(changes) >= 4)
    return result


# --------------------------------------------------------------------------- orchestration
@contextlib.contextmanager
def serve(root_ui):
    from scripts.ci_v213_real_auth_ui_browser import isolated_server
    previous = os.environ.get("JW_ROOT_UI")
    if root_ui is None:
        os.environ.pop("JW_ROOT_UI", None)
    else:
        os.environ["JW_ROOT_UI"] = root_ui
    tmp = tempfile.mkdtemp(prefix="jw-v222-root-")
    try:
        proc, log, url = isolated_server(tmp)
        try:
            yield url
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
            log.close()
    finally:
        if previous is None:
            os.environ.pop("JW_ROOT_UI", None)
        else:
            os.environ["JW_ROOT_UI"] = previous
        shutil.rmtree(tmp, ignore_errors=True)


def new_page(browser, bucket, **context_args):
    context = browser.new_context(**context_args)
    context.add_init_script(LONGTASK_INIT)
    page = context.new_page()
    attach_monitors(page, bucket)
    return context, page


def desktop_pass(c, browser, url, width, height, bucket, results):
    tag = f"pc{width}"
    context, page = new_page(browser, bucket, viewport={"width": width, "height": height},
                             device_scale_factor=1, color_scheme="light", reduced_motion="no-preference")
    try:
        with c.section(tag):
            page.goto(url + "/", wait_until="domcontentloaded")
            photon = login_screen_checks(c, page, tag)
            if width == 1440:
                shot(page, "01-login-1440.png")
                # a persisted light preference must not survive: the product is dark-only
                page.evaluate("localStorage.setItem('jw206-theme','light')")
                page.reload(wait_until="domcontentloaded")
                page.locator("#login-view.jw211-login").wait_for(state="visible", timeout=20000)
                c.check(f"{tag}:persisted_light_setting_is_overridden",
                        page.evaluate("document.documentElement.dataset.jw206Theme") == "dark"
                        and page.evaluate("localStorage.getItem('jw206-theme')") == "dark")
            login_ms, entry = login(c, page, tag)
            workspace_photon = workspace_checks(c, page, tag)
            if width == 1440:
                shot(page, "04-home-1440.png")
            rail_overlap_checks(c, page, tag, "home")
            rail_open_checks(c, page, tag)
            routes = route_sweep(c, page, tag, capture=(width == 1440))
            open_route(page, "dashboard")
            results["viewports"][tag] = {
                "login_photon": photon, "workspace_photon": workspace_photon, "entrance": entry,
                "rail": rail_overlap_checks(c, page, tag, "home_final"),
                "perf": perf_checks(c, page, tag, login_ms, routes)}
            logout_check(c, page, tag)
    finally:
        context.close()


def narrow_pass(c, browser, url, bucket):
    context, page = new_page(browser, bucket, viewport={"width": 768, "height": 900})
    try:
        with c.section("narrow768"):
            page.goto(url + "/", wait_until="domcontentloaded")
            login_screen_checks(c, page, "narrow768", mobile_notice=True)
    finally:
        context.close()


def reduced_pass(c, browser, url, bucket, results):
    tag = "reduced"
    context, page = new_page(browser, bucket, viewport={"width": 1440, "height": 900},
                             device_scale_factor=1, color_scheme="light", reduced_motion="reduce")
    try:
        with c.section(tag):
            page.goto(url + "/", wait_until="domcontentloaded")
            photon = login_screen_checks(c, page, tag, reduced=True)
            login(c, page, tag, reduced=True, wrong_first=False)
            workspace_photon = workspace_checks(c, page, tag, reduced=True)
            page.locator("#jw222-story-continuity").scroll_into_view_if_needed()
            c.check(f"{tag}:v222_objects_do_not_animate",
                    page.locator(".jw222-object").first.evaluate("x=>getComputedStyle(x).animationName") == "none")
            open_route(page, "automation")
            c.check(f"{tag}:content_usable_without_motion",
                    bool(HANGUL.search(page.locator("#main-content").inner_text())))
            shot(page, "09-reduced-motion-automation-1440.png")
            results["reduced_motion"] = {"login_photon": photon, "workspace_photon": workspace_photon}
    finally:
        context.close()


def recording_pass(c, browser, url, bucket, results):
    tag = "record"
    raw = OUT / "raw-video"
    shutil.rmtree(raw, ignore_errors=True)
    raw.mkdir(parents=True)
    context, page = new_page(browser, bucket, viewport={"width": 1440, "height": 900}, device_scale_factor=1,
                             color_scheme="light", reduced_motion="no-preference",
                             record_video_dir=str(raw), record_video_size={"width": 1440, "height": 900})
    video = page.video
    try:
        with c.section(tag):
            page.goto(url + "/", wait_until="domcontentloaded")
            page.locator("#login-view.jw211-login").wait_for(state="visible", timeout=20000)
            page.locator("#login-view .jw212-sculpt canvas").wait_for(state="attached", timeout=20000)
            page.mouse.move(915, 390, steps=14)
            page.wait_for_timeout(2600)
            page.evaluate(ENTRY_OBSERVER)
            page.locator("#login-form [name=email]").fill(EMAIL)
            page.locator("#login-form [name=password]").fill(PASSWORD)
            page.locator("#login-form button[type=submit]").click()
            page.locator(".jw210-home").wait_for(state="visible", timeout=30000)
            with contextlib.suppress(Exception):  # best effort: mid-animation still for the evidence set
                wait_for_js(page, "document.querySelector('#app-shell').classList.contains('jw214-entry-playing')",
                                       timeout=3000)
                shot(page, "03-login-success-entrance-1440.png")
            wait_for_js(page, "window.__jwEntry&&window.__jwEntry.t1!==null", timeout=15000)
            page.wait_for_timeout(2500)
            for scene in ("source", "continuity", "assurance"):
                for _ in range(3):
                    page.mouse.wheel(0, 440)
                    page.wait_for_timeout(380)
                page.locator("#jw222-story-" + scene).scroll_into_view_if_needed()
                page.wait_for_timeout(900)
            page.evaluate("window.scrollTo(0,0)")
            for route in ("quotes", "orders", "invoices", "automation", "messenger", "customers", "dashboard"):
                open_route(page, route)
                page.wait_for_timeout(1100)
            document_flow(c, page, tag)
            page.wait_for_timeout(1200)
            open_route(page, "dashboard")
            page.mouse.move(905, 380, steps=10)
            page.wait_for_timeout(1800)
            page.locator(".jw213-logout").click()
            page.locator("#login-view").wait_for(state="visible", timeout=15000)
            page.wait_for_timeout(1300)
    finally:
        context.close()
    webm = Path(video.path())
    c.check(f"{tag}:raw_video_written", webm.is_file() and webm.stat().st_size > 80_000, webm)
    with c.section(tag + ":mp4"):
        info = encode_and_verify_mp4(webm, OUT / "JARVIS_WORKS_V222_ROOT_REAL_BROWSER.mp4")
        c.check(f"{tag}:mp4_encoded_and_playback_verified", info["verified"], info)
        results["video"] = info


def main() -> int:
    if os.environ.get("JW_ENV") != "review":
        raise RuntimeError("isolated review only (JW_ENV=review)")
    from playwright.sync_api import sync_playwright
    OUT.mkdir(parents=True, exist_ok=True)
    SHOTS.mkdir(parents=True, exist_ok=True)
    c = Checker()
    bucket = {"js_errors": [], "http_5xx": []}
    results = {"scope": "isolated synthetic FastAPI + temporary SQLite; NOT PostgreSQL; NOT Gate 2/3/4",
               "root_ui_candidate": "JW_ROOT_UI=v222", "budgets_PROVISIONAL_UNCALIBRATED": BUDGET,
               "viewports": {}}
    with sync_playwright() as pw:
        # Use the GitHub-hosted Ubuntu runner's preinstalled Chrome for isolated
        # CI when requested. Default remains Playwright's Chromium everywhere else.
        launch_options = {"headless": True, "args": ["--no-sandbox"]}
        if os.environ.get("JW_USE_SYSTEM_CHROME") == "1":
            launch_options["channel"] = "chrome"
        browser = pw.chromium.launch(**launch_options)
        results["chromium"] = browser.version
        try:
            with c.section("entry"):
                with serve("v222") as v222_url, serve(None) as default_url:
                    entry_path_checks(c, v222_url, default_url)
            with serve("v222") as url:
                for width, height in DESKTOPS:
                    desktop_pass(c, browser, url, width, height, bucket, results)
                narrow_pass(c, browser, url, bucket)
                reduced_pass(c, browser, url, bucket, results)
                recording_pass(c, browser, url, bucket, results)
        finally:
            browser.close()
    c.check("health:no_js_page_errors", not bucket["js_errors"], bucket["js_errors"][:5])
    c.check("health:no_http_5xx", not bucket["http_5xx"], bucket["http_5xx"][:5])
    results.update(js_errors=bucket["js_errors"], http_5xx=bucket["http_5xx"], checks=c.rows,
                   totals={"pass": len(c.rows) - len(c.failed), "fail": len(c.failed)})
    (OUT / "acceptance.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    if c.failed:
        print("FAIL_V222_ROOT_REAL_BROWSER", json.dumps(results["totals"]), flush=True)
        for row in c.failed:
            print("  FAILED:", row["check"], "::", row["detail"][:200], flush=True)
        return 1
    print("PASS_V222_ROOT_REAL_BROWSER", json.dumps(results["totals"]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
