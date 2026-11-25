"""V22.0 authenticated Chromium UX and real API type-integrity test.

Runs only against temporary SQLite / synthetic XLSX data; no operations deployed.
"""
from __future__ import annotations
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path

from openpyxl import Workbook
from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import ROOT
from scripts.ci_v213_real_auth_ui_browser import isolated_server, sign_in, navigate_real

OUT = ROOT / "artifacts/v220-browser"


def worksheet(kind: str, width: int) -> bytes:
    wb = Workbook()
    for row in (
        ("문서종류", kind),
        ("거래처", "가상유통회사"),
        ("거래일", "2026-11-03"),
        ("총금액", 11000),
        ("문서번호", f"V220-{width}"),
    ):
        wb.active.append(row)
    io_file = io.BytesIO()
    wb.save(io_file)
    return io_file.getvalue()


def dashboard(page):
    return page.evaluate("""async()=> {
       const r=await fetch('/api/evidence/dashboard');
       if(!r.ok)throw Error('dashboard rejected');
       return await r.json();
    }""")


def run() -> None:
    assert os.environ.get("JW_ENV") == "review"
    OUT.mkdir(parents=True, exist_ok=True)
    results = []
    with tempfile.TemporaryDirectory(prefix="jw-v220-browser-") as tmp:
        server, log, base = isolated_server(tmp)
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
                try:
                    scenarios = (
                        (1280, 800, "매출전표", ["sales"], "sales", "expense"),
                        (1440, 900, "거래명세표", ["sales", "purchase"], "purchase", "expense"),
                        (1920, 1080, "영수증", ["sales", "purchase", "expense"], "expense", "inventory_snapshot"),
                    )
                    for width, height, label, expected, permitted, rejected in scenarios:
                        ctx = browser.new_context(viewport={"width":width,"height":height})
                        page = ctx.new_page()
                        errors, http_errors = [], []
                        page.on("pageerror", lambda e: errors.append(str(e)))
                        page.on("response", lambda r: http_errors.append(r.status) if r.status>=500 else None)
                        page.goto(base+"/",wait_until="domcontentloaded")
                        sign_in(page, "demo@hanbit.example")
                        navigate_real(page, "imports")
                        upload = page.locator("#evidence-v64-file")
                        upload.wait_for(state="visible")
                        upload.locator('input[type=file]').set_input_files({
                            "name":f"v220-document-{width}.xlsx",
                            "mimeType":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "buffer":worksheet(label,width)
                        })
                        upload.locator('button[type=submit]').click()
                        review = page.locator("#evidence-v64-confirm")
                        review.wait_for(state="visible",timeout=20000)
                        kind = review.locator("[name=document_kind]")
                        assert kind.locator("option").count()==1
                        source = page.evaluate("state.evidencePreview")
                        assert kind.input_value()==source["document"]["document_kind"]
                        record = review.locator("[name=record_type]")
                        options = record.locator("option").evaluate_all("(xs)=>xs.map(x=>x.value)")
                        assert options==expected,(label,options)
                        assert rejected not in options
                        # A malicious direct POST must fail, not just be hidden by the select.
                        attacked = page.evaluate("""async (rejected)=>{
                          const p=state.evidencePreview;
                          const r=await fetch('/api/evidence/preview/'+encodeURIComponent(p.id)+'/confirm',{
                            method:'POST',
                            headers:{'Content-Type':'application/json','X-CSRF-Token':state.csrf},
                            body:JSON.stringify({preview_digest:p.digest,
                              record_type:rejected,document_kind:p.document.document_kind,
                              counterparty:'가상유통회사',document_date:'2026-11-03',
                              gross_amount:11000,reference_number:'V220-ADVERSARIAL',
                              original_checked:true})});
                          return {status:r.status,body:await r.json()};
                        }""",rejected)
                        assert attacked["status"]==422,(label,attacked)
                        assert dashboard(page)["total_confirmed"]==len(results)
                        record.select_option(permitted)
                        review.locator("[name=counterparty]").fill("가상유통회사")
                        review.locator("[name=document_date]").fill("2026-11-03")
                        review.locator("[name=gross_amount]").fill("11000")
                        review.locator("[name=reference_number]").fill(f"V220-{width}")
                        review.locator("[name=original_checked]").check()
                        if width==1440:
                            page.screenshot(path=str(OUT/"type-locked-review.png"),animations="disabled")
                        review.locator("button[type=submit]").click()
                        review.wait_for(state="detached",timeout=20000)
                        assert dashboard(page)["total_confirmed"]==len(results)+1
                        assert not errors,(width,errors)
                        assert not http_errors,(width,http_errors)
                        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
                        results.append({"width":width,"original_kind":label,"allowed_record_types":options,
                                        "denied_direct_api":attacked["status"],"manual_approval":True})
                        ctx.close()
                finally:
                    browser.close()
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill()
            log.close()
    assert len(results)==3
    (OUT/"results.json").write_text(json.dumps(results,indent=2,ensure_ascii=False))
    print("PASS_V220_ACTUAL_CHROMIUM_TYPE_FILTER_DIRECT_API_DENIAL_AND_MANUAL_APPROVAL",results)


if __name__=="__main__":
    run()
