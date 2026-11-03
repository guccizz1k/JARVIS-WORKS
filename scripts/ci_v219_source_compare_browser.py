"""V21.9 REAL FastAPI + Chromium source-side review, matching and mismatch reattach.

Entirely synthetic data, isolated temporary SQLite; no customer/AI-Hub bytes.
"""
from __future__ import annotations
import json
import os
import subprocess
import tempfile
from pathlib import Path
from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import ROOT
from scripts.ci_v213_real_auth_ui_browser import isolated_server,sign_in,navigate_real
from scripts.ci_v217_ocr_browser import sample
from tests.test_evidence_v64 import xlsx

OUT=ROOT/"artifacts/v219-source-compare"


def dashboard(page):
    return page.evaluate("""async()=> {
      const r=await fetch('/api/evidence/dashboard');
      if(!r.ok)throw Error('Dashboard unavailable');
      return await r.json();
    }""")


def upload(page,filename,raw,mime):
    form=page.locator("#evidence-v64-file")
    form.wait_for(state="visible")
    form.locator('input[type=file]').set_input_files({
      "name":filename,"mimeType":mime,"buffer":raw
    })
    form.locator('button[type=submit]').click()
    page.locator("#evidence-v64-confirm").wait_for(state="visible",timeout=30000)


def run():
    assert os.environ.get("JW_ENV")=="review"
    OUT.mkdir(parents=True,exist_ok=True)
    report={"photo_in_place":0,"pdf_excel_source_button":0,"reopen_denied":0,
        "tampered_local_files_denied":0,"genuine_reattach_accepted":0,
        "human_approval":0,"javascript_errors":0,"http_5xx":0}
    with tempfile.TemporaryDirectory(prefix="jw-v219-real-browser-") as tmp:
        proc,log,url=isolated_server(tmp)
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
                try:
                    for size in (1280,1440):
                        ctx=browser.new_context(viewport={"width":size,"height":900})
                        page=ctx.new_page();errors=[];server=[]
                        page.on("pageerror",lambda err:errors.append(str(err)))
                        page.on("response",lambda r:server.append((r.status,r.url)) if r.status>=500 else None)
                        page.goto(url+"/",wait_until="domcontentloaded")
                        sign_in(page,"demo@hanbit.example")
                        navigate_real(page,"imports")
                        source=sample(1300,700,size)
                        upload(page,f"synthetic-source-{size}.jpg",source,"image/jpeg")
                        picture=page.locator(".jw219-source .jw219-original")
                        picture.wait_for(state="visible")
                        assert picture.evaluate("(img)=>img.complete && img.naturalWidth>0")
                        assert page.locator("#evidence-v64-confirm").is_visible()
                        assert dashboard(page)["total_confirmed"]==0
                        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
                        if size==1440:
                            page.screenshot(path=str(OUT/"source-next-to-recognized-fields.png"),animations="disabled")
                        report["photo_in_place"]+=1
                        # Reading a stored queue entry never inherits a different local file.
                        page.locator('[data-action="evidence-v64-open"]').first.click()
                        reattach=page.locator("#evidence-v219-reattach")
                        reattach.wait_for(state="visible")
                        assert page.locator("#evidence-v64-confirm").count()==0
                        assert page.locator(".jw219-original").count()==0
                        assert dashboard(page)["total_confirmed"]==0
                        report["reopen_denied"]+=1
                        wrong=sample(1300,700,size+111)
                        reattach.set_input_files({
                          "name":f"synthetic-source-{size}.jpg",
                          "mimeType":"image/jpeg","buffer":wrong
                        })
                        page.locator("#toast.error.visible").wait_for(timeout=10000)
                        assert page.locator("#evidence-v64-confirm").count()==0
                        assert dashboard(page)["total_confirmed"]==0
                        report["tampered_local_files_denied"]+=1
                        reattach.set_input_files({
                          "name":f"synthetic-source-{size}.jpg",
                          "mimeType":"image/jpeg","buffer":source
                        })
                        page.locator("#evidence-v64-confirm").wait_for(state="visible",timeout=10000)
                        assert page.locator(".jw219-original").evaluate("(img)=>img.complete&&img.naturalWidth>0")
                        report["genuine_reattach_accepted"]+=1
                        assert dashboard(page)["total_confirmed"]==0
                        form=page.locator("#evidence-v64-confirm")
                        form.locator('[name=document_kind]').select_option("receipt")
                        form.locator('[name=record_type]').select_option("expense")
                        form.locator('[name=counterparty]').fill("가상기업")
                        form.locator('[name=document_date]').fill("2026-11-03")
                        form.locator('[name=gross_amount]').fill("11000")
                        form.locator('[name=reference_number]').fill("V219-"+str(size))
                        form.locator('[name=original_checked]').check()
                        form.locator('button[type=submit]').click()
                        form.wait_for(state="detached",timeout=15000)
                        assert dashboard(page)["total_confirmed"]==report["human_approval"]+1
                        report["human_approval"]+=1
                        assert page.locator(".jw219-original").count()==0
                        assert not errors,(size,errors)
                        assert not server,(size,server)
                        ctx.close()
                    # XLSX stays local, browser displays a source-open control,
                    # never guesses tabular cell coordinates from file bytes.
                    ctx=browser.new_context(viewport={"width":1440,"height":900})
                    page=ctx.new_page();page.goto(url+"/",wait_until="domcontentloaded")
                    sign_in(page,"demo@hanbit.example")
                    navigate_real(page,"imports")
                    upload(page,"synthetic-source-v219.xlsx",xlsx(reference="V219-XLSX"),
                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
                    assert page.locator(".jw219-original").count()==0
                    assert page.locator('[data-action="open-evidence-source"]').is_visible()
                    assert page.locator("#evidence-v64-confirm").is_visible()
                    assert dashboard(page)["total_confirmed"]==2
                    report["pdf_excel_source_button"]+=1
                    ctx.close()
                finally:browser.close()
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill()
            log.close()
    assert report["photo_in_place"]==2
    assert report["reopen_denied"]==2
    assert report["tampered_local_files_denied"]==2
    assert report["genuine_reattach_accepted"]==2
    assert report["human_approval"]==2
    (OUT/"acceptance.json").write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print("PASS_V219_REAL_SOURCE_VS_OCR_AND_SHA_REATTACH_BROWSER",report)


if __name__=="__main__":
    run()
