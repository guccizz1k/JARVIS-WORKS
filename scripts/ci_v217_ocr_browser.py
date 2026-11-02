"""V21.7 Gate 4: real isolated FastAPI + Chromium photo-OCR user journey.

Synthetic images only, temporary SQLite only. No AI-Hub bytes or production.
"""
from __future__ import annotations
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright
from scripts.ci_v202_bento_browser import ROOT
from scripts.ci_v213_real_auth_ui_browser import isolated_server, sign_in, navigate_real

OUT = ROOT / "artifacts/v217-browser"
FONT = Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf")


def sample(width, height, unique_id):
    image=Image.new("RGB",(width,height),"white")
    draw=ImageDraw.Draw(image)
    font=ImageFont.truetype(str(FONT),64 if width>2500 else 34)
    for i,line in enumerate((
        "문서종류: 영수증",
        "거래처: 가상기업",
        "거래일: 2026-11-03",
        "총금액: 11000",
        "SYNTHETIC QA ONLY "+str(unique_id)
    )):
        draw.text((80,80+i*(130 if width>2500 else 68)),line,font=font,fill="black")
    out=io.BytesIO()
    image.save(out,format="JPEG",quality=91)
    return out.getvalue()


def summary(page):
    return page.evaluate("""async()=> {
      const r=await fetch('/api/evidence/dashboard');
      if(!r.ok)throw Error('evidence dashboard rejected '+r.status);
      return await r.json();
    }""")


def run():
    assert os.environ.get("JW_ENV")=="review"
    OUT.mkdir(parents=True,exist_ok=True)
    accepted=[]
    with tempfile.TemporaryDirectory(prefix="jw-v217-ui-") as root:
        process, log, url=isolated_server(root)
        try:
            with sync_playwright() as pw:
                browser=pw.chromium.launch(headless=True,args=["--no-sandbox"])
                try:
                    for width,height,photo_width,photo_height in (
                        (1280,800,1000,700),
                        (1440,900,4000,3400),
                        (1920,1080,1100,750)
                    ):
                        context=browser.new_context(viewport={"width":width,"height":height})
                        page=context.new_page()
                        page_errors=[]
                        responses=[]
                        page.on("pageerror",lambda x:page_errors.append(str(x)))
                        page.on("response",lambda x:responses.append((x.status,x.url)) if x.status>=500 else None)
                        page.goto(url+"/",wait_until="domcontentloaded")
                        sign_in(page,"demo@hanbit.example")
                        navigate_real(page,"imports")
                        assert summary(page)["total_confirmed"]==len(accepted)
                        form=page.locator("#evidence-v64-file")
                        form.wait_for(state="visible")
                        raw=sample(photo_width,photo_height,width)
                        assert len(raw)<5*1024*1024
                        form.locator('input[type=file]').set_input_files({
                          "name":f"synthetic-v217-{width}.jpg",
                          "mimeType":"image/jpeg",
                          "buffer":raw
                        })
                        form.locator('button[type=submit]').click()
                        review=page.locator("#evidence-v64-confirm")
                        review.wait_for(state="visible",timeout=30000)
                        parsed=page.evaluate("state.evidencePreview")
                        assert parsed["status"]=="pending",parsed
                        assert parsed["confirmation_required"] is True
                        assert parsed["original_file_stored"] is False
                        assert parsed["document"]["method"]=="ocr",parsed["document"]
                        assert parsed["document"]["quality"]["needs_manual_review"] is True
                        assert summary(page)["total_confirmed"]==len(accepted)
                        assert summary(page)["pending_review"]==1
                        assert not review.locator('[name=original_checked]').is_checked()
                        # Human confirmation cannot be bypassed by submitting an unchecked form.
                        review.locator('button[type=submit]').click()
                        assert review.is_visible()
                        assert summary(page)["total_confirmed"]==len(accepted)
                        review.locator('[name=document_kind]').select_option('receipt')
                        review.locator('[name=record_type]').select_option('expense')
                        review.locator('[name=counterparty]').fill('가상기업')
                        review.locator('[name=document_date]').fill('2026-11-03')
                        review.locator('[name=gross_amount]').fill('11000')
                        review.locator('[name=original_checked]').check()
                        if width==1440:
                            page.screenshot(path=str(OUT/"ocr-before-manual-review-1440.png"),animations="disabled")
                        review.locator('button[type=submit]').click()
                        review.wait_for(state="detached",timeout=15000)
                        accepted.append(width)
                        result=summary(page)
                        assert result["total_confirmed"]==len(accepted),result
                        assert result["pending_review"]==0,result
                        assert "공식 회계" in result["warning"]
                        assert not page_errors,(width,page_errors)
                        assert not responses,(width,responses)
                        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
                        if width==1440:
                            page.screenshot(path=str(OUT/"ocr-after-human-review-1440.png"),animations="disabled")
                        context.close()
                finally:
                    browser.close()
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill()
            log.close()
    result={"tested_viewports":len(accepted),"ocr_ui_uploads":len(accepted),
            "highres_real_upload":1,"manual_confirmations":len(accepted),
            "auto_confirmations":0,"js_errors":0,"http_5xx":0,
            "scope":"isolated synthetic FastAPI/Chromium only; NOT production OCR accuracy"}
    (OUT/"acceptance.json").write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print("PASS_V217_ACTUAL_OCR_UI_API_MANUAL_APPROVAL",result)


if __name__=="__main__":
    run()
