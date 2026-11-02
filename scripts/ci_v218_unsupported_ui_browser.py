"""V21.8 isolated real Chromium + FastAPI unsupported OCR safety flow."""
from __future__ import annotations
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path

from openpyxl import Workbook
from playwright.sync_api import sync_playwright
from scripts.ci_v213_real_auth_ui_browser import isolated_server, sign_in, navigate_real
from scripts.ci_v202_bento_browser import ROOT

OUTPUT=ROOT/"artifacts/v218-browser"


def unsupported_xlsx(unique_id):
    wb=Workbook()
    for record in (
        ("문서종류","정보보안동의서"),
        ("거래처","가상회사"),
        ("거래일","2026-11-03"),
        ("총금액",11000),
        ("문서번호","CONSENT-2026-11"),
        ("검증파일번호",str(unique_id)),
    ):
        wb.active.append(record)
    buffer=io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()


def run():
    assert os.environ.get("JW_ENV")=="review"
    OUTPUT.mkdir(parents=True,exist_ok=True)
    report={"real_browser_unsupported_previews":0,"approval_buttons":0,
            "server_direct_approval_denials":0,"surviving_pending":0,
            "js_errors":0,"server_5xx":0}
    with tempfile.TemporaryDirectory(prefix="jw-v218-unsupported-") as tmp:
        proc,log,url=isolated_server(tmp)
        try:
            with sync_playwright() as p:
                browser=p.chromium.launch(headless=True,args=["--no-sandbox"])
                try:
                    for width,height in ((1280,800),(1440,900),(1920,1080)):
                        ctx=browser.new_context(viewport={"width":width,"height":height})
                        page=ctx.new_page()
                        js=[];server=[]
                        page.on("pageerror",lambda e:js.append(str(e)))
                        page.on("response",lambda r:server.append((r.status,r.url)) if r.status>=500 else None)
                        page.goto(url+"/",wait_until="domcontentloaded")
                        sign_in(page,"demo@hanbit.example")
                        navigate_real(page,"imports")
                        upload=page.locator("#evidence-v64-file")
                        upload.wait_for(state="visible")
                        upload.locator('input[type=file]').set_input_files({
                            "name":f"unsupported-consent-{width}.xlsx",
                            "mimeType":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            "buffer":unsupported_xlsx(width)
                        })
                        upload.locator('button[type=submit]').click()
                        page.get_by_text("이 문서는 지원하는 증빙 유형으로 확인되지 않았습니다.",exact=False).wait_for()
                        assert page.locator("#evidence-v64-confirm").count()==0
                        assert page.locator('button:has-text("검토 완료 후 별도 증빙 기록 생성")').count()==0
                        preview=page.evaluate("state.evidencePreview")
                        assert preview["status"]=="pending"
                        assert preview["document"]["document_kind"] is None
                        assert preview["document"]["proposed_record_type"] is None
                        response=page.evaluate("""async () => {
                          const p=state.evidencePreview;
                          const body={preview_digest:p.digest,record_type:'expense',document_kind:'receipt',
                            counterparty:'가상회사',document_date:'2026-11-03',gross_amount:11000,
                            reference_number:'CONSENT-2026-11',original_checked:true};
                          const r=await fetch('/api/evidence/preview/'+encodeURIComponent(p.id)+'/confirm',{
                            method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':state.csrf},
                            body:JSON.stringify(body)});
                          return {status:r.status,payload:await r.json()};
                        }""")
                        assert response["status"]==409,response
                        summary=page.evaluate("""async()=> {
                          const r=await fetch('/api/evidence/dashboard');
                          return await r.json();
                        }""")
                        assert summary["total_confirmed"]==0,summary
                        assert summary["pending_review"]==report["surviving_pending"]+1,summary
                        assert not js,(width,js)
                        assert not server,(width,server)
                        assert page.evaluate("document.documentElement.scrollWidth<=innerWidth+1")
                        if width==1440:
                            page.screenshot(path=str(OUTPUT/"unsupported-document-blocked.png"),animations="disabled")
                        report["real_browser_unsupported_previews"]+=1
                        report["server_direct_approval_denials"]+=1
                        report["surviving_pending"]+=1
                        ctx.close()
                finally:browser.close()
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill()
            log.close()
    assert report["real_browser_unsupported_previews"]==3
    assert report["server_direct_approval_denials"]==3
    (OUTPUT/"acceptance.json").write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print("PASS_V218_REAL_UI_UNSUPPORTED_FINANCIAL_DOC_DENIED",report)


if __name__=="__main__":
    run()
