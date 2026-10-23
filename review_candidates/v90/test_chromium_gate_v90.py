"""Real Chromium DOM test with synthetic HTTP/WS; NOT server or PostgreSQL E2E.

Uses about:blank and set_content to avoid restricted localhost navigation.
Run explicitly: python -m pytest -q test_chromium_gate_v90.py
"""
from pathlib import Path
import re
import pytest
from playwright.sync_api import sync_playwright, expect

HTML=Path(__file__).with_name('messenger_stage_v90.html').read_text('utf-8')
MOCK=r"""
window.__qa={sends:[],ws:[]};
window.fetch=async(url,options={})=>{
 const ok=data=>new Response(JSON.stringify(data),{status:200,headers:{'content-type':'application/json'}});
 const p=String(url);
 if(p==='/api/pg-stage/v90/me')return ok({org_id:'A',csrf_token:'c'});
 if(p.includes('/companies?'))return ok([{org_id:'B',company_name:'인증 기업 B'},{org_id:'C',company_name:'기업 C'}]);
 if(p.endsWith('/chats'))return ok({connection_id:'chat-B'});
 if(p.includes('/edits?')||p.endsWith('/read'))return ok([]);
 if(p.includes('/messages?'))return ok([]);
 if(p.endsWith('/messages')){
   const data=JSON.parse(options.body);__qa.sends.push(data);
   await new Promise(resolve=>setTimeout(resolve,60));
   const sock=__qa.ws.at(-1);
   sock?.onmessage?.({data:JSON.stringify({type:'message',data:{message_id:'test-'+__qa.sends.length,message_cursor:__qa.sends.length,sender_org:'A',body:data.body,version:1}})});
   return ok({message_id:'test-1',message_cursor:1});
 }
 return ok([]);
};
window.WebSocket=class {
 static OPEN=1;
 constructor(url){this.url=url;this.readyState=1;__qa.ws.push(this);queueMicrotask(()=>this.onopen?.())}
 close(){this.readyState=3;this.onclose?.({code:1000})}
};
"""

@pytest.fixture
def browser_page():
 with sync_playwright() as p:
  b=p.chromium.launch(headless=True,executable_path='/usr/bin/chromium',args=['--no-sandbox'])
  try:
   page=b.new_page(viewport={'width':1280,'height':800})
   page.evaluate("() => {"+MOCK+"}")
   page.set_content(HTML)
   expect(page.locator('.company')).to_have_count(2)
   yield page
  finally:b.close()

def open_chat(page):
 page.locator('.company').first.click()
 expect(page.locator('#message')).to_be_enabled()
 expect(page.locator('#status')).to_have_text('실시간 연결')

def test_search_chat_send_and_crypto_uuid_on_insecure_context(browser_page):
 page=browser_page
 assert page.evaluate('isSecureContext') is False
 open_chat(page)
 page.locator('#message').fill('브라우저 전송 테스트')
 page.locator('#send').click()
 expect(page.locator('.bodytext')).to_have_text('브라우저 전송 테스트')
 key=page.evaluate('__qa.sends[0].request_id')
 assert re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}',key)

def test_enter_spam_has_one_request(browser_page):
 page=browser_page;open_chat(page)
 page.locator('#message').fill('하나만 전송')
 page.locator('#message').press('Enter')
 page.locator('#message').press('Enter')
 expect(page.locator('.bodytext')).to_have_count(1)
 assert page.evaluate('__qa.sends.length')==1

def test_company_change_prevents_old_ws_message_leak(browser_page):
 page=browser_page;open_chat(page)
 page.locator('.company').nth(1).click()
 expect(page.locator('#message')).to_be_enabled()
 page.evaluate("() => __qa.ws[0].onmessage?.({data:JSON.stringify({type:'message',data:{message_id:'leak',message_cursor:999,sender_org:'B',body:'민감 내용',version:1}})})")
 assert page.locator('.bodytext').count()==0

def test_chromium_page_has_no_desktop_overflow(browser_page):
 page=browser_page
 assert page.evaluate('document.documentElement.scrollWidth <= innerWidth')
 assert page.locator('#companies').bounding_box()['width']>250

def test_company_switch_clears_draft_before_other_company_can_send(browser_page):
    page=browser_page
    open_chat(page)
    page.locator('#message').fill('기업 B 전용 영업비밀')
    page.locator('.company').nth(1).click()
    expect(page.locator('#message')).to_be_enabled()
    assert page.locator('#message').input_value()=='' , 'Prior company draft leaks into next recipient'
    assert page.evaluate('__qa.sends.length')==0

def test_company_switch_removes_previous_attachment(browser_page):
    page=browser_page
    open_chat(page)
    page.locator('#fileInput').set_input_files({'name':'confidential.pdf','mimeType':'application/pdf','buffer':b'%PDF-1.7 test'})
    expect(page.locator('#fileInfo')).to_contain_text('confidential.pdf')
    page.locator('.company').nth(1).click()
    expect(page.locator('#message')).to_be_enabled()
    assert page.locator('#fileInfo').inner_text() == ''
    assert page.locator('#fileInput').evaluate('(el) => el.files.length') == 0
    assert page.evaluate('__qa.sends.length')==0


def test_company_switch_with_inflight_send_never_transfers_payload(browser_page):
    page=browser_page
    open_chat(page)
    page.locator('#message').fill('B only confidential payload')
    page.locator('#send').click()
    page.locator('.company').nth(1).click()
    expect(page.locator('#message')).to_be_enabled()
    assert page.locator('#message').input_value() == ''
    page.wait_for_timeout(180)
    assert page.locator('#message').input_value() == ''
    assert page.evaluate('__qa.sends.length') == 1
    assert page.evaluate('__qa.sends[0].body') == 'B only confidential payload'

def test_burst_messages_coalesce_read_receipt_requests(browser_page):
    page=browser_page
    open_chat(page)
    page.evaluate("""() => {
      window.__reads=[];
      const originalFetch=window.fetch;
      window.fetch=(url,opts={})=>{
        if(String(url).endsWith('/read'))__reads.push(JSON.parse(opts.body));
        return originalFetch(url,opts);
      };
      const ws=__qa.ws.at(-1);
      for(let i=1;i<=40;i++){
        ws.onmessage({data:JSON.stringify({type:'message',data:{message_id:'burst-'+i,message_cursor:i,sender_org:'B',body:'notice '+i,version:1}})});
      }
    }""")
    page.wait_for_timeout(440)
    assert page.evaluate('__reads.length') <= 2, 'Unbounded read receipt POSTs from one WS message batch'
    assert page.evaluate('__reads.at(-1)?.cursor') == 40
