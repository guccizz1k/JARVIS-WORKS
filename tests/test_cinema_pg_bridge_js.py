"""Executable tests for app/cinema_bridge_v3.js using Node's vm with stubbed CINEMA globals.

No browser, no real server: a fake `fetch` plays the PostgreSQL trade API. This proves the bridge's
own logic (activation, ledger mapping, request ids, duplicate-click guard, success-only-after-server,
evidence hashing, role/flow guards). It does NOT prove the real HTML UI, real HTTP, or real database.
"""
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = ROOT / "app" / "cinema_bridge_v3.js"

RUNNER = r'''
const vm=require('vm'),fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
const prelude=`
const calls=[],toasts=[],events=[],downloads=[];let lastModal=null,fileInput=null;
function download(name,blob,type){downloads.push({name,blob,type})}
let fetchRouter=null;let me={id:'u-admin',org_id:'o1',role:'admin'};
let _jwServerUser={id:'u-admin',org_id:'o1',role:'admin'};let _jwCsrf='csrf-token';let _jwServerData=null;
const modalStack=[];
function toast(m,k){toasts.push([k||'info',m]);events.push('toast:'+(k||'info'))}
async function fetch(url,opt){opt=opt||{};const isStr=typeof opt.body==='string';const rec={url,method:opt.method||'GET',headers:opt.headers||{},body:isStr?JSON.parse(opt.body):null,raw:(!isStr&&opt.body)?opt.body:null};calls.push(rec);events.push((rec.method)+' '+url);
  const r=await fetchRouter(rec);const hd=r.headers||{};return {ok:r.status>=200&&r.status<300,status:r.status,
    headers:{get:k=>{const kk=Object.keys(hd).find(x=>x.toLowerCase()===String(k).toLowerCase());return kk?hd[kk]:null}},
    arrayBuffer:async()=>r.bytes,json:async()=>{if(r.json===undefined)throw new Error('no json');return r.json}}}
async function _jwRequest(p){events.push('GET '+p);return Object.assign({},me)}
async function _jwFetchSnapshot(){return {partners:[{id:'legacy-p',name:'L'}],deals:[{id:'legacy-d'}]}}
function _jwSeedReadOnly(){events.push('seed')} function restoreSession(){} function emit(){events.push('emit')} async function softRender(){}
function go(h){events.push('go:'+h)} const today=()=>'2026-11-04'; const won=n=>n+'원';
function formModal(cfg){lastModal=cfg;return {box:{querySelector:s=>s==='input[type=file]'?fileInput:null},close(){}}}
function _jwOriginalCINEMAPartnerForm(){} function _jwOriginalCINEMADealForm(){return null}
let quoteSetStatus=(d,s)=>{calls.push({prev:'quoteSetStatus'});return 'prev'};
let createOrder=d=>{calls.push({prev:'createOrder'})}; let createStatement=d=>{calls.push({prev:'createStatement'})};
let confirmStatement=d=>{calls.push({prev:'confirmStatement'})}; let createInvoice=d=>{calls.push({prev:'createInvoice'})};
let invoiceRequest=d=>{calls.push({prev:'invoiceRequest'})}; let invoiceIssue=d=>{calls.push({prev:'invoiceIssue'})};
let invoiceReject=d=>{calls.push({prev:'invoiceReject'})}; let paymentForm=d=>{calls.push({prev:'paymentForm'})};
let removePayment=d=>{calls.push({prev:'removePayment'})}; let deliveryForm=d=>{calls.push({prev:'deliveryForm'})};
let partnerForm=()=>{calls.push({prev:'partnerForm'})}; let dealForm=()=>{calls.push({prev:'dealForm'})};
`;
const tests=`
const results=[];
const check=(name,ok,detail)=>results.push({name,ok:!!ok,detail:detail===undefined?'':String(detail)});
const reset=()=>{calls.length=0;toasts.length=0;events.length=0;lastModal=null;fileInput=null;downloads.length=0;_jwV3Opening.clear();_jwV3Active=false;_jwV3ProbeAt=0;_jwV3Pending.clear();_jwServerUser={id:'u-admin',org_id:'o1',role:'admin'};me={id:'u-admin',org_id:'o1',role:'admin'};_jwCsrf='csrf-token'};
const SHA_B=sha256hex('proof-b');
const ledger=()=>({
 partners:[{id:'P1',name:'ACME',business_number:'1234567890',version:3}],
 quotes:[{id:'Q1',trade_no:'T261104-0001',partner_id:'P1',title:'Parts',status:'ordered',vat_mode:'taxable',version:4,created_at:'2026-11-04T01:00:00Z',updated_at:'2026-11-04T02:00:00Z'},
         {id:'Q2',trade_no:'T261104-0002',partner_id:'P1',title:'Draft',status:'draft',vat_mode:'exempt',version:1,created_at:'2026-11-04T03:00:00Z',updated_at:'2026-11-04T03:00:00Z'}],
 quoteItems:[{id:'QI1',quote_id:'Q1',position:0,name:'Bolt',quantity:10,unit_price:1000},{id:'QI2',quote_id:'Q2',position:0,name:'Nut',quantity:2,unit_price:500}],
 orders:[{id:'O1',trade_no:'T261104-0001',quote_id:'Q1',partner_id:'P1',status:'open',created_at:'2026-11-04T01:30:00Z'}],
 orderItems:[{id:'OI1',order_id:'O1',position:0,name:'Bolt',quantity:10,unit_price:1000}],
 deliveries:[{id:'D1',order_id:'O1',seq:1,status:'confirmed',evidence_name:'a.pdf',evidence_sha256:'a'.repeat(64),recorded_by:'u-member',approved_at:'2026-11-04T04:00:00Z'},
             {id:'D2',order_id:'O1',seq:2,status:'recorded',evidence_name:'b.pdf',evidence_sha256:SHA_B,recorded_by:'u-member'},
             {id:'D3',order_id:'O1',seq:3,status:'cancelled',evidence_name:'c.pdf',evidence_sha256:'c'.repeat(64),recorded_by:'u-member'}],
 deliveryItems:[{delivery_id:'D1',order_item_id:'OI1',quantity:6},{delivery_id:'D2',order_item_id:'OI1',quantity:3},{delivery_id:'D3',order_item_id:'OI1',quantity:1}],
 statements:[{id:'S1',order_id:'O1',delivery_id:'D1',status:'confirmed',total_krw:6600,created_at:'2026-11-04T05:00:00Z'}],
 invoices:[{id:'V1',statement_id:'S1',invoice_no:'INV-T261104-0001-01',status:'confirmed',total_krw:6600,created_at:'2026-11-04T06:00:00Z'}],
 payments:[{id:'PY1',invoice_id:'V1',amount_krw:1000,paid_on:'2026-11-05',reference:'r1'},{id:'PY2',invoice_id:'V1',amount_krw:600,paid_on:'2026-11-06',reference:'r2'}],
 reversals:[{payment_id:'PY2'}],
 evidence:[{id:'E1',content_sha256:'a'.repeat(64),size_bytes:100,content_type:'application/pdf',file_name:'a.pdf',uploaded_by:'u-member'},
           {id:'E2',content_sha256:SHA_B,size_bytes:7,content_type:'application/pdf',file_name:'b.pdf',uploaded_by:'u-member'}]});
const pgRoutes=(over)=>async rec=>{
  const u=rec.url.replace('/api/pg-stage/cinema-trade','');
  if(over&&over[rec.method+' '+u.split('?')[0]])return over[rec.method+' '+u.split('?')[0]](rec);
  const L=ledger();const map={'/partners':L.partners,'/quotes':L.quotes,'/quote-items':L.quoteItems,'/orders':L.orders,'/order-items':L.orderItems,'/deliveries':L.deliveries,'/delivery-items':L.deliveryItems,'/statements':L.statements,'/invoices':L.invoices,'/payments':L.payments,'/payment-reversals':L.reversals,'/evidence':L.evidence};
  const key=u.split('?')[0];
  if(rec.method==='GET'&&map[key])return {status:200,json:map[key].map(r=>({row:r}))};
  if(rec.method==='POST'&&key==='/evidence'){const sha=Buffer.from(await crypto.subtle.digest('SHA-256',rec.raw)).toString('hex');
    const nm=decodeURIComponent(new URLSearchParams(u.split('?')[1]).get('name'));
    return {status:200,json:{replayed:false,entity_type:'evidence',entity:{id:'EVNEW',content_sha256:sha,size_bytes:rec.raw.byteLength,file_name:nm}}}}
  if(rec.method==='POST'&&/^\\/evidence\\/[^/]+\\/open$/.test(key))return {status:200,headers:{'Content-Type':'application/pdf','X-Evidence-SHA256':SHA_B},bytes:Uint8Array.from(Buffer.from('proof-b')).buffer};
  if(rec.method==='POST')return {status:200,json:{entity:{id:'NEW1'},replayed:false}};
  return {status:404,json:{detail:'nf'}}};
const loadDeals=async()=>{_jwServerData=await _jwFetchSnapshot();return _jwServerData};
const findDeal=(snap,id)=>snap.deals.find(d=>d.id===id);
const hex=async s=>Buffer.from(await crypto.subtle.digest('SHA-256',Buffer.from(s))).toString('hex');
const fileOf=(text,type='image/png',name='ev.png')=>({size:Buffer.byteLength(text),type,arrayBuffer:async()=>Uint8Array.from(Buffer.from(text)).buffer,name});

(async()=>{
 // 1 inert when the PG API is not mounted
 reset();fetchRouter=async()=>({status:404,json:{detail:'nf'}});
 let snap=await loadDeals();
 check('J01_inert_when_pg_api_absent',!_jwV3Active&&snap.deals.length===1&&snap.deals[0].id==='legacy-d'&&calls.every(c=>c.method==='GET'),JSON.stringify(calls.map(c=>c.url)));
 // 2 probe throttled
 const n=calls.length;await loadDeals();
 check('J02_negative_probe_is_throttled',calls.length===n,calls.length-n);
 // 3 inert when logged out
 reset();_jwServerUser=null;fetchRouter=pgRoutes();snap=await loadDeals();
 check('J03_inert_without_signed_in_user',!_jwV3Active&&calls.length===0);
 // 4 active mapping
 reset();fetchRouter=pgRoutes();snap=await loadDeals();
 const d=findDeal(snap,'pg-Q1'),d2=findDeal(snap,'pg-Q2');
 check('J04_active_merges_legacy_and_pg_deals',_jwV3Active&&snap.deals.length===3&&snap.partners.length===2);
 check('J05_only_confirmed_delivery_counts_as_delivered',d.deliveries.length===1&&d.deliveries[0].items[0].qty===6,JSON.stringify(d.deliveries));
 check('J06_pending_delivery_reserves_but_is_not_delivered',d.items[0].pgReserved===9&&d.items[0].pgConfirmed===6&&d.pg.pending.length===1&&d.pg.pending[0].id==='D2');
 check('J07_cancelled_delivery_is_ignored',!JSON.stringify(d).includes('"D3"'));
 check('J08_invoice_status_mapping_and_paid_excludes_reversed',d.invoice.status==='issued'&&d.invoice.paid===1000&&d.payments.length===1&&d.payments[0].id==='PY1',JSON.stringify(d.invoice));
 check('J09_quote_status_mapping_ordered_to_approved',d.quote.status==='approved'&&d2.quote.status==='draft'&&d2.order===null);
 check('J10_honesty_flags_present',d.pg.bankConfirmed===false&&d.pg.paymentBasis==='internal_record_only'&&d.pg.deliveryBasis==='human_admin_attested_evidence_hash');
 check('J11_money_stays_integer_krw',d.items.every(i=>Number.isSafeInteger(i.price)&&Number.isSafeInteger(i.qty))&&Number.isSafeInteger(d.invoice.total));
 // 5 delegation for legacy deals
 reset();fetchRouter=pgRoutes();await loadDeals();
 quoteSetStatus({id:'legacy-d'},'sent');createOrder({id:'legacy-d'});
 check('J12_legacy_deals_delegate_to_previous_handlers',calls.filter(c=>c.prev).map(c=>c.prev).join()==='quoteSetStatus,createOrder'&&!calls.some(c=>c.method==='POST'));
 // 6 success only after server + refresh
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;events.length=0;
 await createOrder(findDeal(snap,'pg-Q2'));
 const post=calls.find(c=>c.method==='POST');
 check('J13_write_posts_csrf_and_request_id',post&&post.url.endsWith('/orders')&&post.headers['X-CSRF-Token']==='csrf-token'&&/^[A-Za-z0-9._:-]{8,128}$/.test(post.body.request_id)&&post.body.quote_id==='Q2',JSON.stringify(post));
 const iPost=events.findIndex(e=>e.startsWith('POST')),iOk=events.indexOf('toast:ok'),iRefresh=events.findIndex(e=>e==='GET /api/me');
 check('J14_ok_toast_only_after_commit_and_ledger_refresh',iPost>=0&&iRefresh>iPost&&iOk>iRefresh,events.join(' | '));
 // 7 definitive failure
 reset();fetchRouter=pgRoutes({'POST /orders':async()=>({status:422,json:{detail:'quote is not approved'}})});snap=await loadDeals();calls.length=0;toasts.length=0;
 await createOrder(findDeal(snap,'pg-Q2'));
 check('J15_server_rejection_shows_error_and_never_success',toasts.length===1&&toasts[0][0]==='bad'&&toasts[0][1]==='quote is not approved'&&!toasts.some(t=>t[0]==='ok'),JSON.stringify(toasts));
 check('J16_definitive_failure_releases_request_id',_jwV3Pending.size===0);
 const failedRid=calls.find(c=>c.method==='POST').body.request_id;
 fetchRouter=pgRoutes();calls.length=0;await createOrder(findDeal(snap,'pg-Q2'));
 check('J17_new_attempt_after_definitive_failure_uses_new_request_id',calls.find(c=>c.method==='POST').body.request_id!==failedRid);
 // 8 unknown outcome keeps the id
 reset();let attempt=0;fetchRouter=pgRoutes({'POST /orders':async()=>{attempt++;if(attempt===1)throw new Error('net');return {status:200,json:{entity:{id:'N'}}}}});
 snap=await loadDeals();calls.length=0;toasts.length=0;
 await createOrder(findDeal(snap,'pg-Q2'));const first=calls.find(c=>c.method==='POST').body.request_id;
 check('J18_network_failure_reports_unknown_outcome',toasts[0][0]==='bad'&&/저장 여부/.test(toasts[0][1]),toasts[0][1]);
 calls.length=0;await createOrder(findDeal(snap,'pg-Q2'));
 check('J19_retry_after_unknown_outcome_reuses_request_id',calls.find(c=>c.method==='POST').body.request_id===first);
 // 9 duplicate click
 reset();let release;const gate=new Promise(r=>release=r);
 fetchRouter=pgRoutes({'POST /orders':async()=>{await gate;return {status:200,json:{entity:{id:'N'}}}}});snap=await loadDeals();calls.length=0;
 const dd=findDeal(snap,'pg-Q2');const a=createOrder(dd),b=createOrder(dd);release();await Promise.all([a,b]);
 check('J20_double_click_sends_exactly_one_request',calls.filter(c=>c.method==='POST').length===1,calls.filter(c=>c.method==='POST').length);
 // 10 saved-but-refresh-failed message
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;toasts.length=0;me={id:'someone-else',org_id:'o2',role:'admin'};
 await createOrder(findDeal(snap,'pg-Q2'));
 check('J21_org_change_after_commit_blocks_success_display',!toasts.some(t=>t[0]==='ok')&&/서버에는 저장/.test(toasts[0][1]),JSON.stringify(toasts));
 // 11 not signed in
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;toasts.length=0;_jwCsrf='';
 await createOrder(findDeal(snap,'pg-Q2'));
 check('J22_missing_csrf_blocks_write_before_network',!calls.some(c=>c.method==='POST')&&toasts[0][0]==='bad');
 // 12 member cannot request invoice (no fake request)
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;toasts.length=0;
 invoiceRequest(findDeal(snap,'pg-Q1'));
 check('J23_member_invoice_request_makes_no_server_call_and_no_success',calls.length===0&&toasts[0][0]==='bad');
 // 13 invoice issue sequence for admin from draft
 reset();fetchRouter=pgRoutes();snap=await loadDeals();const q1=findDeal(snap,'pg-Q1');q1.invoice={...q1.invoice,status:'draft',serverId:'V1'};calls.length=0;
 await invoiceIssue(q1);
 const paths=calls.filter(c=>c.method==='POST').map(c=>c.url.replace('/api/pg-stage/cinema-trade',''));
 check('J24_issue_from_draft_reviews_then_confirms',paths.join()==='/invoices/V1/review,/invoices/V1/confirm',paths.join());
 // 14 delivery record (server-stored evidence)
 reset();fetchRouter=pgRoutes();snap=await loadDeals();const q=findDeal(snap,'pg-Q1');calls.length=0;_jwServerUser.role='member';_jwServerUser.id='u-member';me={...me,id:'u-member',role:'member'};
 deliveryForm(q);
 check('J25_member_sees_record_mode_only',lastModal&&!lastModal.fields.some(f=>f.k==='pending')&&lastModal.fields.some(f=>f.k==='evidence'));
 const rem=lastModal.fields.find(f=>f.k==='q0');
 check('J26_quantity_validation_blocks_over_remaining',rem.validate(1)==='' && rem.validate(0)==='' && rem.validate(2)!=='' && rem.validate(0.5)!=='' && rem.validate(-1)!=='' && rem.validate(1000)!=='' ,rem.validate(1000));
 fileInput={files:[fileOf('delivery-proof')]};
 let err=null;try{await lastModal.onSubmit({q0:1,ack:false},{box:{querySelector:()=>fileInput}})}catch(e){err=e}
 check('J27_record_requires_evidence_acknowledgement',err&&/확인/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 fileInput={files:[]};err=null;try{await lastModal.onSubmit({q0:1,ack:true},{box:{querySelector:()=>fileInput}})}catch(e){err=e}
 check('J28_record_requires_a_file',err&&/파일/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 fileInput={files:[fileOf('delivery-proof')]};await lastModal.onSubmit({q0:1,ack:true},{box:{querySelector:()=>fileInput}});
 const up=calls.find(c=>c.method==='POST'&&c.url.includes('/evidence?'));
 const rp=calls.find(c=>c.method==='POST'&&c.url.endsWith('/orders/O1/deliveries'));
 const shaDP=await hex('delivery-proof');
 check('J29_record_uploads_the_raw_file_then_uses_the_server_hash',!!up&&!!rp&&up.raw&&up.raw.byteLength===14&&up.headers['Content-Type']==='image/png'&&up.headers['X-CSRF-Token']==='csrf-token'&&up.body===null&&/request_id=cpg-[0-9a-f]{32}/.test(up.url)&&rp.body.evidence_sha256===shaDP&&JSON.stringify(rp.body.lines)==='[{"order_item_id":"OI1","quantity":1}]',JSON.stringify([up&&up.url,rp&&rp.body]));
 check('J29b_upload_precedes_record_and_delivery_is_not_recorded_before_upload',calls.findIndex(c=>c===up)<calls.findIndex(c=>c===rp));
 // 15 admin open / confirm modes
 reset();fetchRouter=pgRoutes();snap=await loadDeals();const q3=findDeal(snap,'pg-Q1');calls.length=0;
 deliveryForm(q3);
 check('J30_admin_sees_record_open_and_confirm_modes',lastModal.fields.find(f=>f.k==='mode').options.map(o=>o[0]).join()==='record,open,confirm'&&lastModal.fields.some(f=>f.k==='pending'));
 check('J30b_pending_carries_the_server_evidence_id',q3.pg.pending[0].evidenceId==='E2'&&q3.pg.pending[0].evidenceSize===7);
 err=null;try{await lastModal.onSubmit({mode:'confirm',pending:'NOPE',ack:true},{box:{querySelector:()=>null}})}catch(e){err=e}
 check('J31_confirm_without_a_selected_delivery_is_rejected_before_network',err&&/선택/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 await lastModal.onSubmit({mode:'open',pending:'D2'},{box:{querySelector:()=>null}});
 const op=calls.find(c=>c.method==='POST');
 check('J32_open_mode_posts_audited_open_and_downloads_the_verified_file',op&&op.url.endsWith('/evidence/E2/open')&&op.headers['X-CSRF-Token']==='csrf-token'&&/^cpg-/.test(op.body.request_id)&&downloads.length===1&&downloads[0].name==='b.pdf'&&downloads[0].type==='application/pdf'&&!calls.some(c=>c.url.endsWith('/confirm')),JSON.stringify(calls.map(c=>c.url)));
 calls.length=0;await lastModal.onSubmit({mode:'confirm',pending:'D2',ack:true},{box:{querySelector:()=>null}});
 const cp=calls.find(c=>c.method==='POST');
 check('J32b_confirm_posts_confirm_for_that_delivery_without_a_client_hash_check',cp&&cp.url.endsWith('/deliveries/D2/confirm')&&!calls.some(c=>c.method==='POST'&&c.url.includes('/evidence')),cp&&cp.url);
 calls.length=0;err=null;try{await lastModal.onSubmit({mode:'confirm',pending:'D2',ack:false},{box:{querySelector:()=>null}})}catch(e){err=e}
 check('J32c_confirm_requires_acknowledgement',err&&/확인/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 // 16 recorder cannot confirm own delivery in UI
 reset();_jwServerUser.id='u-member';_jwServerUser.role='admin';me={...me,id:'u-member'};fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;toasts.length=0;
 const q5=findDeal(snap,'pg-Q1');q5.items.forEach(i=>i.pgReserved=i.qty);deliveryForm(q5);
 check('J33_recorder_is_told_they_cannot_confirm_own_delivery',lastModal===null&&/본인이 기록/.test(toasts[0][1]),toasts[0]&&toasts[0][1]);
 // 17 payments
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;
 paymentForm(findDeal(snap,'pg-Q1'));
 const amt=lastModal.fields.find(f=>f.k==='amount');
 check('J34_payment_validation_rejects_overpay_zero_and_fractions',amt.validate(5601)!==''&&amt.validate(5600)===''&&amt.validate(0)!==''&&amt.validate(1.5)!=='',amt.validate(5601));
 check('J35_payment_modal_states_it_is_not_a_bank_confirmation',/은행 입금 확인이 아니며/.test(lastModal.note));
 await lastModal.onSubmit({date:'2026-11-07',amount:5600});
 const pp=calls.find(c=>c.method==='POST');
 check('J36_payment_posts_integer_amount_date_and_reference',pp.url.endsWith('/invoices/V1/payments')&&pp.body.amount_krw===5600&&pp.body.paid_on==='2026-11-07'&&/^pay-/.test(pp.body.reference));
 reset();fetchRouter=pgRoutes();snap=await loadDeals();const q6=findDeal(snap,'pg-Q1');q6.invoice={...q6.invoice,status:'draft'};toasts.length=0;calls.length=0;paymentForm(q6);
 check('J37_payment_blocked_until_invoice_is_issued',lastModal===null&&toasts[0][0]==='bad');
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;removePayment(findDeal(snap,'pg-Q1'),'PY1');
 await lastModal.onSubmit({reason:'wrong amount'});
 const rv=calls.find(c=>c.method==='POST');
 check('J38_payment_removal_becomes_a_reversal_with_reason',rv.url.endsWith('/payments/PY1/reverse')&&rv.body.reason==='wrong amount');
 // 18 quote transitions use server version
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;await quoteSetStatus(findDeal(snap,'pg-Q2'),'sent');
 const qt=calls.find(c=>c.method==='POST');
 check('J39_quote_transition_sends_expected_version_and_target',qt.url.endsWith('/quotes/Q2/transition')&&qt.body.expected_version===1&&qt.body.to==='submitted');
 // 19 statement flow
 reset();fetchRouter=pgRoutes();snap=await loadDeals();calls.length=0;
 const q7=findDeal(snap,'pg-Q1');q7.pg.uncoveredDelivery={id:'D9'};await createStatement(q7);
 check('J40_statement_is_created_from_a_confirmed_delivery',calls.find(c=>c.method==='POST').url.endsWith('/deliveries/D9/statements'));
 // 20 corrupt ledger values must never be shown as 0 won / current time (audit S2)
 const corrupt=async(mut)=>{reset();const base=ledger();mut(base);
   fetchRouter=async rec=>{const u=rec.url.replace('/api/pg-stage/cinema-trade','').split('?')[0];
     const map={'/partners':base.partners,'/quotes':base.quotes,'/quote-items':base.quoteItems,'/orders':base.orders,'/order-items':base.orderItems,'/deliveries':base.deliveries,'/delivery-items':base.deliveryItems,'/statements':base.statements,'/invoices':base.invoices,'/payments':base.payments,'/payment-reversals':base.reversals,'/evidence':base.evidence};
     if(rec.method==='GET'&&map[u])return {status:200,json:map[u].map(r=>({row:r}))};return {status:404,json:{}}};
   const sn=await loadDeals();return {sn,active:_jwV3Active,bad:toasts.filter(t=>t[0]==='bad').length};};
 let r=await corrupt(L=>{L.invoices[0].total_krw=null});
 check('J41_null_invoice_total_is_not_shown_as_zero',!r.active&&r.sn.deals.length===1&&r.bad===1,JSON.stringify([r.active,r.sn.deals.length,r.bad]));
 r=await corrupt(L=>{L.payments[0].amount_krw=''});
 check('J42_empty_payment_amount_is_not_shown_as_zero',!r.active&&r.sn.deals.length===1&&r.bad===1);
 r=await corrupt(L=>{L.quoteItems[0].unit_price='1e9';L.orderItems[0].unit_price=4.5});
 check('J43_fractional_or_exponent_amount_blocks_display',!r.active&&r.sn.deals.length===1&&r.bad===1);
 r=await corrupt(L=>{L.quotes[0].created_at='not-a-date'});
 check('J44_invalid_timestamp_is_not_replaced_by_now',!r.active&&r.sn.deals.length===1&&r.bad===1);
 r=await corrupt(L=>{L.statements[0].created_at=null});
 check('J45_missing_statement_date_is_left_blank_never_replaced_by_today',r.active&&findDeal(r.sn,'pg-Q1').statement.date===''&&r.bad===0,JSON.stringify(findDeal(r.sn,'pg-Q1').statement));
 r=await corrupt(L=>{L.deliveryItems[0].quantity=9007199254740993});
 check('J46_unsafe_integer_quantity_blocks_display',!r.active&&r.sn.deals.length===1&&r.bad===1);
 r=await corrupt(L=>{});
 check('J47_clean_ledger_still_displays',r.active&&r.sn.deals.length===3&&r.bad===0);
 // 21 server-stored evidence hardening (audit S3)
 const memberForm=async(over)=>{reset();fetchRouter=pgRoutes(over);snap=await loadDeals();_jwServerUser.role='member';_jwServerUser.id='u-member';me={...me,id:'u-member',role:'member'};calls.length=0;toasts.length=0;deliveryForm(findDeal(snap,'pg-Q1'));return lastModal};
 let fm=await memberForm();
 err=null;try{await fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[fileOf('x','text/html','x.html')]})}})}catch(e){err=e}
 check('J48_non_pdf_png_jpeg_type_is_blocked_before_network',err&&/PDF/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 err=null;try{await fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[{size:5*1024*1024+1,type:'application/pdf',name:'big.pdf',arrayBuffer:async()=>new ArrayBuffer(0)}]})}})}catch(e){err=e}
 check('J49_file_over_five_megabytes_is_blocked_before_network',err&&/5MB/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 err=null;try{await fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[{size:0,type:'application/pdf',name:'z.pdf',arrayBuffer:async()=>new ArrayBuffer(0)}]})}})}catch(e){err=e}
 check('J50_empty_file_is_blocked_before_network',err&&/5MB/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 fm=await memberForm({'POST /evidence':async rec=>({status:200,json:{replayed:false,entity_type:'evidence',entity:{id:'EVX',content_sha256:'f'.repeat(64),size_bytes:3,file_name:'e.png'}}})});
 err=null;try{await fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[fileOf('abc')]})}})}catch(e){err=e}
 check('J51_server_hash_differing_from_the_file_blocks_the_delivery_record',err&&/지문/.test(err.message)&&!calls.some(c=>c.url.endsWith('/deliveries')),err&&err.message);
 fm=await memberForm({'POST /evidence':async rec=>({status:200,json:{replayed:false,entity_type:'evidence',entity:{id:'EVX'}}})});
 err=null;try{await fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[fileOf('abc')]})}})}catch(e){err=e}
 check('J52_malformed_upload_response_blocks_the_delivery_record',err&&/응답/.test(err.message)&&!calls.some(c=>c.url.endsWith('/deliveries')));
 let n503=0;
 fm=await memberForm({'POST /evidence':async rec=>{n503++;if(n503===1)return {status:503,json:{detail:'x'}};return pgRoutes()(rec)}});
 err=null;try{await fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[fileOf('abc')]})}})}catch(e){err=e}
 await fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[fileOf('abc')]})}});
 const ups=calls.filter(c=>c.method==='POST'&&c.url.includes('/evidence?'));
 const rid=u=>new URLSearchParams(u.split('?')[1]).get('request_id');
 check('J53_upload_retry_after_unknown_outcome_reuses_request_id',!!err&&ups.length===2&&rid(ups[0].url)===rid(ups[1].url),ups.map(c=>c.url).join(' '));
 let releaseU;const gateU=new Promise(r=>releaseU=r);
 fm=await memberForm({'POST /evidence':async rec=>{await gateU;return pgRoutes()(rec)}});
 const sub=()=>fm.onSubmit({q0:1,ack:true},{box:{querySelector:()=>({files:[fileOf('abc')]})}});
 const s1=sub(),s2=sub();await new Promise(r=>setTimeout(r,20));releaseU();await Promise.all([s1,s2]);
 check('J54_double_submit_uploads_the_file_exactly_once',calls.filter(c=>c.method==='POST'&&c.url.includes('/evidence?')).length===1&&calls.filter(c=>c.url.endsWith('/deliveries')).length===1,calls.filter(c=>c.method==='POST').map(c=>c.url).join(' '));
 // open: integrity of what the server sends
 const adminForm=async(over)=>{reset();fetchRouter=pgRoutes(over);snap=await loadDeals();calls.length=0;toasts.length=0;deliveryForm(findDeal(snap,'pg-Q1'));return lastModal};
 let af=await adminForm({'POST /evidence/E2/open':async()=>({status:200,headers:{'Content-Type':'application/pdf','X-Evidence-SHA256':SHA_B},bytes:Uint8Array.from(Buffer.from('tampered')).buffer})});
 err=null;try{await af.onSubmit({mode:'open',pending:'D2'},{box:{querySelector:()=>null}})}catch(e){err=e}
 check('J55_open_with_tampered_bytes_is_rejected_and_nothing_is_downloaded',err&&/지문/.test(err.message)&&downloads.length===0,err&&err.message);
 af=await adminForm({'POST /evidence/E2/open':async()=>({status:200,headers:{'Content-Type':'text/html','X-Evidence-SHA256':SHA_B},bytes:Uint8Array.from(Buffer.from('proof-b')).buffer})});
 err=null;try{await af.onSubmit({mode:'open',pending:'D2'},{box:{querySelector:()=>null}})}catch(e){err=e}
 check('J56_open_with_unexpected_content_type_is_rejected',err&&/형식/.test(err.message)&&downloads.length===0);
 af=await adminForm({'POST /evidence/E2/open':async()=>({status:403,json:{detail:'forbidden'}})});
 err=null;try{await af.onSubmit({mode:'open',pending:'D2'},{box:{querySelector:()=>null}})}catch(e){err=e}
 check('J57_open_refused_by_server_downloads_nothing',err&&/forbidden/.test(err.message)&&downloads.length===0);
 { // evidence row missing for a recorded delivery -> fail closed
   reset();const base=ledger();base.evidence=base.evidence.filter(e=>e.id!=='E2');
   fetchRouter=async rec=>{const u=rec.url.replace('/api/pg-stage/cinema-trade','').split('?')[0];
     const map={'/partners':base.partners,'/quotes':base.quotes,'/quote-items':base.quoteItems,'/orders':base.orders,'/order-items':base.orderItems,'/deliveries':base.deliveries,'/delivery-items':base.deliveryItems,'/statements':base.statements,'/invoices':base.invoices,'/payments':base.payments,'/payment-reversals':base.reversals,'/evidence':base.evidence};
     if(rec.method==='GET'&&map[u])return {status:200,json:map[u].map(r=>({row:r}))};return {status:404,json:{}}};
   snap=await loadDeals();calls.length=0;deliveryForm(findDeal(snap,'pg-Q1'));
   err=null;try{await lastModal.onSubmit({mode:'open',pending:'D2'},{box:{querySelector:()=>null}})}catch(e){err=e}
   check('J58_missing_server_evidence_row_blocks_open_and_confirm_view',err&&/찾을 수 없/.test(err.message)&&!calls.some(c=>c.method==='POST'));
 }
 r=await corrupt(L=>{L.evidence=null});
 check('J59_missing_evidence_collection_blocks_ledger_display',!r.active&&r.sn.deals.length===1&&r.bad===1);
 console.log(JSON.stringify(results));
})().catch(e=>{console.log(JSON.stringify([{name:'J00_harness_crashed',ok:false,detail:String(e&&e.stack||e)}]))});
`;
const code=prelude+'\n'+src+'\n'+tests;
const ctx=vm.createContext({console,crypto:require('crypto').webcrypto,Buffer,Uint8Array,ArrayBuffer,Blob:require('buffer').Blob,sha256hex:s=>require('crypto').createHash('sha256').update(s).digest('hex'),Date,JSON,Promise,Map,Set,Array,Object,Number,Error,Math,String,Symbol,parseInt,setTimeout,URLSearchParams,encodeURIComponent,FormData:class{}});
vm.runInContext(code,ctx);
'''


def run_harness():
    assert shutil.which("node"), "node is required for the bridge tests (this is a FAIL, not a skip)"
    with tempfile.TemporaryDirectory() as tmp:
        runner = Path(tmp) / "runner.js"
        runner.write_text(RUNNER, encoding="utf-8")
        proc = subprocess.run(["node", str(runner), str(BRIDGE)], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


RESULTS = None


def results():
    global RESULTS
    if RESULTS is None:
        RESULTS = run_harness()
    return RESULTS


def test_bridge_parses_as_javascript():
    assert shutil.which("node")
    proc = subprocess.run(["node", "--check", str(BRIDGE)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_bridge_never_uses_browser_storage_or_dangerous_sinks():
    text = BRIDGE.read_text(encoding="utf-8")
    assert not re.search(r"localStorage|sessionStorage|indexedDB|document\.cookie|eval\(|new Function|innerHTML", text)
    assert "</script" not in text.lower()


def test_bridge_has_no_claim_of_bank_or_physical_confirmation():
    text = BRIDGE.read_text(encoding="utf-8")
    assert "은행 입금 확인이 아니며" in text and "은행 확인 아님" in text


def test_harness_ran_at_least_forty_checks():
    names = [r["name"] for r in results()]
    assert len(names) >= 60 and "J00_harness_crashed" not in names


def test_every_harness_check_passed():
    failed = [r for r in results() if not r["ok"]]
    assert not failed, json.dumps(failed, ensure_ascii=False, indent=1)
