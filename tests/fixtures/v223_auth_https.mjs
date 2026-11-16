import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const origin=process.env.JW_TEST_ORIGIN,password=process.env.JW_TEST_PASSWORD;
assert.ok(origin?.startsWith('https://127.0.0.1:'));
const code=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const defer=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve}};
let checks=0;
function setup(){
 let cookie='',hold=null,arrived=null,invalidNext=false,loginPosts=0,failMe=false;const flags=[];
 const fetcher=async(url,init)=>{
  const headers=new Headers(init.headers);if(cookie)headers.set('Cookie',cookie);
  if(invalidNext&&url.endsWith('/api/customers')){headers.set('Cookie','jw_session=synthetic_invalid');invalidNext=false;}
  if(url.endsWith('/api/login'))loginPosts++;
  const r=await fetch(url,{...init,headers});
  for(const value of r.headers.getSetCookie()){
   if(url.endsWith('/api/login'))flags.push(value.includes('HttpOnly')&&value.includes('Secure')&&/SameSite=strict/i.test(value));
   cookie=value.split(';')[0];
  }
  if(failMe&&url.endsWith('/api/me')){failMe=false;throw Error('synthetic lost identity response');}
  if(hold&&url.endsWith('/api/customers')){const gate=hold;hold=null;arrived.resolve();await gate.promise;}
  return r;
 };
 const ctx={window:{},location:{origin,protocol:'https:'},fetch:fetcher,FormData,Blob,File,console};vm.runInNewContext(code,ctx);
 return {bridge:new ctx.window.JWOwnerServerBridge(),hold(){hold=defer();arrived=defer();return {arrived:arrived.promise,release:()=>hold?.resolve(),gate:hold}},invalid(){invalidNext=true},failNextMe(){failMe=true},posts:()=>loginPosts,flags,raw:async(path,init={})=>fetch(origin+path,{...init,headers:{...init.headers,...(cookie?{Cookie:cookie}:{})}})};
}
async function transitionRace(target,unauthorized=false){
 const x=setup(),b=x.bridge;await b.login('demo@hanbit.example',password);
 if(unauthorized)x.invalid();const hold=x.hold();const pending=b.list('customers');const rejected=assert.rejects(pending,{code:'STALE_SESSION'});
 await hold.arrived;await b.login(target,password);const id=b.identity.id;hold.gate.resolve();await rejected;
 assert.equal(b.identity.id,id);const r=await x.raw('/api/me');assert.equal(r.status,200);assert.equal((await r.json()).id,id);checks++;
}
await transitionRace('sameorg@example.invalid');
await transitionRace('demo@bada.example');
await transitionRace('sameorg@example.invalid',true);
const x=setup(),b=x.bridge;await b.login('demo@hanbit.example',password);assert.ok(x.flags.every(Boolean));checks++;
const missing=await x.raw('/api/customers',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:'Rejected synthetic'})});assert.equal(missing.status,403);checks++;
const customer=await b.write('/api/customers',{name:'TLS synthetic customer'});
const q=await b.write('/api/quotes',{customer_id:customer.id,title:'TLS synthetic flow',vat_mode:'taxable',items:[{name:'Part',quantity:2,unit_price:1000}]});
await b.write('/api/quotes/'+q.id+'/status',{status:'sent'});await b.write('/api/quotes/'+q.id+'/status',{status:'accepted'});
const o=await b.write('/api/orders/from-quote',{quote_id:q.id,due_date:'2099-12-30'});
await b.write('/api/orders/'+o.id+'/status',{status:'processing'});await b.write('/api/orders/'+o.id+'/status',{status:'fulfilled'});
const s=await b.statementFromOrder(o.id);await b.statementDetail(s.id,o.id);
const draft=await b.draftFromSource('delivery_note_draft',o.id);assert.equal((await b.draftDetail(draft.id)).source_id,o.id);assert.ok((await b.draftSummary()).recent.some(r=>r.id===draft.id));assert.equal((await b.draftXlsx(draft.id)).bytes[0],80);checks++;
const foreign=setup();await foreign.bridge.login('demo@bada.example',password);await assert.rejects(foreign.bridge.draftXlsx(draft.id));checks++;
const inv=await b.write('/api/invoices/from-order',{order_id:o.id,due_date:'2099-12-31'});
assert.equal(inv.money.total,2200);
const paymentDraft=await b.draftFromSource('payment_request_draft',inv.id);
await b.write('/api/invoices/'+inv.id+'/payments',{reference:'tls-synthetic-reference',amount:2200,paid_at:new Date().toISOString().slice(0,10)});
await assert.rejects(b.draftXlsx(paymentDraft.id),{code:'STALE_DRAFT'});checks++;
const trace=await b.orderTransactionTrace(o.id);assert.equal(trace.active_paid,2200);checks++;
await b.write('/api/invoices/'+inv.id+'/payments',{reference:'tls-synthetic-reference',amount:2200,paid_at:new Date().toISOString().slice(0,10)});assert.equal((await b.orderTransactionTrace(o.id)).active_paid,2200);checks++;
await assert.rejects(b.write('/api/invoices/'+inv.id+'/payments',{reference:'tls-synthetic-reference',amount:2100,paid_at:new Date().toISOString().slice(0,10)}));checks++;
const uploaded=await b.uploadEvidence(new File([fs.readFileSync(process.env.JW_TEST_EVIDENCE_FILE)],'synthetic.xlsx'));assert.equal(uploaded.confirmation_required,true);assert.equal(uploaded.original_file_stored,false);assert.ok((await b.evidenceQueue()).items.some(r=>r.id===uploaded.id));checks++;
const reviewed=await b.evidencePreview(uploaded.id);const approval={preview_digest:reviewed.digest,record_type:'expense',document_kind:reviewed.document.document_kind,counterparty:reviewed.document.fields.counterparty,document_date:reviewed.document.fields.document_date,gross_amount:reviewed.document.fields.gross_amount,reference_number:reviewed.document.fields.reference_number,original_checked:true};
await assert.rejects(b.confirmEvidence(uploaded.id,{...approval,original_checked:false}),{code:'ORIGINAL_REVIEW_REQUIRED'});checks++;
const confirmed=await b.confirmEvidence(uploaded.id,approval);assert.equal(confirmed.accounting_posted,false);assert.equal(confirmed.payment_created,false);assert.equal(confirmed.inventory_stock_changed,false);assert.ok((await b.listEvidenceRecords()).some(r=>r.id===confirmed.id));checks++;
await assert.rejects(foreign.bridge.evidencePreview(uploaded.id));assert.ok(!(await foreign.bridge.evidenceQueue()).items.some(r=>r.id===uploaded.id));checks++;
await assert.rejects(b.confirmEvidence(uploaded.id,approval),{code:'EVIDENCE_ALREADY_CONFIRMED'});assert.equal((await b.orderTransactionTrace(o.id)).active_paid,2200);checks++;
await b.logout();assert.equal((await x.raw('/api/me')).status,401);assert.equal(b.signedIn,false);checks++;
const partial=setup();partial.failNextMe();await assert.rejects(partial.bridge.login('demo@hanbit.example',password),{code:'NETWORK_ERROR'});assert.equal(partial.bridge.signedIn,false);assert.equal((await partial.raw('/api/me')).status,200);await partial.bridge.logout();assert.equal((await partial.raw('/api/me')).status,401);checks++;
console.log(JSON.stringify({status:'PASS_REAL_HTTPS_BRIDGE_COOKIE_CSRF_EPOCH_AND_BUSINESS',checks,synthetic_only:true,physical_safari:false}));
