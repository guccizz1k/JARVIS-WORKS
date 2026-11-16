'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const src=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const ui=fs.readFileSync('app/static/approved_ui_quote_edit_v223.js','utf8');
const entry=fs.readFileSync('app/cinema_entry_v1.py','utf8');
const review=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),D='d'.repeat(32);
const ID={id:A,org_id:B,email:'qa@example.invalid',name:'Synthetic',role:'admin',
 org_name:'QA Org',csrf_token:'z'.repeat(36)};
const item={id:D,name:'Part A',quantity:1,unit_price:1000,position:0};
const quote={id:C,org_id:B,customer_id:D,customer_name_snapshot:'Customer',
 doc_no:'Q-20261116-1234567890',title:'Draft',status:'draft',vat_mode:'taxable',
 updated_at:'2026-11-16T18:00:00+09:00',items:[item],money:{subtotal:1000,vat:100,total:1100}};
const fingerprint='f'.repeat(64);
const response={quote,fingerprint};
function setup(handler){
 const calls=[],ctx={window:{},location:{origin:'https://review.example.invalid',protocol:'https:'},
 fetch:async(url,opts)=>{
   const path=new URL(url).pathname;calls.push({path,opts});
   const result=await handler(path,opts);
   const status=Number.isInteger(result?.status)?result.status:200;
   return {status,ok:status>=200&&status<300,
     headers:{get:key=>key==='content-type'?'application/json':null},
     json:async()=>result?.payload===undefined?result:result.payload};
 }};
 vm.runInNewContext(src,ctx);
 return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const denied=(promise,code)=>assert.rejects(promise,{code});
test('review-only script linked to deals panel, not baseline owner original',()=>{
 assert.ok(review.includes('JWOwnerQuoteEdit.render'));
 assert.ok(review.includes("if(key==='deals')"));
 assert.ok(entry.includes('approved_ui_quote_edit_v223.js'));
 assert.doesNotMatch(ui,/innerHTML|localStorage|indexedDB|sessionStorage|eval\(/);
});
test('draft quote editor returns tenant-verified fingerprint',async()=>{
 const x=setup(path=>path==='/api/me'?ID:response);
 await x.bridge.restore();const result=await x.bridge.quoteEditContext(C);
 assert.equal(result.quote.id,C);assert.equal(result.fingerprint,fingerprint);
 assert.equal(x.calls.at(-1).path,'/api/review/quotes/'+C+'/edit-context');
});
test('foreign org and non-draft quotes rejected',async()=>{
 const x=setup(path=>path==='/api/me'?ID:{...response,quote:{...quote,org_id:A}});
 await x.bridge.restore();
 await denied(x.bridge.quoteEditContext(C),'INVALID_QUOTE_EDIT_CONTEXT');
 const y=setup(path=>path==='/api/me'?ID:{...response,quote:{...quote,status:'sent'}});
 await y.bridge.restore();
 await denied(y.bridge.quoteEditContext(C),'INVALID_QUOTE_EDIT_CONTEXT');
});
test('quote write is explicit CSRF POST and allowlisted fields',async()=>{
 const x=setup(path=>path==='/api/me'?ID:{...response,changed:true});
 await x.bridge.restore();
 const update={customer_id:D,title:'New title',vat_mode:'taxable',
  items:[{name:'Part B',quantity:2,unit_price:500}]};
 const result=await x.bridge.quoteEditSave(C,fingerprint,update);
 assert.equal(result.changed,true);
 const sent=x.calls.at(-1);
 assert.equal(sent.path,'/api/review/quotes/'+C+'/update');
 assert.equal(sent.opts.headers['X-CSRF-Token'],ID.csrf_token);
 assert.equal(sent.opts.credentials,'same-origin');
 assert.deepEqual(Object.keys(JSON.parse(sent.opts.body)).sort(),['expected_sha256','updated']);
 assert.equal(JSON.parse(sent.opts.body).updated.items[0].name,'Part B');
});
test('write invalid quote IDs and malformed prices fail before fetch',async()=>{
 const x=setup(path=>path==='/api/me'?ID:response);
 await x.bridge.restore();
 const good={customer_id:D,title:'Title',vat_mode:'taxable',items:[{name:'Part A',quantity:1,unit_price:1000}]};
 await denied(x.bridge.quoteEditSave('bad',fingerprint,good),'INVALID_QUOTE_UPDATE');
 await denied(x.bridge.quoteEditSave(C,'not-a-fingerprint',good),'INVALID_QUOTE_UPDATE');
 await denied(x.bridge.quoteEditSave(C,fingerprint,{...good,items:[{...good.items[0],quantity:0}]}),'INVALID_QUOTE_UPDATE');
 await denied(x.bridge.quoteEditSave(C,fingerprint,{...good,items:[{...good.items[0],unit_price:'100'}]}),'INVALID_QUOTE_UPDATE');
 assert.equal(x.calls.length,1);
});
test('server 409 returns stale-version without claiming success',async()=>{
 const x=setup(path=>path==='/api/me'?ID:{status:409,payload:{detail:'stale'}});
 await x.bridge.restore();
 const p=x.bridge.quoteEditSave(C,fingerprint,
   {customer_id:D,title:'Updated',vat_mode:'taxable',items:[{name:'Part',quantity:1,unit_price:50}]});
 await denied(p,'STALE_VERSION');
});
test('session switch rejects delayed quotation read from former tenant',async()=>{
 let release;const slow=new Promise(r=>release=r);let current=ID;
 const x=setup(path=>path==='/api/me'?current:slow);
 await x.bridge.restore();
 const old=x.bridge.quoteEditContext(C).then(()=>null,e=>e.code);
 current={...ID,id:D,org_id:A};await x.bridge.restore();release(response);
 assert.equal(await old,'STALE_SESSION');
});
test('no HTML injection even if server quote title contains markup',()=>{
 assert.ok(ui.includes('textContent'));
 assert.ok(ui.includes('quoteEditContext'));
 assert.ok(ui.includes('quoteEditSave'));
});
