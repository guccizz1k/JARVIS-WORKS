'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const bridgeSrc=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const ui=fs.readFileSync('app/static/approved_ui_order_review_v223.js','utf8');
const review=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const entry=fs.readFileSync('app/cinema_entry_v1.py','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),D='d'.repeat(32),E='e'.repeat(32);
const user={id:A,org_id:B,name:'QA',email:'qa@example.invalid',role:'admin',
  org_name:'QA Org',csrf_token:'z'.repeat(36)};
const line={id:D,source_quote_item_id:E,name:'Part',quantity:2,unit_price:1000,position:0};
const quoteLine={id:E,name:'Part',quantity:2,unit_price:1000,position:0};
const snapshot={id:C,org_id:B,quote_id:E,customer_id:D,
  title:'Order',doc_no:'O-20261116-ABC',status:'received',
  review_state:'clean',due_date:'2099-12-30',money:{subtotal:2000,vat:200,total:2200},
  items:[line],quote_items:[quoteLine],differences:[]};
const hash='f'.repeat(64);
const response={order:snapshot,fingerprint:hash};
function serve(resolver){
  const calls=[],ctx={window:{},location:{origin:'https://review.example.invalid',protocol:'https:'},
    fetch:async(url,opts)=>{
      const path=new URL(url).pathname;calls.push({path,opts});
      const res=await resolver(path,opts);
      const status=Number.isInteger(res?.http_status)?res.http_status:200;
      return {status,ok:status>=200&&status<300,
        headers:{get:k=>k==='content-type'?'application/json':null},
        json:async()=>res?.payload===undefined?res:res.payload};
    }};
  vm.runInNewContext(bridgeSrc,ctx);
  return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const denied=(promise,code)=>assert.rejects(promise,{code});
test('order module is isolated in money page, never baseline owner HTML',()=>{
  assert.match(review,/JWOwnerOrderReview\.render/);
  assert.match(entry,/approved_ui_order_review_v223\.js/);
  assert.doesNotMatch(ui,/innerHTML|localStorage|sessionStorage|indexedDB|eval\(/);
});
test('order context rejects another company and foreign quote source',async()=>{
  const x=serve(path=>path==='/api/me'?user:{...response,order:{...snapshot,org_id:A}});
  await x.bridge.restore();
  await denied(x.bridge.orderReviewContext(C),'INVALID_ORDER_REVIEW_CONTEXT');
  const y=serve(path=>path==='/api/me'?user:{...response,order:{
    ...snapshot,quote_items:[{...quoteLine,id:A}]}});
  await y.bridge.restore();
  await denied(y.bridge.orderReviewContext(C),'INVALID_ORDER_SOURCE');
});
test('order context returns original quote-linked items and fingerprint',async()=>{
  const x=serve(path=>path==='/api/me'?user:response);
  await x.bridge.restore();const r=await x.bridge.orderReviewContext(C);
  assert.equal(r.order.items[0].source_quote_item_id,E);
  assert.equal(r.order.review_state,'clean');
  assert.equal(r.fingerprint,hash);
  assert.equal(x.calls.at(-1).path,'/api/review/orders/'+C+'/edit-context');
});
test('order update sends explicit CSRF POST with only validated fields',async()=>{
  const result={...response,changed:true,order:{
    ...snapshot,review_state:'pending',items:[{...line,quantity:3}],
    money:{subtotal:3000,vat:300,total:3300},
    differences:[{item:'Part',field:'quantity',expected:2,actual:3}]}};
  const x=serve(path=>path==='/api/me'?user:result);await x.bridge.restore();
  const p=await x.bridge.orderReviewSave(C,hash,{
    due_date:'2099-12-30',change_reason:'Customer requested quantity increase',
    items:[{source_quote_item_id:E,name:'Part',quantity:3,unit_price:1000}]});
  assert.equal(p.order.review_state,'pending');assert.equal(p.changed,true);
  const sent=x.calls.at(-1);
  assert.equal(sent.path,'/api/review/orders/'+C+'/update');
  assert.equal(sent.opts.credentials,'same-origin');
  assert.equal(sent.opts.headers['X-CSRF-Token'],user.csrf_token);
  const body=JSON.parse(sent.opts.body);
  assert.deepEqual(Object.keys(body).sort(),['fingerprint','updated']);
  assert.equal(body.updated.items[0].quantity,3);
});
test('reject malformed item, duplicate source and invalid reason before fetch',async()=>{
  const x=serve(path=>path==='/api/me'?user:response);await x.bridge.restore();
  const base={due_date:'2099-12-30',change_reason:'Valid change reason',
    items:[{source_quote_item_id:E,name:'Part',quantity:3,unit_price:1000}]};
  await denied(x.bridge.orderReviewSave(C,hash,{...base,items:[{...base.items[0],quantity:0}]}),'INVALID_ORDER_UPDATE');
  await denied(x.bridge.orderReviewSave(C,hash,{...base,change_reason:'no'}),'INVALID_ORDER_UPDATE');
  await denied(x.bridge.orderReviewSave(C,hash,{...base,items:[base.items[0],base.items[0]]}),'DUPLICATE_ORDER_SOURCE');
  await denied(x.bridge.orderReviewSave(C,'not-hash',base),'INVALID_ORDER_UPDATE');
  assert.equal(x.calls.length,1);
});
test('administrator approval requires CSRF and acknowledged receipt',async()=>{
  const ack={...response,order:{...snapshot,review_state:'acknowledged',
    differences:[{item:'Part',field:'quantity',expected:2,actual:3}]}};
  const x=serve(path=>path==='/api/me'?user:ack);await x.bridge.restore();
  const res=await x.bridge.orderReviewAcknowledge(C,hash);
  assert.equal(res.order.review_state,'acknowledged');
  const sent=x.calls.at(-1);
  assert.equal(sent.path,'/api/review/orders/'+C+'/acknowledge');
  assert.equal(sent.opts.headers['X-CSRF-Token'],user.csrf_token);
  assert.equal(JSON.parse(sent.opts.body).confirm,true);
});
test('non-admin cannot approve or contact network',async()=>{
  const member={...user,role:'member'};
  const x=serve(path=>path==='/api/me'?member:response);
  await x.bridge.restore();
  await denied(x.bridge.orderReviewAcknowledge(C,hash),'ADMIN_ONLY');
  assert.equal(x.calls.length,1);
});
test('server cannot claim acknowledged without approved persisted state',async()=>{
  const x=serve(path=>path==='/api/me'?user:response);await x.bridge.restore();
  await denied(x.bridge.orderReviewAcknowledge(C,hash),'INVALID_ORDER_ACK_RECEIPT');
});
test('stale tenant response never applies to new session',async()=>{
  let release;const pending=new Promise(r=>release=r),current={...user};
  const x=serve(path=>path==='/api/me'?current:pending);
  await x.bridge.restore();
  const old=x.bridge.orderReviewContext(C).then(()=>null,e=>e.code);
  current.id=D;current.org_id=A;
  await x.bridge.restore();
  release(response);
  assert.equal(await old,'STALE_SESSION');
});
test('409 concurrency error is distinct from network error',async()=>{
  const x=serve(path=>path==='/api/me'?user:{http_status:409,payload:{detail:'stale'}});
  await x.bridge.restore();
  await denied(x.bridge.orderReviewSave(C,hash,{
    due_date:'2099-12-30',change_reason:'Valid change reason',
    items:[{source_quote_item_id:E,name:'Part',quantity:3,unit_price:1000}]
  }),'STALE_VERSION');
});
