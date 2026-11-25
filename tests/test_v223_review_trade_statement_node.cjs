'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const UI=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const id='a'.repeat(32),statement='b'.repeat(32),org='tenant-1';
const who={id:'u',org_id:org,email:'a@example.invalid',name:'Tester',role:'admin',org_name:'Synthetic',csrf_token:'q'.repeat(36)};
const snap={id:statement,order_id:id,org_id:org,doc_no:'TS-SYNTHETIC',reused:false,document:{source_order_id:id,document_type:'trade_statement',
  legal_status:'internal_business_record_not_tax_invoice',finalized:true,money:{total:275000}}};
const trace={source_order_id:id,scope:'authenticated_tenant_only',order_money:{total:275000},active_paid:0,
  statement_id:statement,events:[{type:'order',id}]};
function setup(handler){
 const calls=[],ctx={window:{},location:{protocol:'https:',origin:'https://isolated.example.invalid'},fetch:async(url,options)=>{
  calls.push({url,options});const data=url.endsWith('/api/me')?who:handler(url,options);
  return {status:200,ok:true,headers:{get:k=>k==='content-type'?'application/json':null},json:async()=>data};
 }};
 vm.runInNewContext(source,ctx);return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
test('authenticated immutable statement create uses CSRF and allowlisted POST',async()=>{
 const {bridge,calls}=setup(()=>snap);await bridge.restore();
 const r=await bridge.statementFromOrder(id);
 assert.equal(r.document.money.total,275000);const post=calls.at(-1);
 assert.equal(post.options.method,'POST');
 assert.equal(post.options.headers['X-CSRF-Token'],who.csrf_token);
 assert.equal(post.url,'https://isolated.example.invalid/api/automation/statements/from-order');
 assert.equal(JSON.parse(post.options.body).order_id,id);
});
test('fail closed on cross-org statement response',async()=>{
 const {bridge}=setup(()=>({...snap,org_id:'tenant-2'}));await bridge.restore();
 await assert.rejects(()=>bridge.statementFromOrder(id),{code:'TENANT_MISMATCH'});
});
test('cannot create statement for forged id before hitting network',async()=>{
 const {bridge,calls}=setup(()=>snap);await bridge.restore();
 await assert.rejects(()=>bridge.statementFromOrder('../etc/passwd'),{code:'INVALID_ORDER_ID'});
 assert.equal(calls.length,1);
});
test('statement response must reflect immutable internal document',async()=>{
 const {bridge}=setup(()=>({...snap,document:{...snap.document,legal_status:'tax_invoice'}}));
 await bridge.restore();
 await assert.rejects(()=>bridge.statementFromOrder(id),{code:'INVALID_STATEMENT_RESPONSE'});
});
test('statement detail rechecked against server, org, original order',async()=>{
 const {bridge}=setup(()=>snap);await bridge.restore();const result=await bridge.statementDetail(statement,id);
 assert.equal(result.doc_no,'TS-SYNTHETIC');
});
test('cross-tenant statement detail refused',async()=>{
 const {bridge}=setup(()=>({...snap,org_id:'other'}));await bridge.restore();
 await assert.rejects(()=>bridge.statementDetail(statement,id),{code:'STATEMENT_IDENTITY_MISMATCH'});
});
test('trace rejects mismatched order and source',async()=>{
 const {bridge}=setup(()=>({...trace,source_order_id:'c'.repeat(32)}));await bridge.restore();
 await assert.rejects(()=>bridge.orderTransactionTrace(id),{code:'INVALID_TRANSACTION_TRACE'});
});
test('trace allows only expected event types and source',async()=>{
 const {bridge}=setup(()=>trace);await bridge.restore();
 const result=await bridge.orderTransactionTrace(id);assert.equal(result.statement_id,statement);
});
test('review UI requires explicit user action and server readback',()=>{
 assert.match(UI,/dataset\.action='statement-from-order'/);
 assert.match(UI,/window\.confirm\(/);
 assert.match(UI,/await bridge\.statementFromOrder\(order\.id\)/);
 assert.match(UI,/await bridge\.statementDetail\(created\.id,order\.id\)/);
 assert.match(UI,/await bridge\.orderTransactionTrace\(order\.id\)/);
 assert.doesNotMatch(UI,/localStorage|indexedDB|innerHTML|eval\(/);
});
