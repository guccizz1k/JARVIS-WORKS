'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const ui=fs.readFileSync('app/static/approved_ui_statement_list_v223.js','utf8');
const review=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const entry=fs.readFileSync('app/cinema_entry_v1.py','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),D='d'.repeat(32);
const me={id:A,org_id:B,name:'Synthetic',org_name:'A Org',email:'a@example.invalid',role:'admin',csrf_token:'z'.repeat(36)};
const row={id:C,org_id:B,order_id:D,doc_no:'TS-C00000000000',created_at:'2026-11-16T00:00:00+09:00'};
function setup(handler){
 const calls=[],ctx={window:{},location:{origin:'https://isolated.example.invalid',protocol:'https:'},
 fetch:async(url,options)=>{
   const path=new URL(url).pathname;calls.push({path,options});
   const data=handler(path,options);
   return{status:200,ok:true,headers:{get:n=>n==='content-type'?'application/json':null},json:async()=>data};
 }};
 vm.runInNewContext(source,ctx);return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const deny=(promise,code)=>assert.rejects(promise,{code});
test('papers route is a real server module, not a quote-only placeholder',()=>{
 assert.ok(review.includes("if(key==='papers')"));
 assert.ok(review.includes('JWOwnerStatements.render'));
 assert.ok(entry.includes('approved_ui_statement_list_v223.js'));
 assert.doesNotMatch(ui,/innerHTML|localStorage|indexedDB|sessionStorage|eval\(/);
});
test('actual statement list requires signed-in session',async()=>{
 const x=setup(()=>[]);await deny(x.bridge.statementList(),'LOGIN_REQUIRED');assert.equal(x.calls.length,0);
});
test('only authenticated org records accepted with no arbitrary API path',async()=>{
 const x=setup(path=>path==='/api/me'?me:[row]);await x.bridge.restore();
 const rows=await x.bridge.statementList();assert.equal(rows[0].id,C);
 assert.equal(x.calls.at(-1).path,'/api/automation/statements');
 assert.equal(x.calls.at(-1).options.credentials,'same-origin');
});
test('cross-org statement in list fails closed',async()=>{
 const x=setup(path=>path==='/api/me'?me:[{...row,org_id:'e'.repeat(32)}]);
 await x.bridge.restore();await deny(x.bridge.statementList(),'INVALID_STATEMENT_LIST');
});
test('tampered immutable source/order identifiers fail closed',async()=>{
 const x=setup(path=>path==='/api/me'?me:[{...row,order_id:'bad'}]);
 await x.bridge.restore();await deny(x.bridge.statementList(),'INVALID_STATEMENT_LIST');
});
test('oversized statement list is refused',async()=>{
 const x=setup(path=>path==='/api/me'?me:Array.from({length:101},()=>row));
 await x.bridge.restore();await deny(x.bridge.statementList(),'INVALID_STATEMENT_LIST');
});
test('read-only statement UI renders verified document and no writes',async()=>{
 class El{
  constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.textContent='';this.disabled=false;this.attributes={};}
  append(...a){this.children.push(...a)}replaceChildren(...a){this.children=[...a]}
  setAttribute(k,v){this.attributes[k]=v}
 }
 const find=(n,p)=>{if(p(n))return n;for(const child of n.children){const result=find(child,p);if(result)return result}return null};
 const ctx={window:{},document:{createElement:t=>new El(t)}};
 vm.runInNewContext(ui,ctx);
 const commands=[],bridge={
  identity:{id:A,org_id:B},signedIn:true,
  statementList:async()=>[row],
  statementDetail:async(id,order)=>{commands.push({id,order});return{
   ...row,document:{document_type:'trade_statement',finalized:true,
    legal_status:'internal_business_record_not_tax_invoice',
    source_order_no:'ORD-001',customer_name:'Synthetic Customer',title:'Parts',
    money:{total:500},items:[{name:'Part',quantity:1,line_total:500}]}
  }}
 };
 const view=new El('div');
 await ctx.window.JWOwnerStatements.render({bridge,view,isCurrent:()=>true});
 const button=find(view,n=>n.tag==='button');assert.ok(button);
 await button.onclick();
 assert.deepEqual(commands,[{id:C,order:D}]);
 assert.ok(find(view,n=>n.textContent.includes('Synthetic Customer')));
});
