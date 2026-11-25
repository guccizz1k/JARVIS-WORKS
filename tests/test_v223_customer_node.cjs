'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const bridgeSrc=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const uiSrc=fs.readFileSync('app/static/approved_ui_customer_edit_v223.js','utf8');
const review=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const entry=fs.readFileSync('app/cinema_entry_v1.py','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),D='d'.repeat(32);
const me={id:A,org_id:B,email:'qa@example.invalid',name:'Review Admin',role:'admin',org_name:'Test',
  csrf_token:'z'.repeat(36)};
const customer={id:C,org_id:B,name:'Customer',business_number:'',contact_name:'',
  email:'',phone:'',created_at:'2026-11-16T09:00:00+09:00'};
function server(resolver) {
  const calls=[],ctx={window:{},location:{origin:'https://review.example.invalid',protocol:'https:'},
   fetch:async(url,opts)=>{
    const path=new URL(url).pathname;calls.push({path,opts});
    const result=await resolver(path,opts);
    const status=Number.isInteger(result?.status)?result.status:200;
    return {status,ok:status>=200&&status<300,
      headers:{get:key=>key==='content-type'?'application/json':null},
      json:async()=>result?.payload===undefined?result:result.payload};
   }};
  vm.runInNewContext(bridgeSrc,ctx);
  return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const deny=(promise,code)=>assert.rejects(promise,{code});
class El {
  constructor(tag){this.tagName=tag;this.className='';this.children=[];this.attributes={};this.textContent='';this.value='';this.disabled=false;this.hidden=false;this.listeners={};}
  append(...v){this.children.push(...v)}
  setAttribute(k,v){this.attributes[k]=v}
  addEventListener(k,fn){this.listeners[k]=fn}
}
function find(n,p){if(p(n))return n;for(const c of n.children){const v=find(c,p);if(v)return v;}return null;}
function ui(bridge){
  const context={window:{},document:{createElement:t=>new El(t)}};
  vm.runInNewContext(uiSrc,context);
  const view=new El('div');
  return {view,render:()=>context.window.JWOwnerCustomerEdit.render({
    bridge,view,isCurrent:()=>true})};
}
test('customer editor loads only in protected partners panel',()=>{
  assert.ok(review.includes('JWOwnerCustomerEdit.render'));
  assert.ok(review.includes("if(key==='partners')"));
  assert.ok(entry.includes('approved_ui_customer_edit_v223.js'));
  assert.doesNotMatch(uiSrc,/innerHTML|localStorage|indexedDB|sessionStorage|eval\(/);
});
test('customer edit sends allowlisted POST with CAS and csrf',async()=>{
  const x=server(path=>path==='/api/me'?me:{...customer,name:'After'});
  await x.bridge.restore();
  const r=await x.bridge.customerEdit(C,customer,{...customer,name:'After'});
  assert.equal(r.name,'After');
  const last=x.calls.at(-1);
  assert.equal(last.path,'/api/review/customers/'+C+'/update');
  assert.equal(last.opts.credentials,'same-origin');
  assert.equal(last.opts.headers['X-CSRF-Token'],me.csrf_token);
  const body=JSON.parse(last.opts.body);
  assert.equal(body.expected.name,'Customer');
  assert.equal(body.updated.name,'After');
  assert.deepEqual(Object.keys(body.expected).sort(),['business_number','contact_name','email','name','phone'].sort());
});
test('cross tenant original rejected before network',async()=>{
  const x=server(path=>path==='/api/me'?me:null);
  await x.bridge.restore();
  await deny(x.bridge.customerEdit(C,{...customer,org_id:D},{...customer,name:'After'}),'TENANT_MISMATCH');
  assert.equal(x.calls.length,1);
});
test('invalid id fields and email rejected before network',async()=>{
  const x=server(path=>path==='/api/me'?me:null);
  await x.bridge.restore();
  await deny(x.bridge.customerEdit('bad',customer,customer),'INVALID_CUSTOMER_ID');
  await deny(x.bridge.customerEdit(C,customer,{...customer,name:''}),'INVALID_CUSTOMER_PAYLOAD');
  await deny(x.bridge.customerEdit(C,customer,{...customer,email:'not-an-email'}),'INVALID_CUSTOMER_PAYLOAD');
  assert.equal(x.calls.length,1);
});
test('server mismatch response blocked',async()=>{
  const x=server(path=>path==='/api/me'?me:{...customer,org_id:D});
  await x.bridge.restore();
  await deny(x.bridge.customerEdit(C,customer,customer),'TENANT_MISMATCH');
});
test('CAS conflict 409 never claims success',async()=>{
  const x=server(path=>path==='/api/me'?me:{status:409,payload:{detail:'stale'}});
  await x.bridge.restore();
  await deny(x.bridge.customerEdit(C,customer,customer),'STALE_VERSION');
});
test('stale session response cannot affect another tenant',async()=>{
  let release;const pending=new Promise(r=>release=r);let user=me;
  const x=server(path=>path==='/api/me'?user:pending);
  await x.bridge.restore();
  const old=x.bridge.customerEdit(C,customer,customer).then(()=>null,e=>e.code);
  user={...me,id:D,org_id:D};await x.bridge.restore();
  release(customer);
  assert.equal(await old,'STALE_SESSION');
});
test('customer UI form saves only after server readback, never synthesizes success',async()=>{
  const updated={...customer,name:'Readback Good'};
  let saved=false;
  const bridge={identity:me,signedIn:true,
    list:async()=>[saved?updated:customer],
    customerEdit:async(id,original,fields)=>{
      assert.equal(id,C);assert.equal(original.name,'Customer');
      assert.equal(fields.name,'Readback Good');saved=true;return updated;
    }};
  const x=ui(bridge);await x.render();
  const form=find(x.view,n=>n.tagName==='form'),input=find(form,n=>n.tagName==='input'&&n.name==='name');
  assert.ok(form);input.value='Readback Good';
  await form.listeners.submit({preventDefault(){}});
  assert.equal(saved,true);
  const status=find(form,n=>n.attributes.role==='status');
  assert.ok(status.textContent.includes('재조회 완료'));
});
test('stale CAS UI surfaces warning, not success',async()=>{
  const bridge={identity:me,signedIn:true,list:async()=>[customer],
    customerEdit:async()=>{const e=new Error('stale');e.code='STALE_VERSION';throw e}};
  const x=ui(bridge);await x.render();const form=find(x.view,n=>n.tagName==='form');
  await form.listeners.submit({preventDefault(){}});
  const alert=find(form,n=>n.attributes.role==='alert');
  assert.ok(alert.textContent.includes('다른 사용자가 거래처를 변경했습니다'));
});
