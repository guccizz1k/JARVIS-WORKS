'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const code=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
function setup(handler){
 const calls=[],location={origin:'https://stage.example.invalid',protocol:'https:'};
 const fetch=async(url,init)=>{calls.push({url,init});const [data,status=200]=handler(url,init);return {
  ok:status>=200&&status<300,status,headers:{get:x=>x==='content-type'?'application/json':null},json:async()=>data}};
 const ctx={window:{},globalThis:{},location,fetch,console};
 vm.runInNewContext(code,ctx);
 const bridge=new ctx.window.JWOwnerServerBridge();
 return {bridge,calls};
}
const me={id:'u1',org_id:'org1',email:'fake@example.invalid',name:'Member',role:'member',org_name:'Isolated',csrf_token:'a'.repeat(36)};
test('member role accepted and cookies remain browser-owned',async()=>{
 const {bridge,calls}=setup(url=>url.endsWith('/api/me')?[me]:[[{org_id:'org1',name:'Customer'}]]);
 assert.equal((await bridge.restore()).role,'member');
 assert.equal((await bridge.list('customers')).length,1);
 assert.equal(calls[0].init.credentials,'same-origin');
 assert.equal(bridge.identity.csrf_token,undefined);
});
test('cross tenant response is denied',async()=>{
 const {bridge}=setup(url=>url.endsWith('/api/me')?[me]:[[{org_id:'other'}]]);
 await bridge.restore();
 await assert.rejects(()=>bridge.list('customers'),{code:'TENANT_MISMATCH'});
});
test('credentials required for login; never downgrade origin',async()=>{
 const {bridge}=setup(()=>[me]);
 await assert.rejects(()=>bridge.login('',''),{code:'CREDENTIALS_REQUIRED'});
 await assert.rejects(()=>bridge.list('unverified'),{code:'LOGIN_REQUIRED'});
});
test('fail closed after session 401',async()=>{
 const {bridge}=setup(url=>url.endsWith('/api/me')?[me]:[{detail:'no'},401]);
 await bridge.restore();await assert.rejects(()=>bridge.list('customers'),{code:'SESSION_EXPIRED'});assert.equal(bridge.signedIn,false);
});
test('review UI navigation has 17 options and no local database fallback',()=>{
 const s=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
 assert.match(s,/const MENUS=/);assert.doesNotMatch(s,/localStorage|indexedDB|sessionStorage/);
 const m=s.match(/const MENUS=([\s\S]*?);/);assert.ok(m);
 const routes=Array.from(m[1].matchAll(/\['([a-z]+)','/g)).map(x=>x[1]);
 assert.equal(routes.length,17);assert.equal(new Set(routes).size,17);
});
