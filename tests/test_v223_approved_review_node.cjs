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

test('business write allowlist rejects arbitrary or cross-tenant target',async()=>{
 const {bridge,calls}=setup(url=>url.endsWith('/api/me')?[me]:[{org_id:'org1',id:'record'}]);
 await bridge.restore();
 await assert.rejects(()=>bridge.write('/api/admin/secrets',{}),{code:'WRITE_NOT_ALLOWLISTED'});
 await assert.rejects(()=>bridge.write('/api/customers',[]),{code:'INVALID_WRITE_PAYLOAD'});
 await assert.rejects(()=>bridge.write('/api/quotes/../../status',{status:'accepted'}),{code:'WRITE_NOT_ALLOWLISTED'});
 assert.equal(calls.length,1);
});
test('same-company business write uses server CSRF and same-origin session',async()=>{
 const {bridge,calls}=setup(url=>url.endsWith('/api/me')?[me]:[{org_id:'org1',id:'customer'}]);
 await bridge.restore();
 let row=await bridge.write('/api/customers',{name:'SYNTHETIC ONLY'});
 assert.equal(row.org_id,'org1');
 const post=calls.at(-1).init;
 assert.equal(post.method,'POST');
 assert.equal(post.credentials,'same-origin');
 assert.equal(post.cache,'no-store');
 assert.equal(post.headers['X-CSRF-Token'],me.csrf_token);
 assert.equal(JSON.stringify(bridge.identity).includes(me.csrf_token),false);
});
test('write result for a different organization is rejected without returning it',async()=>{
 const {bridge}=setup(url=>url.endsWith('/api/me')?[me]:[{org_id:'org2',id:'private'}]);
 await bridge.restore();
 await assert.rejects(()=>bridge.write('/api/customers',{name:'A'}),{code:'TENANT_MISMATCH'});
});
test('unauthenticated write refuses without a network request',async()=>{
 const {bridge,calls}=setup(()=>[{org_id:'org1'}]);
 await assert.rejects(()=>bridge.write('/api/customers',{name:'A'}),{code:'LOGIN_REQUIRED'});
 assert.equal(calls.length,0);
});

test('review business forms are user initiated, CSRF-gated and never use browser local storage',()=>{
 const s=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
 for(const path of ['/api/customers','/api/quotes','/api/orders/from-quote','/api/invoices/from-order'])
   assert.ok(s.includes(path),'missing UI server action '+path);
 assert.match(s,/bridge\.write/);
 assert.doesNotMatch(s,/localStorage|indexedDB|sessionStorage|innerHTML|eval\(/);
});
