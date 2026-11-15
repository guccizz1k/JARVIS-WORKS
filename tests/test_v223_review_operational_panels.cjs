'use strict';
const {test}=require('node:test'), assert=require('node:assert/strict'), fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const identity={id:'u',org_id:'A',email:'a@invalid.example',name:'User',role:'admin',org_name:'Test',csrf_token:'z'.repeat(36)};
function harness(response,me=identity){
 const calls=[],ctx={window:{},location:{protocol:'https:',origin:'https://isolated.example'},
 fetch:async(url,init)=>{calls.push({url,init});const data=url.endsWith('/api/me')?me:response(url,init);
 return {status:200,ok:true,headers:{get:k=>k==='content-type'?'application/json':null},json:async()=>data};}};
 vm.runInNewContext(source,ctx);
 return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
test('server dashboard reads no fake financial data',async()=>{
 const d={customers:2,quotes:1,orders:1,invoices:1,outstanding:125000,collected:0,quote_total:250000,issues:[]};
 const t={status:'NOT_MEASURED',samples:{manual:0,automated:0},observed_difference_ms:null};
 const {bridge,calls}=harness(url=>url.endsWith('dashboard')?d:t);
 await bridge.restore();const r=await bridge.readPanel('stats');
 assert.equal(r.money.outstanding,125000);assert.equal(r.measured,false);assert.equal(r.observed_difference_ms,null);
 assert.deepEqual(calls.slice(1).map(x=>new URL(x.url).pathname),['/api/dashboard','/api/automation/time-savings']);
 assert.ok(calls.every(x=>x.init.method==='GET'&&x.init.credentials==='same-origin'));
});
test('audit rejects foreign org rows before showing',async()=>{
 const {bridge}=harness(()=>[{id:'other',org_id:'B',actor_name:'secret'}]);await bridge.restore();
 await assert.rejects(()=>bridge.readPanel('activity'),{code:'TENANT_MISMATCH'});
});
test('manager overview forbidden for member before network',async()=>{
 const {bridge,calls}=harness(()=>({}),{...identity,role:'member'});await bridge.restore();
 await assert.rejects(()=>bridge.readPanel('security'),{code:'ADMIN_ONLY'});
 assert.equal(calls.length,1);
});
test('never permits a user-selected arbitrary endpoint',async()=>{
 const {bridge,calls}=harness(()=>[]);await bridge.restore();
 await assert.rejects(()=>bridge.readPanel('/api/security/users'),{code:'READ_NOT_ALLOWLISTED'});
 assert.equal(calls.length,1);
});
test('queue is server-provided data only and supports empty response',async()=>{
 const {bridge}=harness(()=>({items:[]}));await bridge.restore();
 assert.equal((await bridge.readPanel('inbox')).length,0);
});
test('messenger validates unread counts and partner',async()=>{
 const {bridge}=harness(()=>[{id:'thread',other_company:'Test B',other_org_id:'B',status:'active',unread_count:3}]);
 await bridge.restore();assert.equal((await bridge.readPanel('messenger'))[0].unread_count,3);
});
test('messenger refuses same org as conversation partner',async()=>{
 const {bridge}=harness(()=>[{id:'thread',other_company:'Self',other_org_id:'A',unread_count:3}]);
 await bridge.restore();await assert.rejects(()=>bridge.readPanel('messenger'),{code:'INVALID_THREADS'});
});
test('invalid dashboard fails closed and does not infer fake metrics',async()=>{
 const {bridge}=harness(()=>({customers:'2',quotes:1,orders:1,invoices:1,outstanding:0,collected:0,quote_total:0,issues:[]}));
 await bridge.restore();await assert.rejects(()=>bridge.readPanel('stats'),{code:'INVALID_STATISTICS'});
});
test('review UI has no unsafe HTML insertion and no fake numbers',()=>{
 const src=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
 assert.ok(src.includes("bridge.readPanel(key)"));
 assert.doesNotMatch(src,/innerHTML|localStorage|indexedDB|sessionStorage|eval\(/);
 for(const k of ['activity','messenger','stats','automation','docs','inbox','security'])
   assert.ok(src.includes("'"+k+"'"));
});
