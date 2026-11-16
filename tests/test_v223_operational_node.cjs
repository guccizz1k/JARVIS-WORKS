'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const bridgeSrc=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const ui=fs.readFileSync('app/static/approved_ui_operational_v223.js','utf8');
const review=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const entry=fs.readFileSync('app/cinema_entry_v1.py','utf8');
const me={id:'a'.repeat(32),org_id:'b'.repeat(32),name:'Owner',email:'qa@example.invalid',role:'admin',org_name:'Synthetic',csrf_token:'z'.repeat(36)};
const id='c'.repeat(32),peer='d'.repeat(32);
const thread={id,other_org_id:peer,other_company:'Peer',status:'active',unread_count:0};
function h(handler){
 const calls=[],ctx={window:{},location:{origin:'https://staging.example.invalid',protocol:'https:'},
 fetch:async(url,opts)=>{
   calls.push({path:new URL(url).pathname,opts});
   let result=await handler(new URL(url).pathname,opts);
   const status=Number.isInteger(result?.status)?result.status:200;
   return {status,ok:status>=200&&status<300,headers:{get:key=>key==='content-type'?'application/json':null},json:async()=>result?.body??result};
 }};
 vm.runInNewContext(bridgeSrc,ctx);
 return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const deny=(p,code)=>assert.rejects(p,{code});
test('safe module loads in review UI before dashboard',()=>{
 assert.ok(entry.indexOf('approved_ui_operational_v223.js')>=0);
 assert.ok(entry.indexOf('approved_ui_operational_v223.js')<entry.indexOf('approved_ui_server_review_v223.js'));
 assert.ok(review.includes('g.JWOwnerOperational.render'));
 assert.doesNotMatch(ui,/innerHTML|localStorage|indexedDB|sessionStorage|eval\(/);
});
test('member cannot access admin endpoint',async()=>{
 const x=h(path=>path==='/api/me'?{...me,role:'member'}:{});
 await x.bridge.restore();
 await deny(x.bridge.securityManageOverview(),'ADMIN_ONLY');
 assert.equal(x.calls.length,1);
});
test('directory validates different tenant',async()=>{
 const x=h(path=>path==='/api/me'?me:[{org_id:me.org_id,company_name:'Self'}]);
 await x.bridge.restore();await deny(x.bridge.messengerDirectory(),'INVALID_DIRECTORY');
});
test('thread creation requires CSRF and non-self org',async()=>{
 const x=h(path=>path==='/api/me'?me:thread);
 await x.bridge.restore();
 await deny(x.bridge.messengerCreateThread(me.org_id),'INVALID_RECIPIENT');
 await x.bridge.messengerCreateThread(peer);
 assert.equal(x.calls.at(-1).path,'/api/messenger/threads');
 assert.equal(x.calls.at(-1).opts.headers['X-CSRF-Token'],me.csrf_token);
});
test('send requires server idempotency key and CSRF',async()=>{
 const x=h(path=>path==='/api/me'?me:{id,version:1});
 await x.bridge.restore();
 await deny(x.bridge.messengerSend(id,'  ',peer),'INVALID_MESSAGE_INPUT');
 await x.bridge.messengerSend(id,'Synthetic',peer);
 assert.equal(x.calls.at(-1).opts.credentials,'same-origin');
 assert.equal(x.calls.at(-1).opts.headers['X-CSRF-Token'],me.csrf_token);
 assert.equal(JSON.parse(x.calls.at(-1).opts.body).request_id,peer);
});
test('foreign org message response refused',async()=>{
 const x=h(path=>path==='/api/me'?me:[{id,connection_id:id,sender_org:'e'.repeat(32),mine:false,kind:'text',body:'Private'}]);
 await x.bridge.restore();await deny(x.bridge.messengerMessages(id,peer),'INVALID_MESSAGES');
});
test('staff self disable refused before network',async()=>{
 const x=h(path=>path==='/api/me'?me:{ok:true});
 await x.bridge.restore();
 await deny(x.bridge.securitySetStaffActive(me.id,false,'pw'),'INVALID_STAFF_ACTION');
 assert.equal(x.calls.length,1);
});
test('staff action uses reauth and CSRF',async()=>{
 const x=h(path=>path==='/api/me'?me:{ok:true});
 await x.bridge.restore();
 await x.bridge.securitySetStaffActive(id,false,'synthetic-only-password');
 const c=x.calls.at(-1);
 assert.equal(c.path,'/api/security/users/'+id+'/disable');
 assert.equal(c.opts.headers['X-CSRF-Token'],me.csrf_token);
 assert.equal(JSON.parse(c.opts.body).admin_password,'synthetic-only-password');
});
test('privileged sessions can only be revoked by admin',async()=>{
 const x=h(path=>path==='/api/me'?me:{ok:true});
 await x.bridge.restore();
 await x.bridge.securityRevokeSession(id);
 assert.equal(x.calls.at(-1).path,'/api/security/sessions/'+id+'/revoke');
});
test('identity switching rejects late tenant data',async()=>{
 let release;
 const delayed=new Promise(r=>{release=r});
 let current=me;
 const x=h(async path=>{
   if(path==='/api/me')return current;
   return delayed;
 });
 await x.bridge.restore();
 const old=x.bridge.messengerThreads().then(()=>null,e=>e.code);
 current={...me,id:'f'.repeat(32),org_id:'0'.repeat(32)};
 await x.bridge.restore();
 release([thread]);
 assert.equal(await old,'STALE_SESSION');
 assert.equal(x.bridge.identity.org_id,current.org_id);
});
