'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const code=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const ui=fs.readFileSync('app/static/approved_ui_profile_v223.js','utf8');
const review=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const operational=fs.readFileSync('app/static/approved_ui_operational_v223.js','utf8');
const entry=fs.readFileSync('app/cinema_entry_v1.py','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32);
const me={id:A,org_id:B,email:'a@example.invalid',name:'Synthetic',org_name:'Company',role:'admin',csrf_token:'z'.repeat(36)};
const prefs={user_id:A,org_id:B,compact_view:false,messenger_auto_refresh:true,version:0};
const profile={id:A,org_id:B,email:me.email,name:me.name,org_name:me.org_name,role:me.role,version:0};
function env(resolver){
 const calls=[],location={origin:'https://isolated.example.invalid',protocol:'https:'};
 const ctx={window:{},location,fetch:async(url,options)=>{
    const path=new URL(url).pathname;
    calls.push({path,options});
    const reply=await resolver(path,options);
    const status=Number.isInteger(reply?.status)?reply.status:200;
    return {status,ok:status>=200&&status<300,
      headers:{get:k=>k==='content-type'?'application/json':null},
      json:async()=>reply?.payload===undefined?reply:reply.payload};
 }};
 vm.runInNewContext(code,ctx);
 return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const rejected=(promise,code)=>assert.rejects(promise,{code});
test('profile and settings route registered only in separate review modules',()=>{
 assert.ok(review.includes("['account','settings'].includes(key)"));
 assert.ok(review.includes('JWOwnerProfile.render'));
 assert.ok(entry.includes('approved_ui_profile_v223.js'));
 assert.ok(entry.includes('approved_ui_profile_v223.css'));
 assert.doesNotMatch(ui,/innerHTML|localStorage|indexedDB|sessionStorage|eval\(/);
});
test('profile GET validates authenticated user',async()=>{
 const x=env(p=>p==='/api/me'?me:profile);await x.bridge.restore();
 const p=await x.bridge.profileRead();assert.equal(p.version,0);
 assert.equal(p.org_id,B);assert.equal(p.name,'Synthetic');
 assert.equal(x.calls.at(-1).options.credentials,'same-origin');
});
test('profile write CSRF, name update, and version',async()=>{
 const x=env((p,opt)=>p==='/api/me'?me:({...profile,name:'Renamed',version:1}));
 await x.bridge.restore();const p=await x.bridge.profileSave('Renamed',0);
 assert.equal(p.name,'Renamed');assert.equal(p.version,1);
 assert.equal(x.bridge.identity.name,'Renamed');
 const sent=x.calls.at(-1);assert.equal(sent.path,'/api/account/profile');
 assert.equal(sent.options.headers['X-CSRF-Token'],me.csrf_token);
 assert.equal(JSON.parse(sent.options.body).version,0);
});
test('409 profile version mismatch reports actionable stale error',async()=>{
 const x=env(p=>p==='/api/me'?me:{status:409,payload:{detail:'stale'}});
 await x.bridge.restore();await rejected(x.bridge.profileSave('Renamed',0),'STALE_VERSION');
});
test('profile refuse cross-tenant user substitution',async()=>{
 const x=env(p=>p==='/api/me'?me:{...profile,org_id:C});
 await x.bridge.restore();await rejected(x.bridge.profileRead(),'INVALID_PROFILE');
});
test('profile reject malformed fields before issuing a write',async()=>{
 const x=env(p=>p==='/api/me'?me:profile);
 await x.bridge.restore();
 await rejected(x.bridge.profileSave('',0),'INVALID_PROFILE_INPUT');
 await rejected(x.bridge.profileSave('x'.repeat(81),0),'INVALID_PROFILE_INPUT');
 await rejected(x.bridge.profileSave('test',-1),'INVALID_PROFILE_INPUT');
 assert.equal(x.calls.length,1);
});
test('preferences GET validates both boolean fields',async()=>{
 const x=env(p=>p==='/api/me'?me:prefs);
 await x.bridge.restore();const p=await x.bridge.preferencesRead();
 assert.equal(p.messenger_auto_refresh,true);assert.equal(p.compact_view,false);
});
test('preferences POST has scoped JSON, CSRF and readback result',async()=>{
 const x=env(p=>p==='/api/me'?me:{...prefs,compact_view:true,messenger_auto_refresh:false,version:1});
 await x.bridge.restore();
 const p=await x.bridge.preferencesSave({compact_view:true,messenger_auto_refresh:false,version:0});
 assert.equal(p.version,1);
 const sent=x.calls.at(-1);assert.equal(sent.path,'/api/account/preferences');
 assert.equal(sent.options.headers['X-CSRF-Token'],me.csrf_token);
 assert.equal(JSON.parse(sent.options.body).messenger_auto_refresh,false);
});
test('preferences reject string toggles and unknown missing version',async()=>{
 const x=env(p=>p==='/api/me'?me:prefs);await x.bridge.restore();
 await rejected(x.bridge.preferencesSave({version:0,compact_view:'true',messenger_auto_refresh:true}),'INVALID_PREFERENCES_INPUT');
 await rejected(x.bridge.preferencesSave({compact_view:false,messenger_auto_refresh:true}),'INVALID_PREFERENCES_INPUT');
 assert.equal(x.calls.length,1);
});
test('cross-company preferences denied',async()=>{
 const x=env(p=>p==='/api/me'?me:{...prefs,org_id:C});await x.bridge.restore();
 await rejected(x.bridge.preferencesRead(),'INVALID_PREFERENCES');
});
test('unauthenticated profile and preferences make zero requests',async()=>{
 const x=env(()=>null);
 await rejected(x.bridge.profileRead(),'LOGIN_REQUIRED');
 await rejected(x.bridge.preferencesRead(),'LOGIN_REQUIRED');
 assert.equal(x.calls.length,0);
});
test('stale profile read cannot update newly authenticated session',async()=>{
 let release;
 let curr=me;
 const pending=new Promise(r=>{release=r});
 const x=env(p=>p==='/api/me'?curr:pending);
 await x.bridge.restore();
 const old=x.bridge.profileRead().then(()=>null,e=>e.code);
 curr={...me,id:C,org_id:C};
 await x.bridge.restore();
 release(profile);
 assert.equal(await old,'STALE_SESSION');
 assert.equal(x.bridge.identity.id,C);
});
test('messenger change signals are scoped and browser-local drafts preserved',()=>{
 assert.ok(operational.includes("'/api/messenger/threads/'+thread.id+'/events'"));
 assert.ok(operational.includes("source.addEventListener('change'"));
 assert.ok(operational.includes("source.addEventListener('revoked'"));
 assert.ok(operational.includes("Math.min(retryMs*2,30000)"));
 assert.ok(operational.includes('setInterval('));
 assert.ok(operational.includes('previousThread===thread.id'));
 assert.ok(operational.includes('g.JWOwnerOperational={render,dispose,randomRequestId}'));
 assert.ok(review.includes('g.JWOwnerOperational?.dispose?.()'));
});
