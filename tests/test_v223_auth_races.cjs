'use strict';
const test=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const rejects=(promise,expected)=>assert.rejects(Promise.race([promise,new Promise((_,reject)=>setTimeout(()=>reject(Object.assign(Error('Expected prompt refusal'),{code:'REFUSAL_TIMEOUT'})),100))]),expected);
const code=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const identity=(id='a',org='org1')=>({id,org_id:org,email:id+'@example.invalid',name:id,role:'member',org_name:org,csrf_token:id.repeat(36)});
const deferred=()=>{let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}};
const response=(data,status=200)=>({ok:status>=200&&status<300,status,headers:{get:k=>k==='content-type'?'application/json':null},json:async()=>data});
function setup(handler){const calls=[];const ctx={window:{},location:{origin:'https://isolated.example.invalid',protocol:'https:'},fetch:async(url,init)=>{calls.push({url,init});return handler(url,init)},console};vm.runInNewContext(code,ctx);return {bridge:new ctx.window.JWOwnerServerBridge(),calls};}
const tick=()=>new Promise(r=>setImmediate(r));
async function race(status,org='org1'){
 let who=identity(),pending=deferred();
 const {bridge}=setup((url)=>url.endsWith('/me')?response(who):url.endsWith('/login')?response({user:who}):pending.promise);
 await bridge.restore();const old=bridge.list('customers');const denied=rejects(old,{code:'STALE_SESSION'});
 who=identity('b',org);await bridge.login('b','synthetic input');pending.resolve(response([{org_id:'org1',owner:'a'}],status));await denied;
 assert.equal(bridge.identity.id,'b');assert.equal(bridge.identity.org_id,org);return bridge;
}
test('A concurrent login is refused before second cookie-setting POST',async()=>{
 const pending=deferred();const {bridge,calls}=setup(url=>url.endsWith('/login')?pending.promise:response(identity()));
 const first=bridge.login('a','synthetic input');
 await rejects(bridge.login('b','synthetic input'),{code:'AUTH_BUSY'});
 pending.resolve(response({user:identity()}));await first;
 assert.equal(calls.filter(c=>c.url.endsWith('/login')).length,1);
});
test('B stale 401 cannot clear newly logged-in identity',async()=>{await race(401)});
test('C same-company different-user response is rejected',async()=>{await race(200)});
test('C cross-company response is rejected before data is returned',async()=>{await race(200,'org2')});
test('logout blocks writes and login until cookie transition settles',async()=>{
 const pending=deferred();const {bridge,calls}=setup(url=>url.endsWith('/me')?response(identity()):pending.promise);
 await bridge.restore();const logout=bridge.logout();
 await rejects(bridge.write('/api/customers',{name:'synthetic'}),{code:'AUTH_BUSY'});
 await rejects(bridge.login('b','synthetic input'),{code:'AUTH_BUSY'});
 pending.resolve(response({ok:true}));await logout;assert.equal(bridge.signedIn,false);
 assert.equal(calls.length,2);
});
test('network failure releases transition lock and allows recovery',async()=>{
 let failed=true;const {bridge}=setup(url=>{if(failed)throw Error('synthetic network');return response(url.endsWith('/login')?{user:identity()}:identity())});
 await rejects(bridge.login('a','synthetic input'),{code:'NETWORK_ERROR'});
 assert.equal(bridge.signedIn,false);failed=false;await bridge.login('a','synthetic input');assert.equal(bridge.identity.id,'a');
});
test('normal business POST retains same-origin cookie and CSRF protections',async()=>{
 const {bridge,calls}=setup(url=>response(url.endsWith('/me')?identity():{org_id:'org1',id:'row'}));await bridge.restore();await bridge.write('/api/customers',{name:'synthetic'});
 const init=calls.at(-1).init;assert.equal(init.headers['X-CSRF-Token'],identity().csrf_token);assert.equal(init.credentials,'same-origin');assert.equal(init.redirect,'error');assert.equal(bridge.identity.csrf_token,undefined);
});
test('unauthenticated business request never reaches fetch',async()=>{const {bridge,calls}=setup(()=>{throw Error('unexpected')});await rejects(bridge.list('customers'),{code:'LOGIN_REQUIRED'});assert.equal(calls.length,0)});
test('current session expiry clears identity and permits fresh login',async()=>{
 let expired=false;const {bridge}=setup(url=>url.endsWith('/me')?response(identity()):url.endsWith('/login')?response({user:identity()}):response({},expired?401:200));await bridge.restore();expired=true;await rejects(bridge.list('customers'),{code:'SESSION_EXPIRED'});assert.equal(bridge.signedIn,false);await bridge.login('a','synthetic input');assert.equal(bridge.identity.id,'a');
});
test('late JSON body cannot escape epoch check after identity transition',async()=>{
 let who=identity(),body=deferred();const {bridge}=setup(url=>url.endsWith('/me')?response(who):url.endsWith('/login')?response({user:who}):{...response(null),json:()=>body.promise});await bridge.restore();const old=bridge.list('customers');const denied=rejects(old,{code:'STALE_SESSION'});await tick();who=identity('b');await bridge.login('b','synthetic input');body.resolve([{org_id:'org1',owner:'a'}]);await denied;assert.equal(bridge.identity.id,'b');
});
test('restore cannot race login or another restore',async()=>{
 const pending=deferred();const {bridge,calls}=setup(()=>pending.promise);const restore=bridge.restore();await rejects(bridge.restore(),{code:'AUTH_BUSY'});await rejects(bridge.login('a','synthetic input'),{code:'AUTH_BUSY'});pending.resolve(response(identity()));await restore;assert.equal(calls.length,1);
});

test('partial login failure still revokes the actual server session on logout',async()=>{
 let failMe=true;const {bridge,calls}=setup(url=>{if(url.endsWith('/login'))return response({user:identity()});if(url.endsWith('/me')){if(failMe){failMe=false;throw Error('lost identity response')}return response(identity())}return response({ok:true})});
 await rejects(bridge.login('a','synthetic input'),{code:'NETWORK_ERROR'});assert.equal(bridge.signedIn,false);await bridge.logout();assert.equal(calls.filter(c=>c.url.endsWith('/logout')).length,1);
});
test('UI never reports confirmed server logout after a transport failure',async()=>{
 const ui=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');const match=ui.match(/logout\.onclick=(async\(\)=>\{[^\n]+\});/);assert.ok(match);let note='';
 const handler=vm.runInNewContext('('+match[1]+')',{bridge:{logout:async()=>{throw Error('offline')}},entry:v=>note=v});await handler();assert.notEqual(note,'서버에서 로그아웃했습니다.');assert.match(note,/확인하지 못/);
});
