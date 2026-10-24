'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {test}=require('node:test');
const html=fs.readFileSync(__dirname+'/messenger_stage_v90.html','utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const a=script.indexOf(' const join=()=>{'),b=script.indexOf(' const selectCompany=async(',a);
assert(a>=0 && b>a, 'WebSocket join handler must be in the real browser source');
function harness(){
 const sockets=[],timers=[],statuses=[],notices=[];
 class FakeSocket {
  constructor(url){this.url=url;this.readyState=1;sockets.push(this)}
  close(){this.closed=true}
 }
 FakeSocket.OPEN=1;
 const st={chat:'conn-A-B',nonce:11,attempt:0,socket:null,cursor:0,editAt:'1970-01-01T00:00:00+00:00',editId:''};
 const env={st,API:'/api/pg-stage/v90',WebSocket:FakeSocket,URLSearchParams,location:{protocol:'https:',host:'example.test'},
  connected:(s)=>statuses.push(s),msg:(s)=>notices.push(s),
  render:()=>{},applyEdit:()=>{},markRead:()=>{},
  setTimeout:(fn,ms)=>{timers.push({fn,ms});return timers.length},
 };
 const join=vm.runInNewContext(script.slice(a,b)+'\njoin',env);
 return {st,join,sockets,timers,statuses,notices};
}
test('an older socket close does not schedule a duplicate current-chat reconnect',()=>{
 const h=harness();h.join();const first=h.sockets[0];h.join();
 first.onclose({code:1006});assert.equal(h.timers.length,0);
 assert.equal(h.st.socket,h.sockets[1]);
});
test('an older socket open does not change status or reset retry counter',()=>{
 const h=harness();h.join();const first=h.sockets[0];h.join();h.st.attempt=4;
 const count=h.statuses.length;first.onopen();
 assert.equal(h.st.attempt,4);assert.equal(h.statuses.length,count);
});
test('rapid open-close loops stop after six failed reconnect attempts',()=>{
 const h=harness();h.join();
 for(let count=0;count<7;count++){
  const socket=h.sockets.at(-1);socket.onopen();socket.onclose({code:1006});
  if(count<6){assert.equal(h.timers.length,1);h.timers.shift().fn()}
 }
 assert.equal(h.sockets.length,7);
 assert.equal(h.timers.length,0);
 assert.match(h.statuses.at(-1),/연결 중단/);
});
test('successful heartbeat signals an established connection and resets retry budget',()=>{
 const h=harness();h.join();h.st.attempt=5;
 h.sockets[0].onmessage({data:JSON.stringify({type:'heartbeat',after:0,edit_after_at:h.st.editAt,edit_after_id:''})});
 assert.equal(h.st.attempt,0);
});
test('late error from superseded socket does not display a misleading error',()=>{
 const h=harness();h.join();const old=h.sockets[0];h.join();
 old.onerror();assert.equal(h.notices.length,0);
});
test('reconnection timer cannot cross into another selected chat',()=>{
 const h=harness();h.join();const original=h.sockets[0];original.onclose({code:1006});
 h.st.nonce++;h.st.chat='conn-A-C';h.st.socket=null;
 h.timers.shift().fn();assert.equal(h.sockets.length,1);
});
