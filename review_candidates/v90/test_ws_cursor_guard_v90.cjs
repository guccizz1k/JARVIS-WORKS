'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {test}=require('node:test');
const html=fs.readFileSync(__dirname+'/messenger_stage_v90.html','utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const a=script.indexOf('sock.onmessage=event=>');
const b=script.indexOf('\n   sock.onclose=',a);
assert(a>=0 && b>a);
function fixture(){
 const sock={},seen=[];
 const st={nonce:8,socket:sock,cursor:9,editAt:'2026-10-24T12:00:02+00:00',editId:'edit-002'};
 const env={sock,st,local:8,render:data=>seen.push(['message',data]),applyEdit:data=>seen.push(['edit',data]),markRead:()=>{}};
 vm.runInNewContext(script.slice(a,b),env);
 return {sock,st,seen};
}
test('stale socket cannot emit into currently selected chat socket',()=>{
 const x=fixture();x.st.socket={different:true};
 x.sock.onmessage({data:JSON.stringify({type:'message',data:{message_id:'foreign',message_cursor:11}})});
 assert.equal(x.seen.length,0);
 assert.equal(x.st.cursor,9);
});
test('delayed edit event cannot move reconnect watermark backwards',()=>{
 const x=fixture();
 x.sock.onmessage({data:JSON.stringify({type:'edit',data:{message_id:'m1',version:2,edited_at:'2026-10-24T12:00:01+00:00',edit_id:'edit-001'}})});
 assert.equal(x.st.editAt,'2026-10-24T12:00:02+00:00');
 assert.equal(x.st.editId,'edit-002');
});
test('equal timestamp, lower edit ID cannot regress cursor',()=>{
 const x=fixture();
 x.sock.onmessage({data:JSON.stringify({type:'edit',data:{message_id:'m1',version:2,edited_at:'2026-10-24T12:00:02Z',edit_id:'edit-001'}})});
 assert.equal(x.st.editId,'edit-002');
});
test('strictly newer edit safely advances cursor',()=>{
 const x=fixture();
 x.sock.onmessage({data:JSON.stringify({type:'edit',data:{message_id:'m1',version:3,edited_at:'2026-10-24T12:00:02Z',edit_id:'edit-003'}})});
 assert.equal(x.st.editId,'edit-003');
 assert.equal(x.seen.length,1);
});
