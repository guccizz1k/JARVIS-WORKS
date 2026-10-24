'use strict';
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const html = fs.readFileSync(__dirname + '/messenger_stage_v90.html', 'utf8');
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const first = script.indexOf(' const render=(item)=>{');
const last = script.indexOf(' const markRead=async()=>{',first);
assert(first>=0 && last>first);
const handlers = script.slice(first,last);
function fixture() {
 const children=[];
 const dom={
  children, scrollHeight:100,scrollTop:0,
  appendChild(n){children.push(n)},
 };
 const st={orgId:'A',chat:'chat1',messages:new Map(),pendingEdits:new Map()};
 const sandbox={st,el:id=>id==='messages'?dom:null,
  nodeFor:item=>({dataset:{messageId:item.message_id},item,replaceWith(n){const i=children.indexOf(this); if(i!==-1)children[i]=n}}),
 };
 const {render,applyEdit}=vm.runInNewContext(handlers+'\n({render,applyEdit})',sandbox);
 return {render,applyEdit,st,children};
}
const message=(id,body,version=1)=>({message_id:id,message_cursor:1,sender_org:'A',body,version});
const edit=(id,body,version=2)=>({message_id:id,edit_id:'edit'+version,version,new_body:body,edited_at:'2026-10-24T12:00:00+00:00'});

test('older version 1 snapshot cannot overwrite committed version 2',()=>{
 const x=fixture();x.render(message('m1','original'));x.applyEdit(edit('m1','fixed'));
 x.render(message('m1','original'));
 assert.equal(x.st.messages.get('m1').body,'fixed');
 assert.equal(x.st.messages.get('m1').version,2);
 assert.equal(x.children.length,1);
});

test('out-of-order edits never regress newest visible version',()=>{
 const x=fixture();x.render(message('m1','original'));
 x.applyEdit(edit('m1','third',3));x.applyEdit(edit('m1','second',2));
 assert.equal(x.st.messages.get('m1').body,'third');
 assert.equal(x.st.messages.get('m1').version,3);
});

test('edit that arrives ahead of its message must be applied after message arrives',()=>{
 const x=fixture();x.applyEdit(edit('m2','new text',2));
 x.render(message('m2','old text'));
 assert.equal(x.st.messages.get('m2').body,'new text');
 assert.equal(x.st.messages.get('m2').version,2);
});

test('delayed older message cannot undo missing-message edit version 4',()=>{
 const x=fixture();x.applyEdit(edit('m3','fourth',4));x.applyEdit(edit('m3','third',3));
 x.render(message('m3','old',1));
 assert.equal(x.st.messages.get('m3').body,'fourth');
 assert.equal(x.st.messages.get('m3').version,4);
});

test('edit with same version is idempotent and cannot change body',()=>{
 const x=fixture();x.render(message('m4','newest',3));
 x.applyEdit(edit('m4','malicious-stale',3));
 assert.equal(x.st.messages.get('m4').body,'newest');
});

test('base message newer than queued edit remains authoritative',()=>{
 const x=fixture();x.applyEdit(edit('m5','edit version 2',2));
 x.render(message('m5','current version 4',4));
 assert.equal(x.st.messages.get('m5').version,4);
 assert.equal(x.st.messages.get('m5').body,'current version 4');
 assert.equal(x.st.pendingEdits.size,0);
});

test('unknown-message edit queue stays bounded to prevent memory exhaustion',()=>{
 const x=fixture();
 for(let i=0;i<520;i++)x.applyEdit(edit('unknown'+i,'msg',2));
 assert.equal(x.st.pendingEdits.size,500);
 assert.equal(x.st.pendingEdits.has('unknown0'),false);
 x.render(message('unknown519','base'));
 assert.equal(x.st.messages.get('unknown519').body,'msg');
});
