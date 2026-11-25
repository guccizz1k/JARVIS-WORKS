'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Node {constructor(tag){this.tag=tag;this.children=[];this.value='';this.handlers={}}
 append(...children){this.children.push(...children)}replaceChildren(...children){this.children=children}
 setAttribute(){}addEventListener(event,fn){this.handlers[event]=fn}
 querySelector(tag){return descendants(this).find(x=>x.tag===tag)||null}}
function descendants(node){return node.children.flatMap(x=>[x,...descendants(x)])}
async function harness(){
 const view=new Node('main'),threads=[{id:'a'.repeat(32),other_org_id:'c'.repeat(32),other_company:'A'},
 {id:'b'.repeat(32),other_org_id:'d'.repeat(32),other_company:'B'}];
 const pending=[],sent=[];let delayed=false;
 const bridge={identity:{id:'u',org_id:'o'},signedIn:true,
 messengerDirectory:async()=>[],preferencesRead:async()=>({messenger_auto_refresh:false}),
 messengerThreads:async()=>threads,
 messengerMessages:async()=>delayed?new Promise(resolve=>pending.push(resolve)):[],
 messengerSend:async(thread,body,key)=>{sent.push({thread,body,key});throw Object.assign(Error('uncertain'),{code:'NETWORK_ERROR'})}};
 const ctx={document:{createElement:tag=>new Node(tag)},window:{},crypto:require('crypto').webcrypto};
 vm.runInNewContext(fs.readFileSync('app/static/approved_ui_operational_v223.js','utf8'),ctx);
 await ctx.window.JWOwnerOperational.render({bridge,view,page:'messenger',isCurrent:()=>true});
 return {view,pending,sent,setDelayed:value=>{delayed=value},
 select:index=>view.children[1].children[index+1].onclick(),
 forms:()=>descendants(view.children[2]).filter(x=>x.tag==='form'),
 async send(text){const form=this.forms()[0];form.children.find(x=>x.tag==='textarea').value=text;
 await form.handlers.submit({preventDefault(){}})}};
}
test('same-thread newer selection wins over older message response and renders one send form',async()=>{
 const h=await harness();h.setDelayed(true);
 const old=h.select(0),latest=h.select(0);
 h.pending[1]([{body:'LATEST',mine:true}]);await latest;
 h.pending[0]([{body:'OLD',mine:true}]);await old;
 assert.equal(h.forms().length,1,'same-thread overlap must not append duplicate send forms');
 const text=descendants(h.view.children[2]).map(x=>x.textContent||'').join('|');
 assert.ok(text.includes('LATEST'));assert.ok(!text.includes('OLD'),'older response must be discarded');
});
test('uncertain same-thread retry retains idempotency key, different thread gets a fresh key',async()=>{
 const h=await harness();await h.select(0);await h.send('Synthetic text');await h.send('Synthetic text');
 assert.equal(h.sent[0].key,h.sent[1].key,'retry must retain original key to avoid duplicate delivery');
 await h.select(1);await h.send('Synthetic text');
 assert.notEqual(h.sent[1].thread,h.sent[2].thread);
 assert.notEqual(h.sent[1].key,h.sent[2].key,'different thread must not collide with uncertain committed send');
 assert.match(h.sent[2].key,/^[a-f0-9]{32}$/);
});
