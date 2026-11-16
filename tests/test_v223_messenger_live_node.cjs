'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('app/static/approved_ui_operational_v223.js','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),D='d'.repeat(32);
class Element{
 constructor(tag){this.tagName=tag;this.textContent='';this.children=[];this.attributes={};this.listeners={};this.dataset={};this.value='';this.disabled=false;}
 append(...v){this.children.push(...v)}
 replaceChildren(...v){this.children=[...v]}
 setAttribute(k,v){this.attributes[k]=v}
 addEventListener(k,f){this.listeners[k]=f}
 querySelector(tag){return find(this,x=>x.tagName===tag)}
}
const find=(node,pred)=>{if(pred(node))return node;for(const x of node.children){const y=find(x,pred);if(y)return y}return null};
function environment(refreshEnabled){
 const streams=[],timers=[],retries=[],document={hidden:false,createElement:t=>new Element(t)};
 class EventSource{
  constructor(url,opts){this.url=url;this.opts=opts;this.events={};this.closed=false;streams.push(this)}
  addEventListener(n,fn){this.events[n]=fn}
  emit(n){this.events[n]?.()}
  close(){this.closed=true}
 }
 const user={id:A,org_id:B,role:'admin'};
 const thread={id:C,other_org_id:D,other_company:'Peer Company',unread_count:1,status:'active'};
 let reads=0;
 const bridge={identity:user,signedIn:true,
   messengerDirectory:async()=>[{org_id:D,company_name:'Peer Company'}],
   messengerThreads:async()=>[thread],
   messengerMessages:async()=>{reads++;return[{id:A,mine:false,body:'Initial message',kind:'text',sender_org:D}]},
   preferencesRead:async()=>({user_id:A,org_id:B,version:0,compact_view:false,messenger_auto_refresh:refreshEnabled})
 };
 const context={window:{EventSource,confirm:()=>true},document,location:{origin:'https://isolated.example.invalid'},
 setInterval:(fn,ms)=>{const t={fn,ms,active:true};timers.push(t);return t},
 clearInterval:t=>{t.active=false},
 setTimeout:(fn,ms)=>{const t={fn,ms,active:true};retries.push(t);return t},
 clearTimeout:t=>{t.active=false},
 console};
 vm.runInNewContext(source,context);
 const view=new Element('div');
 const app=context.window.JWOwnerOperational;
 const render=()=>app.render({bridge,view,page:'messenger',isCurrent:()=>true});
 const open=async()=>{await render();const btn=find(view,x=>x.tagName==='button'&&x.textContent.includes('안 읽음'));assert.ok(btn);await btn.onclick()};
 return {app,bridge,view,streams,timers,retries,open,reads:()=>reads};
}
const flush=async()=>{await new Promise(resolve=>setImmediate(resolve));await new Promise(resolve=>setImmediate(resolve))};
test('SSE is scoped to thread and uses cookie-enabled same origin',async()=>{
 const x=environment(true);try{
   await x.open();assert.equal(x.streams.length,1);
   assert.equal(x.streams[0].url,'https://isolated.example.invalid/api/messenger/threads/'+C+'/events');
   assert.equal(x.streams[0].opts.withCredentials,true);
   assert.equal(x.timers[0].ms,8000);
 }finally{x.app.dispose()}
});
test('SSE change fetches authoritative data and preserves unsent draft',async()=>{
 const x=environment(true);try{
   await x.open();
   const field=x.view.querySelector('textarea');assert.ok(field);field.value='Draft must survive';
   x.streams[0].emit('change');await flush();
   assert.ok(x.reads()>=2);
   assert.equal(x.view.querySelector('textarea').value,'Draft must survive');
 }finally{x.app.dispose()}
});
test('SSE failure schedules bounded reconnection with fallback',async()=>{
 const x=environment(true);try{
   await x.open();const old=x.streams[0];old.onerror();assert.equal(old.closed,true);
   assert.equal(x.retries[0].ms,1000);
   x.retries[0].fn();assert.equal(x.streams.length,2);
   assert.equal(x.streams[1].closed,false);
   x.app.dispose();assert.equal(x.streams[1].closed,true);
   assert.ok(x.timers.every(t=>t.active===false));
 }finally{x.app.dispose()}
});
test('explicit server preferences disable all background streams and timers',async()=>{
 const x=environment(false);try{
   await x.open();
   assert.equal(x.streams.length,0);
   assert.equal(x.timers.length,0);
 }finally{x.app.dispose()}
});
test('navigation disposer closes existing event stream and polling timer',async()=>{
 const x=environment(true);
 await x.open();x.app.dispose();
 assert.equal(x.streams[0].closed,true);
 assert.equal(x.timers[0].active,false);
});
test('server session revocation closes realtime channel immediately',async()=>{
 const x=environment(true);try{
   await x.open();x.streams[0].emit('revoked');
   assert.equal(x.streams[0].closed,true);
   assert.equal(x.timers[0].active,false);
 }finally{x.app.dispose()}
});
