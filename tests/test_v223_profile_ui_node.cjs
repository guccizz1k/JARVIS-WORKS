'use strict';
const {test}=require('node:test');
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('app/static/approved_ui_profile_v223.js','utf8');
class Element {
 constructor(tag){this.tagName=tag;this.children=[];this.attributes={};this.listeners={};this.textContent='';this.value='';this.checked=false;this.disabled=false;
  this.classList={values:new Set(),toggle:(n,yes)=>{if(yes)this.classList.values.add(n);else this.classList.values.delete(n)}};}
 append(...nodes){this.children.push(...nodes)}
 replaceChildren(...nodes){this.children=[...nodes]}
 insertBefore(node,other){const i=this.children.indexOf(other);if(i<0)throw Error('anchor not child');this.children.splice(i,0,node)}
 setAttribute(key,value){this.attributes[key]=value}
 addEventListener(name,handler){this.listeners[name]=handler}
}
const find=(node,pred)=>{if(pred(node))return node;for(const x of node.children){const y=find(x,pred);if(y)return y}return null};
function harness(overrides={}){
 const body=new Element('body'),userLabel=new Element('span');
 const document={body,createElement:tag=>new Element(tag),querySelector:q=>q==='.jw-review-user'?userLabel:null};
 const context={window:{},document,console};
 vm.runInNewContext(source,context);
 const me={id:'a'.repeat(32),org_id:'b'.repeat(32),name:'Before',email:'before@example.invalid',role:'admin',org_name:'Synthetic'};
 let profile={...me,version:0},preferences={user_id:me.id,org_id:me.org_id,compact_view:false,messenger_auto_refresh:true,version:0};
 const called=[];
 const bridge={identity:me,signedIn:true,
   profileRead:async()=>({...profile}),profileSave:async(name,version)=>{
     called.push({name,version});profile={...profile,name,version:version+1};bridge.identity={...bridge.identity,name};return {...profile}},
   preferencesRead:async()=>({...preferences}),preferencesSave:async input=>{
     called.push({...input});preferences={...preferences,...input,version:input.version+1};return {...preferences}}
 };
 Object.assign(bridge,overrides);
 return {profile:()=>profile,preferences:()=>preferences,bridge,called,view:new Element('section'),userLabel,body,app:context.window.JWOwnerProfile};
}
test('account renders actual server name without HTML markup injection',async()=>{
 const a=harness();
 await a.app.render({bridge:a.bridge,view:a.view,page:'account',isCurrent:()=>true});
 const input=find(a.view,x=>x.tagName==='input');
 assert.equal(input.value,'Before');
 const form=find(a.view,x=>x.tagName==='form');assert.ok(form.listeners.submit);
});
test('profile form performs server CAS write and readback',async()=>{
 const a=harness();
 await a.app.render({bridge:a.bridge,view:a.view,page:'account',isCurrent:()=>true});
 const input=find(a.view,x=>x.tagName==='input');
 input.value='New Display';
 await find(a.view,x=>x.tagName==='form').listeners.submit({preventDefault(){}});
 assert.deepEqual(a.called,[{name:'New Display',version:0}]);
 assert.equal(a.profile().name,'New Display');
 assert.equal(a.userLabel.textContent,'New Display · Synthetic');
 const status=find(a.view,x=>x.attributes?.role==='status');
 assert.ok(status.textContent.includes('다시 확인'));
});
test('preferences form persists toggles and applies compact class',async()=>{
 const a=harness();
 await a.app.render({bridge:a.bridge,view:a.view,page:'settings',isCurrent:()=>true});
 const form=find(a.view,x=>x.tagName==='form');
 const inputs=form.children.filter(x=>x.tagName==='label').map(x=>x.children[0]);
 assert.equal(inputs.length,2);
 inputs[0].checked=true;inputs[1].checked=false;
 await form.listeners.submit({preventDefault(){}});
 assert.equal(a.preferences().compact_view,true);
 assert.equal(a.preferences().messenger_auto_refresh,false);
 assert.equal(a.body.classList.values.has('jw-compact-view'),true);
});
test('automatic preference restore requires matching identity',async()=>{
 let resolver;const delayed=new Promise(r=>resolver=r);
 const a=harness({preferencesRead:()=>delayed});
 const task=a.app.applySaved({bridge:a.bridge});
 a.bridge.identity={...a.bridge.identity,org_id:'c'.repeat(32)};
 resolver({compact_view:true});
 await task;
 assert.equal(a.body.classList.values.has('jw-compact-view'),false);
});
test('server profile response after route exit cannot mutate visible page',async()=>{
 let release;const delayed=new Promise(r=>release=r);
 const a=harness({profileRead:()=>delayed});
 let current=true;
 const task=a.app.render({bridge:a.bridge,view:a.view,page:'account',isCurrent:()=>current});
 current=false;release({id:a.bridge.identity.id,org_id:a.bridge.identity.org_id,name:'Private',version:0});
 await task;
 assert.equal(find(a.view,x=>x.tagName==='form'),null);
});
test('stale preferences error is surfaced without claiming saved',async()=>{
 const a=harness({preferencesSave:async()=>{const e=new Error('conflict');e.code='STALE_VERSION';throw e}});
 await a.app.render({bridge:a.bridge,view:a.view,page:'settings',isCurrent:()=>true});
 await find(a.view,x=>x.tagName==='form').listeners.submit({preventDefault(){}});
 const alert=find(a.view,x=>x.attributes?.role==='alert');
 assert.ok(alert.textContent.includes('다른 창'));
});
