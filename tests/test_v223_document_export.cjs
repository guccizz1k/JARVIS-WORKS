'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const api=require('../app/static/approved_ui_document_export_v223.js');
const id='a'.repeat(32),source='b'.repeat(32);
const draft=(extra={})=>({id,kind:'sales_order_draft',source_type:'quote',source_id:source,document_no:'SOD-ABC123456789',scope:'authenticated_tenant_only',stale:false,document:{source_id:source,source_type:'quote',document_status:'internal_review_draft_only',money:{subtotal:100,vat:10,total:110}},...extra});
test('only existing source kinds and eligible server states are exported',()=>{
 assert.equal(api.eligible('sales_order_draft',{status:'accepted'}),true);assert.equal(api.eligible('sales_order_draft',{status:'draft'}),false);
 assert.equal(api.eligible('delivery_note_draft',{status:'fulfilled',review_state:'pending'}),false);
 assert.equal(api.eligible('payment_request_draft',{status:'issued',balance:100}),true);assert.equal(api.eligible('payment_request_draft',{status:'issued',balance:0}),false);
});
test('draft identity and integer money must match server snapshot',()=>{
 assert.equal(api.validateDraft(draft(),{kind:'sales_order_draft',sourceId:source}).id,id);
 for(const d of [draft({scope:'all'}),draft({source_id:'c'.repeat(32)}),draft({document:{...draft().document,money:{subtotal:100,vat:10,total:111}}}),draft({document:{...draft().document,money:{subtotal:100.5,vat:10,total:110.5}}})])assert.throws(()=>api.validateDraft(d,{kind:'sales_order_draft',sourceId:source}));
});
test('stale snapshots and unsafe document filenames are refused',()=>{
 assert.throws(()=>api.validateDraft(draft({stale:true})),{code:'STALE_DRAFT'});assert.throws(()=>api.validateDraft(draft({document_no:'../../private'})),{code:'INVALID_DRAFT'});
});
test('summary rejects forged scope, malformed rows and ambiguous totals',()=>{
 const summary={scope:'authenticated_tenant_only',total:1,by_kind:{sales_order_draft:1},recent:[{id,kind:'sales_order_draft',document_no:'SOD-ABC123456789',created_at:'2026-11-16T00:00:00Z'}]};assert.equal(api.validateSummary(summary).total,1);
 assert.throws(()=>api.validateSummary({...summary,total:true}));assert.throws(()=>api.validateSummary({...summary,scope:'public'}));
});
test('binary download must have XLSX ZIP framing and remain bounded',()=>{
 assert.equal(api.validateWorkbook(Uint8Array.from([80,75,3,4,1])).byteLength,5);
 assert.throws(()=>api.validateWorkbook(Uint8Array.from([60,104,116,109,108])));assert.throws(()=>api.validateWorkbook(new Uint8Array(2097153)));
});
test('controller checks server detail and user identity before returning workbook',async()=>{
 let who={id:'user-a',org_id:'org-a'},calls=[];const bridge={get identity(){return who},draftDetail:async x=>{calls.push('detail');return draft()},draftXlsx:async x=>{calls.push('xlsx');return {bytes:Uint8Array.from([80,75,3,4,1]),filename:'draft-'+id+'.xlsx',contentType:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}}};
 const ctrl=api.controller(bridge);const result=await ctrl.workbook(id);assert.equal(result.filename,'draft-'+id+'.xlsx');assert.deepEqual(calls,['detail','xlsx']);
 bridge.draftXlsx=async()=>{who={id:'user-b',org_id:'org-a'};return {bytes:Uint8Array.from([80,75,3,4,1]),filename:'draft-'+id+'.xlsx',contentType:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}};await assert.rejects(ctrl.workbook(id),{code:'STALE_SESSION'});
});
test('creating export draft is never automatic and requires explicit confirmation',async()=>{
 let creates=0;const bridge={identity:{id:'a',org_id:'org'},draftFromSource:async()=>{creates++;return draft()}};const ctrl=api.controller(bridge);
 assert.equal(await ctrl.create('sales_order_draft',source,()=>false),null);assert.equal(creates,0);
 assert.equal((await ctrl.create('sales_order_draft',source,()=>true)).id,id);assert.equal(creates,1);
});
test('controller refuses cross-source create result and partial signed-out state',async()=>{
 const bridge={identity:{id:'a',org_id:'org'},draftFromSource:async()=>draft({source_id:'c'.repeat(32)})};await assert.rejects(api.controller(bridge).create('sales_order_draft',source,()=>true),{code:'INVALID_DRAFT'});
 assert.throws(()=>api.controller({identity:null}),{code:'LOGIN_REQUIRED'});
});

class Element{
 constructor(tag){this.tag=tag;this.children=[];this.handlers={};this.disabled=false;this.value='';this.textContent='';}
 append(...nodes){this.children.push(...nodes);if(this.tag==='select'&&!this.value&&nodes[0])this.value=nodes[0].value;}
 setAttribute(k,v){this[k]=v;}
 addEventListener(k,fn){this.handlers[k]=fn;}
}
const dom=()=>({createElement:tag=>new Element(tag)});
const find=(node,tag)=>node.tag===tag?node:node.children.map(c=>find(c,tag)).find(Boolean);
const buttons=node=>[...(node.tag==='button'?[node]:[]),...node.children.flatMap(buttons)];
test('simulated DOM export panel performs no write or download until separate user actions',async()=>{
 const view=new Element('section'),document=dom();let creates=0,downloads=0,confirmed=false;
 const bridge={identity:{id:'user',org_id:'org1'},draftSummary:async()=>({scope:'authenticated_tenant_only',total:0,by_kind:{},recent:[]}),list:async name=>name==='quotes'?[{id:source,org_id:'org1',doc_no:'Q-SYNTHETIC',status:'accepted'}]:[],draftFromSource:async()=>{creates++;return draft()},draftDetail:async()=>draft(),draftXlsx:async()=>({bytes:Uint8Array.from([80,75,3,4,1]),filename:'draft-'+id+'.xlsx',contentType:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'})};
 await api.render({bridge,view,document,confirm:()=>confirmed,download:()=>downloads++});assert.equal(creates,0);assert.equal(downloads,0);
 const form=find(view,'form');await form.handlers.submit({preventDefault(){}});assert.equal(creates,0);
 confirmed=true;await form.handlers.submit({preventDefault(){}});assert.equal(creates,1);assert.equal(downloads,0);
 const download=buttons(view).find(x=>x.textContent==='확인 후 XLSX 내려받기');assert.ok(download);await download.onclick();assert.equal(downloads,1);
});
test('simulated DOM discards workbook when navigation changes during slow response',async()=>{
 let live=true,release;const pending=new Promise(r=>release=r),view=new Element('section');let downloads=0;
 const bridge={identity:{id:'u',org_id:'org1'},draftSummary:async()=>({scope:'authenticated_tenant_only',total:1,by_kind:{sales_order_draft:1},recent:[{id,kind:'sales_order_draft',document_no:'SOD-ABC123456789',created_at:'2026-11-16T00:00:00Z'}]}),list:async()=>[],draftDetail:async()=>draft(),draftXlsx:async()=>pending};
 await api.render({bridge,view,document:dom(),isCurrent:()=>live,download:()=>downloads++});const action=buttons(view).find(x=>x.textContent==='확인 후 XLSX 내려받기');const result=action.onclick();await Promise.resolve();live=false;release({bytes:Uint8Array.from([80,75,3,4,1]),filename:'draft-'+id+'.xlsx',contentType:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});await result;assert.equal(downloads,0);
});
