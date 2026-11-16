'use strict';
const test=require('node:test'),assert=require('node:assert/strict');
const api=require('../app/static/approved_ui_evidence_review_v223.js');
const id='a'.repeat(32),digest='b'.repeat(64);
const preview=(extra={})=>({id,digest,status:'pending',source_file_sha256:'c'.repeat(64),original_file_stored:false,source_size_bytes:100,document:{document_kind:'receipt',kind_inference:'explicit',fields:{counterparty:'Synthetic',document_date:'2026-11-16',gross_amount:11000,reference_number:'R-1'}},...extra});
const fields={record_type:'expense',counterparty:'Synthetic',document_date:'2026-11-16',gross_amount:'11000',reference_number:'R-1',sku:'',quantity:'',unit:''};
test('upload extension and actual declared byte bound are required before network call',()=>{
 assert.equal(api.validateFile({name:'receipt.xlsx',size:1}).name,'receipt.xlsx');
 for(const file of [{name:'run.exe',size:1},{name:'a.pdf',size:0},{name:'a.png',size:5242881},{name:'../a.pdf',size:1}])assert.throws(()=>api.validateFile(file),{code:'INVALID_EVIDENCE_FILE'});
});
test('confirmation cannot relabel unsupported or ambiguous source documents',()=>{
 assert.throws(()=>api.validatePreview(preview({document:{document_kind:null,kind_inference:'unknown',fields:{}}}),true),{code:'UNSUPPORTED_EVIDENCE'});
 assert.throws(()=>api.approvalPayload(preview(),{...fields,record_type:'inventory_snapshot'},true),{code:'INVALID_EVIDENCE_APPROVAL'});
});
test('original human check is mandatory and immutable preview digest/type are retained',()=>{
 assert.throws(()=>api.approvalPayload(preview(),fields,false),{code:'ORIGINAL_CHECK_REQUIRED'});
 const body=api.approvalPayload(preview(),{...fields,preview_digest:'forged',document_kind:'inventory_sheet'},true);
 assert.equal(body.preview_digest,digest);assert.equal(body.document_kind,'receipt');assert.equal(body.original_checked,true);assert.equal(body.gross_amount,11000);
});
test('money, dates and inventory fields reject ambiguous or impossible inputs',()=>{
 for(const value of ['1e4','12.5','0','-3','1000000001'])assert.throws(()=>api.approvalPayload(preview(),{...fields,gross_amount:value},true));
 assert.throws(()=>api.approvalPayload(preview(),{...fields,document_date:'2026-02-30'},true));
 const stock=preview({document:{document_kind:'inventory_sheet',kind_inference:'explicit',fields:{}}});
 assert.throws(()=>api.approvalPayload(stock,{...fields,record_type:'inventory_snapshot'},true));
 const body=api.approvalPayload(stock,{...fields,record_type:'inventory_snapshot',gross_amount:'',sku:'SKU-A',quantity:'5',unit:'개'},true);assert.equal(body.gross_amount,null);assert.equal(body.quantity,5);
});
test('no approval occurs without separate final confirmation',async()=>{
 let writes=0;const bridge={identity:{id:'u',org_id:'o'},confirmEvidence:async()=>{writes++;return {id,record_type:'expense',corrected_fields:[],accounting_posted:false,payment_created:false,inventory_stock_changed:false}}};
 assert.equal(await api.controller(bridge).approve(preview(),fields,true,()=>false),null);assert.equal(writes,0);
 await api.controller(bridge).approve(preview(),fields,true,()=>true);assert.equal(writes,1);
});
test('late approval response after same-company actor change is not displayed',async()=>{
 let who={id:'a',org_id:'o'};const bridge={get identity(){return who},confirmEvidence:async()=>{who={id:'b',org_id:'o'};return {id,record_type:'expense',corrected_fields:[],accounting_posted:false,payment_created:false,inventory_stock_changed:false}}};
 await assert.rejects(api.controller(bridge).approve(preview(),fields,true,()=>true),{code:'STALE_SESSION'});
});
test('server response must deny automatic accounting/payment/stock effects',async()=>{
 const bridge={identity:{id:'u',org_id:'o'},confirmEvidence:async()=>({id,record_type:'expense',corrected_fields:[],accounting_posted:true,payment_created:false,inventory_stock_changed:false})};
 await assert.rejects(api.controller(bridge).approve(preview(),fields,true,()=>true),{code:'INVALID_EVIDENCE_RESULT'});
});

class Element{
 constructor(tag){this.tag=tag;this.children=[];this.handlers={};this.disabled=false;this.value='';this.textContent='';this.files=[];this.checked=false;}
 append(...nodes){this.children.push(...nodes);if(this.tag==='select'&&!this.value&&nodes[0])this.value=nodes[0].value;}
 replaceChildren(...nodes){this.children=[];this.append(...nodes);}
 setAttribute(k,v){this[k]=v;}
 addEventListener(k,fn){this.handlers[k]=fn;}
}
const elements=node=>[node,...node.children.flatMap(elements)];
const document=()=>({createElement:tag=>new Element(tag)});
test('simulated inbox approval keeps source acknowledgment unchecked and never auto-confirms',async()=>{
 const view=new Element('section');let writes=0,confirmed=false,state='pending';
 const bridge={identity:{id:'u',org_id:'o'},evidenceQueue:async()=>({items:[{id,filename:'synthetic.xlsx',status:state}]}),listEvidenceRecords:async()=>[],evidencePreview:async()=>preview(),confirmEvidence:async(_,body)=>{writes++;state='confirmed';return {id,record_type:body.record_type,corrected_fields:[],accounting_posted:false,payment_created:false,inventory_stock_changed:false}}};
 await api.render({bridge,view,page:'inbox',document:document(),confirm:()=>confirmed});assert.equal(writes,0);
 assert.equal(elements(view).some(e=>e.type==='file'),false);
 const review=elements(view).find(e=>e.textContent==='인식값 검토');await review.onclick();assert.equal(writes,0);
 const ack=elements(view).find(e=>e.type==='checkbox'),form=elements(view).find(e=>e.tag==='form');assert.equal(ack.checked,false);
 await form.handlers.submit({preventDefault(){}});assert.equal(writes,0);
 ack.checked=true;await form.handlers.submit({preventDefault(){}});assert.equal(writes,0);
 confirmed=true;await form.handlers.submit({preventDefault(){}});assert.equal(writes,1);
 assert.ok(elements(view).some(e=>e.textContent.includes('회계전표·입금·실재고는 변경하지 않았습니다.')));
});
test('simulated upload is explicit, bounded, and does not approve parsed proposals',async()=>{
 const view=new Element('section');let uploads=0,approvals=0;
 const bridge={identity:{id:'u',org_id:'o'},evidenceQueue:async()=>({items:[]}),listEvidenceRecords:async()=>[],uploadEvidence:async()=>{uploads++;return preview()},confirmEvidence:async()=>{approvals++}};
 await api.render({bridge,view,page:'docs',document:document()});const form=elements(view).find(e=>e.tag==='form'),file=elements(view).find(e=>e.type==='file');assert.equal(uploads,0);
 file.files=[{name:'malware.exe',size:10}];await form.handlers.submit({preventDefault(){}});assert.equal(uploads,0);
 file.files=[{name:'synthetic.xlsx',size:100}];assert.equal(uploads,0);await form.handlers.submit({preventDefault(){}});assert.equal(uploads,1);assert.equal(approvals,0);
 assert.ok(elements(view).some(e=>e.textContent.includes('원본 파일은 서버에 보관되지 않습니다.')));
});
test('simulated slow preview response cannot replace view after navigation',async()=>{
 let release,live=true;const wait=new Promise(r=>release=r),view=new Element('section');
 const bridge={identity:{id:'u',org_id:'o'},evidenceQueue:async()=>({items:[{id,filename:'synthetic.xlsx',status:'pending'}]}),listEvidenceRecords:async()=>[],evidencePreview:async()=>wait};
 await api.render({bridge,view,page:'inbox',document:document(),isCurrent:()=>live});const review=elements(view).find(e=>e.textContent==='인식값 검토');const action=review.onclick();live=false;release(preview());await action;assert.equal(elements(view).some(e=>e.type==='checkbox'),false);
});

test('legacy preview size stays unknown and its unchanged digest remains approvable',()=>{
 for(const size of [null,undefined]){const p=preview({source_size_bytes:size});assert.equal(api.validatePreview(p),p);assert.equal(api.approvalPayload(p,fields,true).preview_digest,digest);}
});
test('new upload requires exact source byte count rather than legacy unknown compatibility',async()=>{
 for(const size of [null,undefined,99]){const bridge={identity:{id:'u',org_id:'o'},uploadEvidence:async()=>preview({source_size_bytes:size})};await assert.rejects(api.controller(bridge).upload({name:'synthetic.xlsx',size:100}),{code:'INVALID_EVIDENCE_PREVIEW'});}
});
test('simulated legacy review explicitly labels unknown source size',async()=>{
 const view=new Element('section'),bridge={identity:{id:'u',org_id:'o'},evidenceQueue:async()=>({items:[{id,filename:'legacy.xlsx',status:'pending'}]}),listEvidenceRecords:async()=>[],evidencePreview:async()=>preview({source_size_bytes:null})};
 await api.render({bridge,view,page:'inbox',document:document()});await elements(view).find(e=>e.textContent==='인식값 검토').onclick();assert.ok(elements(view).some(e=>e.textContent.includes('크기 정보 없음(이전 문서)')));assert.ok(elements(view).some(e=>e.type==='checkbox'));
});
const defer=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve}};
test('simulated slow preview A cannot replace a more recently selected B in the same view',async()=>{
 const bid='d'.repeat(32),a=defer(),view=new Element('section');const bridge={identity:{id:'u',org_id:'o'},evidenceQueue:async()=>({items:[{id,filename:'a.xlsx',status:'pending'},{id:bid,filename:'b.xlsx',status:'pending'}]}),listEvidenceRecords:async()=>[],evidencePreview:async key=>key===id?a.promise:preview({id:bid,document:{...preview().document,fields:{...preview().document.fields,counterparty:'Preview B'}}})};
 await api.render({bridge,view,page:'inbox',document:document()});const buttons=elements(view).filter(e=>e.textContent==='인식값 검토');const slow=buttons[0].onclick();await buttons[1].onclick();a.resolve(preview());await slow;assert.equal(elements(view).find(e=>e.name==='counterparty').value,'Preview B');
});
test('simulated old approval completion cannot clear a newly selected B preview',async()=>{
 const bid='d'.repeat(32),approved=defer(),view=new Element('section');const bridge={identity:{id:'u',org_id:'o'},evidenceQueue:async()=>({items:[{id,filename:'a.xlsx',status:'pending'},{id:bid,filename:'b.xlsx',status:'pending'}]}),listEvidenceRecords:async()=>[],evidencePreview:async key=>preview({id:key,document:{...preview().document,fields:{...preview().document.fields,counterparty:key===bid?'Preview B':'Preview A'}}}),confirmEvidence:async()=>approved.promise};
 await api.render({bridge,view,page:'inbox',document:document(),confirm:()=>true});const buttons=elements(view).filter(e=>e.textContent==='인식값 검토');await buttons[0].onclick();const form=elements(view).find(e=>e.tag==='form');elements(view).find(e=>e.type==='checkbox').checked=true;const saving=form.handlers.submit({preventDefault(){}});await buttons[1].onclick();approved.resolve({id,record_type:'sales',corrected_fields:[],accounting_posted:false,payment_created:false,inventory_stock_changed:false});await saving;assert.equal(elements(view).find(e=>e.name==='counterparty')?.value,'Preview B');assert.equal(elements(view).some(e=>e.textContent.includes('증빙 기록을 등록했습니다.')),false);
});
test('simulated slow upload A cannot replace a later queue selection B',async()=>{
 const bid='d'.repeat(32),upload=defer(),view=new Element('section');const bridge={identity:{id:'u',org_id:'o'},evidenceQueue:async()=>({items:[{id:bid,filename:'b.xlsx',status:'pending'}]}),listEvidenceRecords:async()=>[],uploadEvidence:async()=>upload.promise,evidencePreview:async()=>preview({id:bid,document:{...preview().document,fields:{...preview().document.fields,counterparty:'Preview B'}}})};
 await api.render({bridge,view,page:'docs',document:document()});const form=elements(view).find(e=>e.tag==='form'),file=elements(view).find(e=>e.type==='file');file.files=[{name:'a.xlsx',size:100}];const saving=form.handlers.submit({preventDefault(){}});await elements(view).find(e=>e.textContent==='인식값 검토').onclick();upload.resolve(preview());await saving;assert.equal(elements(view).find(e=>e.name==='counterparty')?.value,'Preview B');
});
