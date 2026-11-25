/* Review-only verified-source XLSX exports; no original UI or browser ledger boot. */
(function(g){
'use strict';
const SOURCES=Object.freeze({sales_order_draft:'quote',delivery_note_draft:'order',payment_request_draft:'invoice'});
const LABELS=Object.freeze({sales_order_draft:'수주서 초안',delivery_note_draft:'납품서 초안',payment_request_draft:'입금요청서 초안'});
const MAX_BYTES=2097152,ID=/^[a-f0-9]{32}$/,DOC=/^[A-Z0-9-]{1,80}$/;
const refuse=code=>{const error=new Error(code);error.code=code;throw error};
const integer=n=>Number.isSafeInteger(n)&&n>=0;
function eligible(kind,row){
 if(!row||!Object.hasOwn(SOURCES,kind))return false;
 if(kind==='sales_order_draft')return row.status==='accepted';
 if(kind==='delivery_note_draft')return row.status==='fulfilled'&&row.review_state!=='pending';
 return row.status==='issued'&&Number.isSafeInteger(row.balance)&&row.balance>0;
}
function validateDraft(d,expected={}){
 if(!d||typeof d!=='object'||!ID.test(d.id||'')||!Object.hasOwn(SOURCES,d.kind)||
    d.scope!=='authenticated_tenant_only'||d.source_type!==SOURCES[d.kind]||!ID.test(d.source_id||'')||
    !DOC.test(d.document_no||'')||!d.document||d.document.source_id!==d.source_id||
    d.document.source_type!==d.source_type||d.document.document_status!=='internal_review_draft_only'||
    (expected.kind&&d.kind!==expected.kind)||(expected.sourceId&&d.source_id!==expected.sourceId)||
    (expected.id&&d.id!==expected.id))refuse('INVALID_DRAFT');
 if(d.stale===true)refuse('STALE_DRAFT');
 const m=d.document.money;
 if(!m||!['subtotal','vat','total'].every(k=>integer(m[k]))||!Number.isSafeInteger(m.subtotal+m.vat)||m.subtotal+m.vat!==m.total)refuse('INVALID_DRAFT');
 return d;
}
function validateSummary(s){
 if(!s||s.scope!=='authenticated_tenant_only'||!integer(s.total)||!s.by_kind||typeof s.by_kind!=='object'||Array.isArray(s.by_kind)||
    !Object.entries(s.by_kind).every(([k,n])=>Object.hasOwn(SOURCES,k)&&integer(n))||Object.values(s.by_kind).reduce((a,b)=>a+b,0)!==s.total||!Array.isArray(s.recent)||s.recent.length>5||
    !s.recent.every(d=>d&&ID.test(d.id||'')&&Object.hasOwn(SOURCES,d.kind)&&DOC.test(d.document_no||'')&&typeof d.created_at==='string'&&Number.isFinite(Date.parse(d.created_at))))refuse('INVALID_DRAFT_SUMMARY');
 return s;
}
function validateWorkbook(bytes){
 if(!(ArrayBuffer.isView(bytes)&&Object.prototype.toString.call(bytes)==='[object Uint8Array]')||bytes.byteLength<4||bytes.byteLength>MAX_BYTES||bytes[0]!==80||bytes[1]!==75||bytes[2]!==3||bytes[3]!==4)refuse('INVALID_WORKBOOK');
 return bytes;
}
function controller(bridge){
 const who=bridge?.identity;if(!who||!who.id||!who.org_id)refuse('LOGIN_REQUIRED');
 const current=()=>{const now=bridge.identity;if(!now||now.id!==who.id||now.org_id!==who.org_id)refuse('STALE_SESSION')};
 return Object.freeze({
  async create(kind,sourceId,confirm){
   current();if(!Object.hasOwn(SOURCES,kind)||!ID.test(sourceId||''))refuse('INVALID_DRAFT_SOURCE');
   if(typeof confirm!=='function'||!confirm())return null;
   current();const d=await bridge.draftFromSource(kind,sourceId);current();return validateDraft(d,{kind,sourceId});
  },
  async workbook(draftId){
   current();if(!ID.test(draftId||''))refuse('INVALID_DRAFT_ID');
   const d=await bridge.draftDetail(draftId);current();if(typeof d?.stale!=='boolean')refuse('INVALID_DRAFT');validateDraft(d,{id:draftId});
   const file=await bridge.draftXlsx(draftId);current();
   if(!file||file.filename!=='draft-'+draftId+'.xlsx'||file.contentType!=='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')refuse('INVALID_WORKBOOK');
   validateWorkbook(file.bytes);return Object.freeze({bytes:file.bytes,filename:file.filename});
  }
 });
}
function saveWorkbook(file){
 const blob=new Blob([file.bytes],{type:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
 const url=g.URL.createObjectURL(blob),link=g.document.createElement('a');
 try{link.href=url;link.download=file.filename;link.hidden=true;g.document.body.append(link);link.click();}
 finally{link.remove();g.setTimeout(()=>g.URL.revokeObjectURL(url),0)}
}
async function render({bridge,view,isCurrent=()=>true,document=g.document,confirm=()=>g.confirm('선택한 서버 원본으로 검토용 문서 초안을 생성하시겠습니까? 실제 수주·납품·입금은 실행하지 않습니다.'),download=saveWorkbook}){
 const ctl=controller(bridge),who=bridge.identity;
 const live=()=>isCurrent()&&bridge.identity?.id===who.id&&bridge.identity?.org_id===who.org_id;
 const t=(tag,cls,text)=>{const el=document.createElement(tag);if(cls)el.className=cls;if(text!==undefined)el.textContent=String(text);return el};
 const status=t('p','jw-review-muted','서버 문서 초안을 확인하고 있습니다.');status.setAttribute('role','status');view.append(status);
 const message=error=>error?.code==='STALE_DRAFT'?'원본 잔액이 변경된 초안은 내려받을 수 없습니다.':error?.code==='STALE_SESSION'?'계정이 변경되어 이전 요청을 중단했습니다. 다시 조회하세요.':'문서 내보내기를 확인하지 못했습니다. 연결 상태와 원본 문서를 확인하세요.';
 const recent=t('section','jw-review-card');
 function item(d){
  const row=t('div','jw-review-row'),label=t('span','',d.document_no+' · '+LABELS[d.kind]),button=t('button','jw-review-action-button','확인 후 XLSX 내려받기');button.type='button';
  button.onclick=async()=>{if(button.disabled||!live())return;button.disabled=true;try{const file=await ctl.workbook(d.id);if(!live())return;download(file);status.textContent='검토용 문서 초안을 내려받았습니다.'}catch(e){if(live())status.textContent=message(e)}finally{button.disabled=false}};
  row.append(label,button);recent.append(row);
 }
 try{
  const [summary,quotes,orders,invoices]=await Promise.all([bridge.draftSummary(),bridge.list('quotes'),bridge.list('orders'),bridge.list('invoices')]);
  if(!live())return;
  validateSummary(summary);
  status.textContent='검토용 초안만 내보냅니다. 회계 전표·입금 확정·외부 발송은 실행하지 않습니다.';
  const form=t('form','jw-review-form'),select=t('select','jw-review-input'),button=t('button','jw-review-action-button','선택한 원본으로 초안 생성');button.type='submit';select.setAttribute('aria-label','내보낼 원본 문서');
  const choices=[];
  for(const [kind,rows] of [['sales_order_draft',quotes],['delivery_note_draft',orders],['payment_request_draft',invoices]]){
   if(!Array.isArray(rows))refuse('INVALID_DRAFT_SOURCE');
   for(const row of rows.filter(r=>eligible(kind,r)).slice(0,100)){
    if(!ID.test(row.id||'')||row.org_id!==who.org_id)refuse('INVALID_DRAFT_SOURCE');
    const value=kind+':'+row.id,option=t('option','',LABELS[kind]+' · '+String(row.doc_no||row.id));option.value=value;select.append(option);choices.push(value);
   }
  }
  button.disabled=choices.length===0;form.append(select,button);
  form.addEventListener('submit',async e=>{e.preventDefault();if(button.disabled||!live())return;button.disabled=true;try{
   if(!choices.includes(select.value))refuse('INVALID_DRAFT_SOURCE');
   const [kind,sourceId]=select.value.split(':');const d=await ctl.create(kind,sourceId,confirm);if(d&&live()){item(d);status.textContent='검토용 초안을 준비했습니다. 문서를 확인한 뒤 내려받으세요.'}
  }catch(error){if(live())status.textContent=message(error)}finally{button.disabled=choices.length===0}});
  view.append(t('p','jw-review-muted',choices.length?'승인 견적·검토 완료된 납품·미수 청구서 중 원본을 선택하세요.':'내보낼 수 있는 원본이 없습니다. 먼저 거래의 승인·납품·청구 상태를 확인하세요.'),form);
  recent.append(t('h3','jw-review-cardtitle','최근 서버 초안'));for(const d of summary.recent)item(d);view.append(recent);
 }catch(error){if(live())status.textContent=message(error)}
}
const api=Object.freeze({eligible,validateDraft,validateSummary,validateWorkbook,controller,render});g.JWOwnerDocumentExport=api;
if(typeof module==='object'&&module.exports)module.exports=api;
})(typeof window==='object'?window:globalThis);
