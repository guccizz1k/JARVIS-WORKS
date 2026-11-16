/* Review-only human-checked evidence workflow; source files are not an archive. */
(function(g){
'use strict';
const ID=/^[a-f0-9]{32}$/,HASH=/^[a-f0-9]{64}$/;
const ALLOWED=Object.freeze({receipt:['sales','purchase','expense'],sales_slip:['sales'],purchase_slip:['purchase'],trade_statement:['sales','purchase'],inventory_sheet:['inventory_snapshot']});
const LABELS=Object.freeze({sales:'매출 증빙',purchase:'매입 증빙',expense:'경비 증빙',inventory_snapshot:'재고 실사 기록'});
const fail=code=>{const e=new Error(code);e.code=code;throw e};
function validateFile(file){
 if(!file||typeof file.name!=='string'||file.name.length>150||/[\\/]/.test(file.name)||! /\.(png|jpe?g|webp|pdf|xlsx)$/i.test(file.name)||!Number.isSafeInteger(file.size)||file.size<1||file.size>5242880)fail('INVALID_EVIDENCE_FILE');return file;
}
function validatePreview(p,supported=false){
 if(!p||!ID.test(p.id||'')||!HASH.test(p.digest||'')||!HASH.test(p.source_file_sha256||'')||!['pending','confirmed'].includes(p.status)||
    p.original_file_stored!==false||(p.source_size_bytes!=null&&(!Number.isSafeInteger(p.source_size_bytes)||p.source_size_bytes<1||p.source_size_bytes>5242880))||
    !p.document||typeof p.document!=='object'||!p.document.fields||typeof p.document.fields!=='object'||Array.isArray(p.document.fields)||
    (p.status==='confirmed'&&!ID.test(p.record_id||'')))fail('INVALID_EVIDENCE_PREVIEW');
 if(supported&&(!Object.hasOwn(ALLOWED,p.document.document_kind)||['ambiguous','unknown','unsupported'].includes(p.document.kind_inference)))fail('UNSUPPORTED_EVIDENCE');return p;
}
function text(value,max,required=false){if(typeof value!=='string')fail('INVALID_EVIDENCE_APPROVAL');const s=value.trim();if(s.length>max||(required&&!s)||/[\x00-\x1f\x7f]/.test(s))fail('INVALID_EVIDENCE_APPROVAL');return s;}
function positive(value,max,required=false){if(value===undefined||value===null||value===''){if(required)fail('INVALID_EVIDENCE_APPROVAL');return null}if(typeof value!=='string'||!/^[1-9]\d*$/.test(value))fail('INVALID_EVIDENCE_APPROVAL');const n=Number(value);if(!Number.isSafeInteger(n)||n>max)fail('INVALID_EVIDENCE_APPROVAL');return n;}
function approvalPayload(p,fields,checked){
 validatePreview(p,true);if(p.status!=='pending')fail('EVIDENCE_ALREADY_CONFIRMED');if(checked!==true)fail('ORIGINAL_CHECK_REQUIRED');
 const kind=p.document.document_kind;if(!fields||!ALLOWED[kind].includes(fields.record_type))fail('INVALID_EVIDENCE_APPROVAL');
 const date=text(fields.document_date,10,true),parsed=new Date(date+'T00:00:00Z');
 if(!/^\d{4}-\d{2}-\d{2}$/.test(date)||!Number.isFinite(parsed.getTime())||parsed.toISOString().slice(0,10)!==date)fail('INVALID_EVIDENCE_APPROVAL');
 const stock=fields.record_type==='inventory_snapshot';
 const body={preview_digest:p.digest,document_kind:kind,record_type:fields.record_type,counterparty:text(fields.counterparty,120,true),document_date:date,
  gross_amount:positive(fields.gross_amount,1000000000,!stock),reference_number:text(fields.reference_number??'',80),sku:text(fields.sku??'',80,stock),quantity:positive(fields.quantity,10000000,stock),unit:text(fields.unit??'',20),original_checked:true};
 if(stock&&body.gross_amount!==null)fail('INVALID_EVIDENCE_APPROVAL');return body;
}
function controller(bridge){
 const who=bridge?.identity;if(!who?.id||!who.org_id)fail('LOGIN_REQUIRED');
 const current=()=>{const now=bridge.identity;if(!now||now.id!==who.id||now.org_id!==who.org_id)fail('STALE_SESSION')};
 return Object.freeze({
  async upload(file){current();validateFile(file);const p=await bridge.uploadEvidence(file);current();validatePreview(p);if(p.status!=='pending'||p.source_size_bytes!==file.size)fail('INVALID_EVIDENCE_PREVIEW');return p},
  async preview(id){current();if(!ID.test(id||''))fail('INVALID_EVIDENCE_ID');const p=await bridge.evidencePreview(id);current();validatePreview(p);if(p.id!==id)fail('INVALID_EVIDENCE_PREVIEW');return p},
  async approve(p,fields,checked,confirm){
   current();const body=approvalPayload(p,fields,checked);if(typeof confirm!=='function'||!confirm())return null;
   current();const d=await bridge.confirmEvidence(p.id,body);current();
   if(!d||!ID.test(d.id||'')||d.record_type!==body.record_type||!Array.isArray(d.corrected_fields)||!d.corrected_fields.every(k=>['counterparty','document_date','gross_amount','reference_number','sku','quantity','unit','document_kind'].includes(k))||
      d.accounting_posted!==false||d.payment_created!==false||d.inventory_stock_changed!==false)fail('INVALID_EVIDENCE_RESULT');return d;
  }
 });
}
async function render({bridge,view,isCurrent=()=>true,page='docs',document=g.document,confirm=()=>g.confirm('직접 확인한 원본과 입력값이 일치합니까? 별도 증빙 기록으로 등록하며 회계전표·입금·실재고는 확정하지 않습니다.')}){
 if(!['docs','inbox','files'].includes(page))fail('UNSUPPORTED_EVIDENCE_PAGE');
 const ctl=controller(bridge),who=bridge.identity,live=()=>isCurrent()&&bridge.identity?.id===who.id&&bridge.identity?.org_id===who.org_id;
 let selection=0,refreshGeneration=0;const selected=token=>live()&&token===selection;
 const t=(tag,cls,value)=>{const el=document.createElement(tag);if(cls)el.className=cls;if(value!==undefined)el.textContent=String(value);return el};
 const status=t('p','jw-review-muted','서버 증빙을 확인하고 있습니다.');status.setAttribute('role','status');
 const warning=t('p','jw-review-muted','원본 파일은 서버에 보관되지 않습니다. 이 화면은 증빙 검토·기록이며 원본 첨부 보관함이 아닙니다. 소유한 원본을 직접 열어 인식값과 대조하세요.');
 const detail=t('section','jw-review-card'),queue=t('section','jw-review-card'),records=t('section','jw-review-card');view.append(warning,status);
 const message=e=>e?.code==='ORIGINAL_CHECK_REQUIRED'?'원본 파일과 입력값을 직접 대조한 뒤 확인란을 선택하세요.':e?.code==='UNSUPPORTED_EVIDENCE'?'원본문서 종류를 판별하지 못했습니다. 다른 종류로 바꾸어 승인할 수 없습니다.':e?.code==='STALE_SESSION'?'계정이 변경되어 이전 요청을 중단했습니다. 다시 조회하세요.':'증빙 처리를 확인하지 못했습니다. 원본·입력값·연결 상태를 확인하세요.';
 function show(p,token){
  if(!selected(token))return;detail.replaceChildren();detail.append(t('h3','jw-review-cardtitle',p.status==='confirmed'?'확인 완료된 증빙':'원본 대조 후 증빙 등록'),t('p','jw-review-muted','인식값은 제안입니다. 원본과 다른 값은 직접 수정하세요.'),t('p','jw-review-muted',p.source_size_bytes==null?'크기 정보 없음(이전 문서)':'원본 크기: '+p.source_size_bytes+'바이트'));
  if(p.status==='confirmed'){detail.append(t('p','jw-review-row','이미 등록된 증빙입니다. 중복 승인하지 않습니다.'));return}
  try{validatePreview(p,true)}catch(e){detail.append(t('p','jw-review-failure',message(e)));return}
  const proposed=p.document.fields,form=t('form','jw-review-form'),inputs={};
  function field(key,label,type,max){const box=t('label','jw-review-muted',label),input=t('input','jw-review-input');input.type=type;input.name=key;input.setAttribute('aria-label',label);if(max)input.maxLength=max;input.value=proposed[key]===undefined||proposed[key]===null?'':String(proposed[key]);box.append(input);form.append(box);inputs[key]=input;}
  const type=t('select','jw-review-input');type.name='record_type';type.setAttribute('aria-label','증빙 기록 구분');
  for(const kind of ALLOWED[p.document.document_kind]){const option=t('option','',LABELS[kind]);option.value=kind;type.append(option)}
  form.append(t('p','jw-review-row','원본문서 유형: '+p.document.document_kind),type);inputs.record_type=type;
  field('counterparty','거래처','text',120);field('document_date','문서 날짜','date');field('gross_amount','금액 (원, 재고 실사는 비움)','text',10);field('reference_number','원본 문서번호','text',80);field('sku','품목코드 (재고 실사 필수)','text',80);field('quantity','수량 (재고 실사 필수)','text',8);field('unit','단위','text',20);
  const ack=t('input','');ack.type='checkbox';ack.checked=false;ack.setAttribute('aria-label','원본 파일과 모든 입력값을 직접 대조했습니다');const label=t('label','jw-review-muted');label.append(ack,t('span','','원본 파일과 모든 입력값을 직접 대조했습니다'));
  const button=t('button','jw-review-action-button','대조한 증빙 등록');button.type='submit';form.append(label,button);detail.append(form);
  form.addEventListener('submit',async e=>{e.preventDefault();if(button.disabled||!selected(token))return;button.disabled=true;
   try{const values=Object.fromEntries(Object.entries(inputs).map(([k,v])=>[k,v.value]));const d=await ctl.approve(p,values,ack.checked,confirm);if(d&&selected(token)){detail.replaceChildren(t('p','jw-review-row','증빙 기록을 등록했습니다. 회계전표·입금·실재고는 변경하지 않았습니다.'));status.textContent='증빙 등록 완료';await refresh()}}
   catch(error){if(selected(token))status.textContent=message(error)}finally{button.disabled=false}
  });
 }
 if(page!=='inbox'){
  const form=t('form','jw-review-form'),file=t('input','jw-review-input'),button=t('button','jw-review-action-button','선택한 문서 분석·검토 요청');file.type='file';file.accept='.png,.jpg,.jpeg,.webp,.pdf,.xlsx';file.setAttribute('aria-label','검토할 원본 파일');button.type='submit';form.append(file,button);view.append(form);
  form.addEventListener('submit',async e=>{e.preventDefault();if(button.disabled||!live())return;const token=++selection;button.disabled=true;
   try{const p=await ctl.upload(file.files?.[0]);if(selected(token)){show(p,token);status.textContent='분석 제안이 준비됐습니다. 원본 확인 전에는 등록되지 않습니다.';await refresh()}}
   catch(error){if(selected(token))status.textContent=message(error)}finally{button.disabled=false}
  });
 }
 view.append(detail,queue,records);
 async function refresh(){
  const generation=++refreshGeneration;
  const [q,rows]=await Promise.all([bridge.evidenceQueue(),bridge.listEvidenceRecords()]);if(!live()||generation!==refreshGeneration)return;
  if(!q||!Array.isArray(q.items)||q.items.length>100||!Array.isArray(rows)||rows.length>100)fail('INVALID_EVIDENCE_ROWS');
  queue.replaceChildren(t('h3','jw-review-cardtitle','서버 검토 목록'));
  for(const row of q.items){
   if(!row||!ID.test(row.id||'')||typeof row.filename!=='string'||!['pending','confirmed'].includes(row.status))fail('INVALID_EVIDENCE_ROWS');
   const box=t('div','jw-review-row'),button=t('button','jw-review-action-button',row.status==='pending'?'인식값 검토':'등록 상태 확인');button.type='button';
   box.append(t('span','',row.filename+' · '+(row.status==='pending'?'원본 대조 대기':'등록 완료')),button);queue.append(box);
   button.onclick=async()=>{if(button.disabled||!live())return;const token=++selection;button.disabled=true;try{const p=await ctl.preview(row.id);if(selected(token))show(p,token)}catch(e){if(selected(token))status.textContent=message(e)}finally{button.disabled=false}};
  }
  records.replaceChildren(t('h3','jw-review-cardtitle','서버 증빙 기록'));
  for(const row of rows){if(!row||!ID.test(row.id||'')||!Object.hasOwn(LABELS,row.kind)||typeof row.counterparty!=='string'||typeof row.document_date!=='string')fail('INVALID_EVIDENCE_ROWS');records.append(t('div','jw-review-row',[LABELS[row.kind],row.counterparty,row.document_date,row.gross_amount??row.quantity??''].join(' · ')))}
 }
 try{await refresh();if(live())status.textContent='분석 제안은 원본 대조와 별도 승인 전까지 업무 기록으로 확정되지 않습니다.'}
 catch(error){if(live())status.textContent=message(error)}
}
const api=Object.freeze({validateFile,validatePreview,approvalPayload,controller,render});g.JWOwnerEvidenceReview=api;
if(typeof module==='object'&&module.exports)module.exports=api;
})(typeof window==='object'?window:globalThis);
