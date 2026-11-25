/* V6.4: minimal evidence workflow. Reviewed source data, never automatic accounting. */
'use strict';
const evidenceTypeLabelsV64={sales:'매출 증빙',purchase:'매입 증빙',expense:'경비 증빙',inventory_snapshot:'재고 실사'};
const evidenceKindLabelsV64={receipt:'영수증',sales_slip:'매출전표',purchase_slip:'매입전표',trade_statement:'거래명세표',inventory_sheet:'재고현황표'};
const evidenceAllowedTypesV220={receipt:['sales','purchase','expense'],sales_slip:['sales'],purchase_slip:['purchase'],trade_statement:['sales','purchase'],inventory_sheet:['inventory_snapshot']};
function evidenceDashboardV64(d){if(!d)return '';
 return `<section class="panel" style="margin-top:20px"><div class="panel-header"><h2>검토 완료 증빙 기록</h2></div><div class="panel-body"><p>검토 대기 <b>${e(d.pending_review)}</b>건 · 별도 증빙 기록 <b>${e(d.total_confirmed)}</b>건</p>${Object.entries(d.by_type||{}).map(([k,x])=>`<p>${e(evidenceTypeLabelsV64[k]||k)}: ${e(x.count)}건 ${k==='inventory_snapshot'?'(수량은 개별 품목 단위로 확인)':`· ${krw(x.amount)}`}</p>`).join('')}<div class="notice warning">${e(d.warning)}</div></div></section>`;
}
function evidenceLocalPreviewV219(file){
 if(!file || !/^image\/(?:png|jpeg|webp)$/.test(file.type))return Promise.resolve(null);
 return new Promise(resolve=>{
  const reader=new FileReader();
  reader.onload=()=>resolve(typeof reader.result==='string' && /^data:image\/(?:png|jpeg|webp);base64,/.test(reader.result)?reader.result:null);
  reader.onerror=()=>resolve(null);
  reader.readAsDataURL(file);
 });
}
function evidenceSourceViewV219(doc){
 const file=state.evidenceOriginalFile;
 const data=state.evidenceOriginalPreviewDataUrl;
 const head='<h3>원본 대조 · 이 브라우저에서만 표시</h3>';
 if(!file)return '<aside class="jw219-source" aria-label="원본 증빙 확인">'+head+
 '<div class="notice warning" role="status">원본 파일이 이 브라우저에 없습니다. 승인하려면 처음 업로드한 파일을 다시 선택해 일치 여부를 확인해야 합니다. 서버는 원본을 저장하지 않습니다.</div>'+
 '<label class="jw219-reattach">원본 다시 선택<input id="evidence-v219-reattach" type="file" accept=".pdf,.xlsx,.png,.jpg,.jpeg,.webp"></label></aside>';
 if(data)return '<aside class="jw219-source" aria-label="원본 증빙 확인">'+head+
 '<img class="jw219-original" alt="직접 선택한 원본 증빙 이미지" src="'+e(data)+'">'+
 '<p class="muted">확대해서 회사·날짜·금액 등 모든 항목을 대조하세요. 서버에는 원본 사진을 추가 보관하지 않습니다.</p></aside>';
 return '<aside class="jw219-source" aria-label="원본 증빙 확인">'+head+
 '<p class="muted">선택한 원본: '+e(file.name)+' · 이 형식은 이 화면에서 안전하게 직접 렌더링하지 않습니다.</p>'+
 btn('open-evidence-source','원본 파일 열기')+
 '<p class="muted">PC의 PDF/Excel 뷰어에서 원본을 확인한 다음 오른쪽 항목과 비교하세요.</p></aside>';
}

function evidenceHtmlV64(){
 const p=state.evidencePreview, doc=p?.document, f=doc?.fields||{}, q=state.evidenceQueue?.items||[];
 const options=(dict,defaultKey)=>Object.entries(dict).map(([k,v])=>`<option value="${e(k)}" ${k===defaultKey?'selected':''}>${e(v)}</option>`).join('');
 const review=doc&&p.status==='pending'?`<section class="panel"><div class="panel-header"><h2>외부 증빙 검토 · 승인 전</h2></div><div class="panel-body"><div class="notice warning">OCR 인식값은 잘못될 수 있습니다. 원본을 직접 열어 문서 유형·날짜·거래처·금액 또는 재고수량을 대조하세요. 자동 전표 발행, 송금, 실재고 변경은 하지 않습니다.</div><p class="muted">${e(doc.filename)} · ${e(doc.method)} · 원본문서 저장 안 함</p><p class="muted">${(doc.warnings||[]).map(e).join(' / ')}</p><div class="jw219-comparison"><div class="jw219-source-column">${evidenceSourceViewV219(doc)}</div><div class="jw219-fields-column">${doc.quality?`<p class="muted">문서 인식 점검: ${doc.quality.review_priority==='manual_entry_required'?'인식 불확실 · 직접 기입 및 검토 필요':'교차 검증상 특이사항 없음 · 원본 확인 필수'} · 사업자번호 ${doc.quality.business_number_format_valid===null?'미제공':doc.quality.business_number_format_valid?'형식 검증 통과(실제 등록 여부 별도)':'형식 오류'} · 신뢰도 확률은 제공하지 않습니다.</p>`:''}${state.evidenceOriginalFile && doc.document_kind && doc.kind_inference!=='ambiguous' && doc.kind_inference!=='unknown' ? `<form id="evidence-v64-confirm"><label>원본 유형 <select name="document_kind" required>${options({[doc.document_kind]:evidenceKindLabelsV64[doc.document_kind]},doc.document_kind)}</select></label><label>기록 목적 <select name="record_type" required>${options(Object.fromEntries((evidenceAllowedTypesV220[doc.document_kind]||[]).map(k=>[k,evidenceTypeLabelsV64[k]])),doc.proposed_record_type)}</select></label><label>거래처·상호 <input name="counterparty" required maxlength="120" value="${e(f.counterparty||'')}"></label><label>거래일 <input name="document_date" required type="date" value="${e(f.document_date||'')}"></label><label>금액(원) · 재고 실사는 공란 <input type="number" name="gross_amount" min="1" max="1000000000" placeholder="재고 실사는 비워두세요" value="${e(f.gross_amount||'')}"></label><label>원본 참조번호 <input name="reference_number" maxlength="80" value="${e(f.reference_number||'')}"></label><label>품목코드(재고 실사 필수) <input name="sku" maxlength="80" value="${e(f.sku||'')}"></label><label>재고수량(재고 실사 필수) <input type="number" name="quantity" min="1" max="10000000" value="${e(f.quantity||'')}"></label><label>단위 <input name="unit" maxlength="20" value="${e(f.unit||'')}"></label><label class="import-confirm"><input type="checkbox" name="original_checked" required> 원본을 직접 확인했고 인식 오류를 수정한 뒤 기록하는 데 동의합니다.</label><button class="btn primary" type="submit">검토 완료 후 별도 증빙 기록 생성</button></form>` : `<div class="notice warning" role="alert">${!state.evidenceOriginalFile?'원본 재첨부 및 일치 확인 전에는 승인할 수 없습니다.': '이 문서는 지원하는 증빙 유형으로 확인되지 않았습니다. 영수증·매출전표 등 다른 유형으로 등록할 수 없습니다. 원본을 확인하고 지원 문서만 다시 업로드하세요.'}</div>`}<details><summary>인식된 문자 일부 · 원본과 비교</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">${e(doc.ocr_text_excerpt||'')}</pre></details></div></div></div></section>`:'';
 return `<section class="panel import-upload-panel"><div class="panel-header"><h2>사진·PDF·Excel 증빙 인식 (V6.4)</h2></div><div class="panel-body"><form id="evidence-v64-file"><label class="import-label">영수증·매출/매입전표·거래명세표·재고표 <input type="file" name="file" accept=".pdf,.xlsx,.png,.jpg,.jpeg,.webp" required></label><p class="muted">최대 5MB. 사진·스캔 PDF는 OCR. 인식된 값은 검토 전까지 업무 기록에 반영되지 않습니다.</p><button class="btn primary" type="submit">증빙 분석 및 검토</button></form></div></section>${review}<section class="panel"><div class="panel-header"><h2>외부 증빙 검토함</h2><span class="badge orange">${q.filter(x=>x.status==='pending').length}건 대기</span></div><div class="panel-body">${q.slice(0,15).map(x=>`<div class="jw-v62-result"><span>${e(x.filename)} · ${e(evidenceKindLabelsV64[x.document_kind]||'유형 확인 필요')} · ${x.status==='pending'?'검토 대기':'확정'}</span>${x.status==='pending'?btn('evidence-v64-open','검토 열기',x.id):''}</div>`).join('')||'<p class="muted">등록된 증빙이 없습니다.</p>'}</div></section>${typeof evidenceV65Html==='function'?evidenceV65Html():''}`;
}
async function evidenceUploadV64(form){const file=form.querySelector('input[type=file]')?.files?.[0];if(!file)throw Error('파일 선택 필요');if(file.size>5*1024*1024)throw Error('최대 5MB');const body=new FormData();body.append('file',file,file.name);const r=await fetch('/api/evidence/preview',{method:'POST',headers:{'X-CSRF-Token':state.csrf,'Accept':'application/json'},body});let data=await r.json();if(!r.ok)throw Error(data.detail||'증빙 분석 실패');state.evidencePreview=data;state.evidenceOriginalFile=file;state.evidenceOriginalPreviewDataUrl=await evidenceLocalPreviewV219(file);await navigate('imports');toast('분석 완료 · 원본을 확인하고 검토하세요')}
async function evidenceConfirmV64(form){const f=Object.fromEntries(new FormData(form));const p=state.evidencePreview;if(!p||!f.original_checked)throw Error('원본 확인이 필요합니다');const body={preview_digest:p.digest,document_kind:f.document_kind,record_type:f.record_type,counterparty:f.counterparty,document_date:f.document_date,gross_amount:f.gross_amount?Number(f.gross_amount):null,reference_number:f.reference_number||'',sku:f.sku||'',quantity:f.quantity?Number(f.quantity):null,unit:f.unit||'',original_checked:true};const result=await api(`/evidence/preview/${encodeURIComponent(p.id)}/confirm`,'POST',body);state.evidencePreview=null;state.evidenceOriginalFile=null;state.evidenceOriginalPreviewDataUrl=null;if(state.evidenceSourceUrl)URL.revokeObjectURL(state.evidenceSourceUrl);state.evidenceSourceUrl=null;await navigate('imports');toast('증빙 기록 저장 완료 · 공식 회계·입금·재고는 변경되지 않았습니다');return result}

document.addEventListener('change',async ev=>{
 if(ev.target.id!=='evidence-v219-reattach')return;
 const input=ev.target,file=input.files?.[0],p=state.evidencePreview;
 try{
  if(!file||!p||file.size>5*1024*1024)throw Error('원본을 선택하거나 5MB 이하 파일만 사용하세요');
  if(!p.source_file_sha256||!globalThis.crypto?.subtle)throw Error('원본 일치 확인을 사용할 수 없습니다. 보안 연결에서 다시 시도하세요');
  const hex=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',await file.arrayBuffer()))).map(x=>x.toString(16).padStart(2,'0')).join('');
  if(hex!==p.source_file_sha256)throw Error('업로드한 원본과 일치하지 않습니다. 다른 파일을 선택하세요');
  state.evidenceOriginalFile=file;
  state.evidenceOriginalPreviewDataUrl=await evidenceLocalPreviewV219(file);
  await navigate('imports');
  toast('원본 SHA-256 일치 확인 완료 · 내용을 대조하고 승인하세요');
 }catch(err){toast(err.message,true)}
 finally{if(input.isConnected)input.value=''}
});
