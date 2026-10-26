/* V6.6-6.8 minimal workflow controls, no redesign. Manual review only. */
'use strict';
function jwV68FormRow(v={}){
 return `<div class="jw-v62-result jw-v68-line" style="gap:6px;flex-wrap:wrap">
 <label>품목 <input name="name" required maxlength="150" value="${e(v.name||'')}"></label>
 <label>품목코드(선택) <input name="product_code" maxlength="80" value="${e(v.product_code||'')}"></label>
 <label>수량 <input name="quantity" required type="number" min="1" max="100000" step="1" value="${e(v.quantity??1)}"></label>
 <label>단가(원) <input name="unit_price" required type="number" min="0" max="1000000000" step="1" value="${e(v.unit_price??0)}"></label>
 </div>`;
}
async function jwV68OpenLines(rid){
 const [existing,suggestions]=await Promise.all([
  api(`/evidence/records/${encodeURIComponent(rid)}/line-items`),
  api(`/evidence/records/${encodeURIComponent(rid)}/line-suggestions`)]);
 if(existing.confirmed){
  modal('확정된 품목 대조 내역',`<p>품목 내역은 수정할 수 없습니다.</p>${(existing.lines||[]).map(x=>`<p>${e(x.name)} · ${e(x.quantity)}개 × ${krw(x.unit_price)}</p>`).join('')}`,'원본 증빙과의 비교 기록입니다.');
  return;
 }
 const rows=suggestions.lines?.length?suggestions.lines:[{name:'',quantity:1,unit_price:0}];
 modal('원본 증빙 품목 검토',`<form id="jw-v68-lines-form" data-rid="${e(rid)}">
 <p class="notice warning">Excel 추출 품목은 후보입니다. 원본을 직접 열어 모든 품목·수량·단가를 확인하세요. 자동 매출·회계·재고 확정은 하지 않습니다.</p>
 <div id="jw-v68-line-list">${rows.map(jwV68FormRow).join('')}</div>
 <button type="button" class="btn ghost" id="jw-v68-add">품목 추가</button>
 <label class="import-confirm"><input type="checkbox" name="original_checked" required> 원본에서 모든 품목을 확인했습니다.</label>
 <button type="submit" class="btn primary">품목 내역 확정</button>
 </form>`,'품목은 최대 40개까지 검토할 수 있으며 확정 후에는 변경할 수 없습니다.');
}
async function jwV68ReviewHistory(rid){
 const [history,queue]=await Promise.all([
  api(`/evidence/records/${encodeURIComponent(rid)}/review-history`),
  api('/evidence/reconciliation/exceptions')]);
 const item=(queue.items||[]).find(x=>x.record_id===rid);
 if(!item)throw Error('검토 대상이 없습니다');
 modal('불일치 검토 이력',`<p>상태: ${e(item.case_status)} · ${item.needs_attention?'추가 검토 필요':'연결 시점 기준 일치'}</p>
 <p>${history.chain_integrity_valid?'기록 연결 검증 통과':'검토 이력 연결 확인 실패'}</p>
 ${(history.events||[]).map(x=>`<p>${e(x.created_at)} · ${e(x.status)} · ${e(x.note)}</p>`).join('')||'<p>검토 이력이 없습니다.</p>'}
 <form id="jw-v68-review-form" data-rid="${e(rid)}" data-digest="${e(item.expected_digest)}">
 <label>검토 상태 <select name="status"><option value="investigating">확인 중</option><option value="document_checked">원본 확인함(미해결 가능)</option></select></label>
 <label>검토 기록 <textarea name="note" minlength="12" maxlength="500" required></textarea></label>
 <label class="import-confirm"><input type="checkbox" name="original_checked" required> 원본문서를 직접 확인했습니다.</label>
 <button type="submit" class="btn primary">검토 기록 추가</button>
 </form>`,'확인 기록은 실제 거래의 문제 해결·입금·재고 확정을 의미하지 않습니다.');
}
document.addEventListener('click',async ev=>{
 if(ev.target.id==='jw-v68-add'){
  const list=document.querySelector('#jw-v68-line-list');
  if(list && list.querySelectorAll('.jw-v68-line').length<40)list.insertAdjacentHTML('beforeend',jwV68FormRow());
  else toast('품목은 최대 40개까지입니다',true);
  return;
 }
 const b=ev.target.closest('[data-v68-lines],[data-v68-review]');if(!b)return;
 b.disabled=true;
 try{
  if(b.dataset.v68Lines)await jwV68OpenLines(b.dataset.v68Lines);
  else await jwV68ReviewHistory(b.dataset.v68Review);
 }catch(err){toast(err.message,true)}finally{if(b.isConnected)b.disabled=false;}
});
document.addEventListener('submit',async ev=>{
 if(ev.target.id==='jw-v68-lines-form'){
  ev.preventDefault();const form=ev.target;
  if(!form.elements.original_checked.checked)return toast('원본 확인이 필요합니다',true);
  const rows=[...form.querySelectorAll('.jw-v68-line')].map(row=>Object.fromEntries(
   [...row.querySelectorAll('input')].map(x=>[x.name,
    ['quantity','unit_price'].includes(x.name)?Number(x.value):x.value])));
  const b=form.querySelector('button[type=submit]');b.disabled=true;
  try{await api(`/evidence/records/${encodeURIComponent(form.dataset.rid)}/line-items`,'POST',{original_checked:true,lines:rows});
   closeModal();await navigate('imports');toast('품목 확인 기록을 저장했습니다');}
  catch(err){toast(err.message,true)}finally{if(b.isConnected)b.disabled=false;}
 }else if(ev.target.id==='jw-v68-review-form'){
  ev.preventDefault();const form=ev.target;
  if(!form.elements.original_checked.checked)return toast('원본 확인이 필요합니다',true);
  const b=form.querySelector('button[type=submit]');b.disabled=true;
  try{await api(`/evidence/records/${encodeURIComponent(form.dataset.rid)}/review-event`,'POST',{
   expected_digest:form.dataset.digest,status:form.elements.status.value,note:form.elements.note.value,
   original_checked:true});closeModal();await navigate('imports');toast('검토 이력이 추가됐습니다');}
  catch(err){toast(err.message,true)}finally{if(b.isConnected)b.disabled=false;}
 }
});
