/* V6.9: minimal adjustment review UI, no visual redesign or official tax postings. */
'use strict';
async function jwV69Open(invoiceId){
 const [invoice,detail]=await Promise.all([
  api('/invoices/'+encodeURIComponent(invoiceId)),
  api('/invoices/'+encodeURIComponent(invoiceId)+'/adjustments')
 ]);
 const rows=detail.adjustments||[], s=detail.settlement;
 const hist=rows.map(r=>`<div class="jw-v62-result"><span>${e({return:'반품',discount:'할인',freight:'운임'}[r.kind])} · ${r.kind==='return'?e(r.quantity)+'개':krw(r.amount)} · ${e(r.reason)} · ${e(r.decision||'승인 대기')}</span>${!r.decision&&state.user.role==='admin'?`<button type="button" class="btn small ghost" data-v69-decide="${e(r.id)}" data-invoice="${e(invoiceId)}" data-approve="yes">승인</button><button type="button" class="btn small ghost" data-v69-decide="${e(r.id)}" data-invoice="${e(invoiceId)}" data-approve="no">반려</button>`:''}</div>`).join('')||'<p class="muted">조정 이력이 없습니다.</p>';
 modal('반품·할인·운임 내부 검토',`<div class="notice warning">원본 청구서는 변경되지 않습니다. 관리자 승인 시 내부 미수금만 조정됩니다. 국세청 수정세금계산서 발행·재고 반입·실제 환불은 처리하지 않습니다.</div>
 <div class="details">${info('원본 청구 합계',krw(s.original.total))}${info('승인 조정 후 합계',krw(s.adjusted_total))}${info('확정 입금액',krw(s.paid))}${info('미수금',krw(s.balance))}</div>
 <h3 class="section-title">조정 기록 (${rows.length}건)</h3>${hist}
 <h3 class="section-title">새 조정 검토 요청</h3>
 <form id="jw-v69-form" data-invoice="${e(invoiceId)}" data-key="${e(requestRef())}">
  <label>조정 종류<select name="kind"><option value="return">반품</option><option value="discount">할인</option><option value="freight">운임 추가</option></select></label>
  <label data-v69-return>원청구 품목<select name="item_id">${invoice.items.map(i=>`<option value="${e(i.id)}">${e(i.name)} · ${e(i.quantity)}개 × ${krw(i.unit_price)}</option>`).join('')}</select></label>
  <label data-v69-return>반품 수량<input name="quantity" type="number" step="1" min="1" max="100000" value="1" required></label>
  <label data-v69-amount hidden>공급가액 조정 금액 (원)<input name="amount" type="number" step="1" min="1" max="1000000000000" value="1" disabled></label>
  <label>원본 대조 및 사유<textarea name="reason" minlength="12" maxlength="500" required rows="3"></textarea></label>
  <label class="import-confirm"><input name="original_checked" type="checkbox" required> 원본 청구서·거래 증빙을 확인했습니다.</label>
  <button type="submit" class="btn primary">검토 요청 등록</button>
 </form>`, '부가세는 청구서 전체 과세 구분에 따라 한 번 반올림합니다. 특수 세무 처리는 지원하지 않습니다.');
 const form=document.querySelector('#jw-v69-form');
 form.elements.kind.addEventListener('change',()=>{
  const isReturn=form.elements.kind.value==='return';
  form.querySelectorAll('[data-v69-return]').forEach(el=>{el.hidden=!isReturn;el.querySelectorAll('input,select').forEach(c=>c.disabled=!isReturn)});
  const amount=form.querySelector('[data-v69-amount]');amount.hidden=isReturn;
  amount.querySelector('input').disabled=isReturn;
 });
 window.jwV69CurrentDigest=detail.expected_digest;
}

document.addEventListener('click',async ev=>{
 const open=ev.target.closest('[data-v69-open]'),dec=ev.target.closest('[data-v69-decide]');
 if(!open&&!dec)return;
 const target=open||dec;target.disabled=true;
 try{
  if(open)await jwV69Open(open.dataset.v69Open);
  else{
   const approve=dec.dataset.approve==='yes';
   if(!confirm(approve?'관리자로서 원본과 금액을 검토하고 이 조정을 승인합니까?':'해당 조정 요청을 반려합니까?'))return;
   const note=prompt('원본문서 대조 결과 및 결정 사유를 12자 이상 입력하세요.');
   if(note===null)return;
   await api(`/invoices/${encodeURIComponent(dec.dataset.invoice)}/adjustments/${encodeURIComponent(dec.dataset.v69Decide)}/decision`,'POST',{
    approve,expected_digest:window.jwV69CurrentDigest,original_checked:true,note});
   await navigate('invoices');await jwV69Open(dec.dataset.invoice);toast(approve?'내부 미수금에 조정을 반영했습니다':'조정 요청을 반려했습니다');
  }
 }catch(err){toast(err.message,true)}finally{if(target.isConnected)target.disabled=false}
});
document.addEventListener('submit',async ev=>{
 if(ev.target.id!=='jw-v69-form')return;ev.preventDefault();
 const form=ev.target,button=form.querySelector('button[type=submit]');button.disabled=true;
 try{
  const kind=form.elements.kind.value,body={kind,request_key:form.dataset.key,
    reason:form.elements.reason.value,original_checked:form.elements.original_checked.checked};
  if(kind==='return'){body.item_id=form.elements.item_id.value;body.quantity=Number(form.elements.quantity.value)}
  else body.amount=Number(form.elements.amount.value);
  await api('/invoices/'+encodeURIComponent(form.dataset.invoice)+'/adjustments','POST',body);
  await navigate('invoices');await jwV69Open(form.dataset.invoice);
  toast('조정 검토 요청이 등록됐습니다');
 }catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false}
});
