/* V22.3 isolated finance review: server invoice, reconciliation, payments,
   authorized reversal. The source ledger is never modified by browser math. */
(function(g){
'use strict';
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;
  if(text!==undefined)e.textContent=String(text);return e};
const input=(type,name)=>{const e=el('input','jw-review-input');e.type=type;
  e.setAttribute('aria-label',name);return e};
const line=(parent,description,field)=>{
  const label=el('label','jw-review-action-label',description);
  label.append(field);parent.append(label);return field;
};
const button=(title)=>{const b=el('button','jw-review-action-button',title);b.type='button';return b};
const why=e=>e?.code==='STALE_SESSION'?'로그인 계정이 바뀌어 이전 응답을 폐기했습니다.':
  e?.code==='ADMIN_ONLY'?'입금 반제는 관리자만 가능합니다.':
  e?.code==='INVALID_PAYMENT_INPUT'?'입금 요청번호(영숫자 8자 이상), 잔액, 입금일을 확인하세요.':
  e?.code==='API_FAILURE'?'서버에서 입금 처리를 거부했습니다. 잔액과 요청번호를 확인하세요.':
  '서버 원장 대조에 실패했습니다. 최신 문서를 다시 확인하세요.';
async function render({bridge,view,isCurrent}){
  const user=bridge?.identity;
  if(!user||!bridge.signedIn||!view||typeof isCurrent!=='function')
    throw Error('FINANCE_REVIEW_CONTEXT_REQUIRED');
  const alive=()=>isCurrent()&&bridge.signedIn&&
    bridge.identity?.id===user.id&&bridge.identity?.org_id===user.org_id;
  const box=el('section','jw-review-finance-panel');
  box.append(el('h3','jw-review-cardtitle','청구서·입금·정산 · 원장 검증'));
  const status=el('p','jw-review-muted','서버 청구서 목록 확인 중');
  status.setAttribute('role','status');
  box.append(status);view.append(box);
  try{
    const invoices=await bridge.list('invoices');
    if(!alive())return;
    if(!invoices.length){status.textContent='발행된 청구서가 없습니다.';return}
    const shown=invoices.slice(0,30);
    status.textContent='청구서 '+shown.length+'건 · 금액과 잔액은 서버 원장 기준입니다.';
    for(const basic of shown){
      if(basic.org_id!==user.org_id)throw Error('TENANT_MISMATCH');
      const open=button(basic.doc_no+' · 입금·정산 확인');
      box.append(open);
      open.onclick=async()=>{
        if(!alive()||open.disabled)return;
        open.disabled=true;
        const panel=el('section','jw-review-card');
        const note=el('p','jw-review-muted','원장·문서 대조 중');
        note.setAttribute('role','status');panel.append(note);box.append(panel);
        try{
          let invoice=await bridge.financeInvoice(basic.id);
          const reconciliation=await bridge.financeReconcile(invoice.order_id,invoice);
          if(!alive())return;
          const summary=el('div','jw-review-finance-summary');
          const payments=el('section','jw-review-finance-payments');
          const controls=el('form','jw-review-action-form');
          const reference=line(controls,'입금 고유 요청번호',input('text','입금 고유 요청번호'));
          reference.minLength=8;reference.maxLength=100;reference.required=true;
          reference.autocomplete='off';
          const amount=line(controls,'입금액(원)',input('number','입금액(원)'));
          amount.min='1';amount.step='1';amount.required=true;
          const date=line(controls,'입금일',input('date','입금일'));
          date.required=true;date.value=new Date().toLocaleDateString('en-CA',{timeZone:'Asia/Seoul'});
          const save=el('button','jw-review-button','입금 원장 기록');
          save.type='submit';controls.append(save);
          panel.append(summary,payments,controls);
          const paint=()=>{
            summary.replaceChildren(
              el('h4','jw-review-cardtitle',invoice.doc_no+' · 실제 정산'),
              el('p','jw-review-row','청구 금액 '+invoice.money.total.toLocaleString('ko-KR')+'원'),
              el('p','jw-review-row','입금 합계 '+invoice.paid.toLocaleString('ko-KR')+'원'),
              el('p','jw-review-row','남은 잔액 '+invoice.balance.toLocaleString('ko-KR')+'원'),
              el('p','jw-review-muted','원본 견적 '+reconciliation.quote_money.total+
                '원 · 수주 '+reconciliation.order_money.total+
                '원 · 청구 '+reconciliation.invoice_money.total+'원'),
              el('p','jw-review-muted','견적→수주 변경 '+reconciliation.quote_to_order.length+
                '건 · 수주→청구 변경 '+reconciliation.order_to_invoice.length+'건'));
            payments.replaceChildren(el('h4','jw-review-cardtitle','입금 원장 및 반제 이력'));
            for(const p of invoice.payments){
              const row=el('div','jw-review-row',p.reference+' · '+p.amount+'원 · '+
                (p.reversed_at?'반제 완료':'입금 유지'));
              if(user.role==='admin'&&!p.reversed_at){
                const reverse=button('입금 반제 · '+p.reference);
                reverse.onclick=async()=>{
                  if(!alive()||reverse.disabled)return;
                  if(!window.confirm('입금 기록을 반제하면 잔액이 증가합니다. 서버 원장 기준으로 반제하시겠습니까?'))return;
                  reverse.disabled=true;note.textContent='관리자 반제 및 서버 재조회 중';
                  try{
                    invoice=await bridge.financeReverse(invoice.id,invoice,p.id);
                    if(!alive())return;
                    paint();note.textContent='입금 반제 및 서버 원장 재조회 완료';
                    note.setAttribute('role','status');
                  }catch(e){
                    if(alive()){note.textContent=why(e);note.setAttribute('role','alert')}
                  }finally{reverse.disabled=false}
                };
                row.append(reverse);
              }
              payments.append(row);
            }
            if(!invoice.payments.length)payments.append(el('p','jw-review-muted','입금 기록 없음'));
            controls.hidden=invoice.balance<=0;
            amount.max=String(invoice.balance);
          };
          controls.addEventListener('submit',async event=>{
            event.preventDefault();
            if(!alive()||save.disabled)return;
            if(!window.confirm('입금액과 요청번호를 원장에 기록하시겠습니까?'))return;
            save.disabled=true;note.textContent='서버 입금 처리 및 원장 재조회 중';
            try{
              const sum=Number(amount.value);
              const receipt=await bridge.financePay(invoice.id,invoice,reference.value,sum,date.value);
              if(!alive())return;
              invoice=receipt;paint();reference.value='';amount.value='';
              note.textContent='입금 처리·원장 잔액 재조회 완료';
              note.setAttribute('role','status');
            }catch(e){
              if(alive()){note.textContent=why(e);note.setAttribute('role','alert')}
            }finally{save.disabled=false}
          });
          paint();note.textContent='원본 수주·청구·입금 원장 대조 완료';
        }catch(e){if(alive()){note.textContent=why(e);note.setAttribute('role','alert')}}
        finally{open.disabled=false}
      };
    }
  }catch(e){if(alive()){status.textContent=why(e);status.setAttribute('role','alert')}}
}
g.JWOwnerFinanceReview={render};
if(typeof module==='object'&&module.exports)module.exports={render};
})(typeof window==='object'?window:globalThis);
