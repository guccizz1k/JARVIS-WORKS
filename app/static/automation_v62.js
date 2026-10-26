/* JARVIS WORKS V6.2 — internal business document drafts. No auto-dispatch. */
'use strict';
function automationPageV62(){
  const quotes=(state.quotes||[]).filter(x=>x.status==='accepted').slice(0,12);
  const orders=(state.orders||[]).filter(x=>x.status==='fulfilled' && x.review_state!=='pending').slice(0,20);
  const invoices=(state.invoices||[]).filter(x=>x.status==='issued' && x.balance>0).slice(0,12);
  const cards=(rows,action,button)=>rows.map(x=>`<article class="jw-auto-order"><div><strong>${e(x.doc_no)}</strong><p class="muted">${e(x.customer_name_snapshot||x.customer_name)} · ${krw(x.money.total)}</p></div><div class="jw-auto-actions">${btn(action,button,x.id,'primary')}</div></article>`).join('');
  return `<section class="panel jw-v62-panel" style="margin-top:18px"><div class="panel-header"><h2>추가 원클릭 문서 작성</h2></div><div class="panel-body">
    <div class="notice">기존 확정 거래를 이용해 내부 검토용 초안을 작성합니다. 실제 수주·납품·송금·세금계산서 발행은 자동 실행되지 않습니다.</div>
    <h3 class="section-title">승인 견적 → 수주서 초안</h3>${cards(quotes,'auto-v62-sales','수주서 초안')||'<p class="muted">승인된 견적이 없습니다.</p>'}
    <h3 class="section-title">납품 완료 발주 → 납품서 초안</h3>${orders.length?`<div class="jw-v62-selects">${orders.map(x=>`<label class="jw-v62-select"><input type="checkbox" class="jw-v62-order" value="${e(x.id)}"><span>${e(x.doc_no)} · ${e(x.customer_name_snapshot||x.customer_name)} · ${krw(x.money.total)}</span></label>`).join('')}</div><div class="jw-auto-actions" style="margin-top:12px">${btn('auto-v62-batch','선택한 발주 일괄 변환','', 'primary')}</div>`:'<p class="muted">검증 완료된 납품 완료 발주가 없습니다.</p>'}
    <h3 class="section-title">미수 청구 → 입금요청서 초안</h3>${cards(invoices,'auto-v62-payment','입금요청서 초안')||'<p class="muted">미수 청구서가 없습니다.</p>'}
    </div></section>`;
}
function automationDetailV62(d){
  const x=d.document;
  const rows=x.items.map(v=>`<tr><td>${e(v.name)}</td><td>${e(v.quantity)}</td><td>${krw(v.unit_price)}</td><td>${krw(v.line_total)}</td></tr>`).join('');
  return `<div class="details">${info('문서 유형',e(x.label))}${info('문서 번호',e(d.document_no))}${info('원본 번호',e(x.source_no))}${info('거래처',e(x.customer_name))}</div>${table(['품목','수량','단가','금액'],rows)}<div class="details">${info('공급가액',krw(x.money.subtotal))}${info('부가세',krw(x.money.vat))}${info('합계',krw(x.money.total))}${x.balance_at_creation===null?'':info('생성 시점 미수금',krw(x.balance_at_creation))}</div><p class="muted">변환 시점의 거래 내용을 보존하는 내부 검토 초안입니다. 입금 금액 등 현재 실시간 상태는 원본 거래에서 재확인하세요.</p>`;
}
function automationShowV62(d){
  modal(d.document.label,automationDetailV62(d),d.stale?'입금 잔액 변경으로 오래된 초안입니다. 재발행 및 출력이 차단됩니다.':d.reused?'이미 생성된 초안을 재표시합니다.':'거래 정보를 재입력하지 않고 만든 검토용 초안입니다.',d.stale?'':btn('auto-v62-xlsx','Excel 다운로드',d.id,'primary')+' '+btn('auto-v62-print','인쇄 · PDF 저장',d.id));
}
function automationPrintDraftV62(d, win){
  if(!win)throw Error('팝업이 차단되었습니다. 브라우저 팝업 설정을 확인하세요.');
  const x=d.document;
  const rows=x.items.map(v=>`<tr><td>${e(v.name)}</td><td>${e(v.quantity)}</td><td>${krw(v.unit_price)}</td><td>${krw(v.line_total)}</td></tr>`).join('');
  win.document.open();
  win.document.write(`<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>${e(d.document_no)} ${e(x.label)}</title><style>body{font:14px system-ui,sans-serif;color:#243047;max-width:830px;margin:35px auto;padding:0 18px}h1{font-size:25px}p{line-height:1.7}table{border-collapse:collapse;width:100%;margin:25px 0}th,td{border-bottom:1px solid #cbd5e1;padding:11px;text-align:left;overflow-wrap:anywhere}th{background:#eef3f9}.total{text-align:right;font-weight:700}.disclaimer{border-top:2px solid #94a3b8;padding-top:14px;color:#555}@media print{button{display:none}}</style></head><body><h1>${e(x.label)}</h1><p>문서 번호: ${e(d.document_no)}<br>원본: ${e(x.source_no)}<br>거래처: ${e(x.customer_name)}</p><table><thead><tr><th>품목</th><th>수량</th><th>단가</th><th>금액</th></tr></thead><tbody>${rows}</tbody></table><p class="total">공급가액 ${krw(x.money.subtotal)} · 부가세 ${krw(x.money.vat)} · 합계 ${krw(x.money.total)}</p>${x.balance_at_creation===null?'':`<p>생성 당시 미수 잔액: ${krw(x.balance_at_creation)}</p>`}<p class="disclaimer">내부 업무 검토용 · 수주/납품/회계/입금 확정이 아니며 공식 세금계산서가 아닙니다.</p><button id="jw-v62-print">인쇄 · PDF로 저장</button></body></html>`);
  win.document.close();
  win.document.querySelector('#jw-v62-print')?.addEventListener('click',()=>win.print());
}
async function automationDownloadV62(id){
  const response=await fetch('/api/automation/drafts/'+encodeURIComponent(id)+'/xlsx',{credentials:'same-origin',cache:'no-store'});
  if(!response.ok)throw Error('엑셀 문서를 내려받지 못했습니다');
  const blob=await response.blob();
  if(blob.size>2*1024*1024 || blob.size===0)throw Error('예상 범위를 벗어난 문서 응답입니다');
  const url=URL.createObjectURL(blob), a=document.createElement('a');
  a.href=url;a.download='JW-Document-'+id.slice(0,12)+'.xlsx';document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),500);
}
async function handleAutomationV62(action,id){
  if(action==='auto-v62-sales' || action==='auto-v62-payment'){
    const kind=action==='auto-v62-sales'?'sales_order_draft':'payment_request_draft';
    const result=await api('/automation/drafts/from-source','POST',{source_id:id,kind});
    automationShowV62(result);return;
  }
  if(action==='auto-v62-batch'){
    const ids=Array.from(document.querySelectorAll('.jw-v62-order:checked')).map(el=>el.value);
    if(!ids.length)throw Error('먼저 변환할 발주를 선택하세요');
    if(ids.length>20)throw Error('한 번에 최대 20건까지만 변환할 수 있습니다');
    const result=await api('/automation/drafts/batch','POST',{kind:'delivery_note_draft',source_ids:ids});
    toast('납품서 초안 '+result.count+'건 확인 · 신규 '+result.created+'건');
    if(result.documents.length===1)automationShowV62(result.documents[0]);
    else modal('일괄 변환 완료',`<p>총 ${result.count}건 · 신규 ${result.created}건 · 기존 문서 ${result.reused}건</p>`+result.documents.map(x=>`<div class="jw-v62-result"><span>${e(x.document_no)} · ${e(x.document.customer_name)}</span>${btn('auto-v62-open','내용 확인',x.id)}</div>`).join(''),'문서 생성은 일괄 트랜잭션으로 수행했습니다.');
    return;
  }
  if(action==='auto-v62-open'){automationShowV62(await api('/automation/drafts/'+encodeURIComponent(id)));return;}
  if(action==='auto-v62-print'){
    // Reserve the window synchronously in the user gesture (Safari popup policy).
    const win=window.open('','_blank');
    if(!win)throw Error('팝업이 차단되었습니다. 팝업 허용 후 다시 시도하세요.');
    try{
      const d=await api('/automation/drafts/'+encodeURIComponent(id));
      if(d.stale)throw Error('입금 잔액이 변경된 이전 초안은 인쇄할 수 없습니다');
      automationPrintDraftV62(d,win);
    }catch(err){win.close();throw err}
    return;
  }
  if(action==='auto-v62-xlsx'){await automationDownloadV62(id);return;}
  throw Error('지원하지 않는 문서 변환 기능입니다');
}
