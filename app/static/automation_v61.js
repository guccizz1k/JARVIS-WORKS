/* JARVIS WORKS V6.1: isolated review UI for document conversion and evidence-labelled timing.
   Depends on authenticated app.js helpers. Never assumes tax invoice issuance or causal ROI. */
'use strict';
let automationManualRun = null;

function automationPageV61(){
  const s = state.automationSavings || {samples:{manual:0,automated:0},status:'NOT_MEASURED'};
  const choices=(state.orders || []).filter(x=>x.status==='fulfilled' && x.review_state!=='pending');
  const orders=choices.map(o=>`<article class="jw-auto-order"><div><strong>${e(o.doc_no)}</strong><p class="muted">${e(o.customer_name_snapshot)} · ${krw(o.money.total)}</p></div><div>${badge(o.review_state)}</div><div class="jw-auto-actions">${btn('auto-create','거래명세표 생성',o.id,'primary')} ${btn('auto-trace','거래 이력',o.id)}</div></article>`).join('');
  const sampleText=`수작업 ${s.samples.manual}건 · 자동화 ${s.samples.automated}건`;
  const difference=s.status==='COMPARISON_AVAILABLE' && s.observed_difference_ms!==null
    ? `관측 중위수 차이 ${Math.round(s.observed_difference_ms/1000)}초`:'비교할 수 있는 표본이 부족합니다';
  return title('원클릭 문서 작성 · 업무 자동화','기존 거래에서 다양한 문서를 만들고 거래 이력을 조회합니다.')+
    `<section class="panel"><div class="panel-body"><div class="notice">확정된 발주 자료를 그대로 재사용합니다. 변환된 거래명세표는 내부 거래 기록이며 공식 세금계산서나 전자납품 증빙이 아닙니다.</div>
    <div class="jw-auto-description"><strong>원클릭 문서 변환</strong><p class="muted">미처리 발주를 먼저 납품 완료로 전환한 뒤 사용하세요. 같은 발주는 재실행해도 기존 문서를 반환합니다.</p></div>
    ${choices.length?`<div class="jw-auto-order-list">${orders}</div>`:'<p class="muted">현재 변환 가능한 납품 완료 발주가 없습니다. 발주 관리에서 거래 상태를 확인하세요.</p>'}</div></section>
    <section class="panel" style="margin-top:18px"><div class="panel-header"><h2>업무 절감시간 측정</h2></div><div class="panel-body">
    <div class="notice">${e(difference)} · ${e(sampleText)}. 단순 관찰 비교이며 인과적 절감 효과나 ROI로 해석하지 않습니다.</div>
    <p class="muted">수작업은 실제로 작업을 진행하면서 시작·종료를 눌러 직접 기록합니다. 자동화는 위 거래명세표 생성 버튼을 클릭할 때 서버 처리시간을 측정합니다.</p>
    <div class="jw-auto-actions" style="margin-top:12px">${btn('auto-manual-start','수작업 측정 시작','', 'primary')}${btn('auto-manual-finish','수작업 완료 기록','')}${btn('auto-timer-cancel','진행 중 측정 취소','')}${btn('auto-refresh','측정 결과 새로고침','')}</div>
    <div class="muted" id="jw-auto-status" role="status" aria-live="polite" style="margin-top:12px">${state.automationActive?.mode==='automated'?'중단된 자동화 측정이 있습니다. 취소 후 다시 진행하세요':automationManualRun?'수작업 측정 진행 중':'진행 중인 측정 없음'}</div>
    <p class="muted" style="margin-top:12px">측정 화면은 개발 검증용이며, 이 수치로 실제 절감시간을 확정하지 않습니다.</p>
    </div></section>` + automationPageV62();
}

function automationStatementV61(d){
  const x=d.document;
  const rows=x.items.map(it=>`<tr><td>${e(it.name)}</td><td>${e(it.quantity)}</td><td>${krw(it.unit_price)}</td><td>${krw(it.line_total)}</td></tr>`).join('');
  return `<div class="details">${info('거래명세표 번호',e(d.doc_no))}${info('기준 발주번호',e(x.source_order_no))}${info('거래처',e(x.customer_name))}${info('상태','내부 거래 기록')}</div>`+
    table(['품목','수량','단가','금액'],rows)+`<div class="details">${info('공급가액',krw(x.money.subtotal))}${info('부가세',krw(x.money.vat))}${info('총액',krw(x.money.total))}</div>`+
    `<p class="muted">원본 발주서에서 생성한 수정 불가 스냅샷입니다. 세금계산서 또는 법적 납품 확인서를 대신하지 않습니다.</p>`;
}

function automationPrintV61(d,win){
  const x=d.document;
  if(!win)throw Error('팝업이 차단되었습니다. 팝업 허용 후 인쇄하세요.');
  const rows=x.items.map(it=>`<tr><td>${e(it.name)}</td><td>${e(it.quantity)}</td><td>${krw(it.unit_price)}</td><td>${krw(it.line_total)}</td></tr>`).join('');
  // All source-document fields are encoded as inert text in the print-only HTML.
  win.document.open();
  win.document.write(`<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>${e(d.doc_no)} 거래명세표</title><style>body{font:14px sans-serif;margin:40px auto;max-width:850px;color:#202c36}table{width:100%;border-collapse:collapse;margin:24px 0}th,td{padding:12px;border-bottom:1px solid #cad4e1;text-align:left}th{background:#f4f6fa}.sum{text-align:right;line-height:1.8}p{line-height:1.6}@media print{button{display:none}}</style></head><body><h1>거래명세표</h1><p>문서번호: ${e(d.doc_no)}<br>발주번호: ${e(x.source_order_no)}<br>거래처: ${e(x.customer_name)}</p><table><thead><tr><th>품목</th><th>수량</th><th>단가</th><th>합계</th></tr></thead><tbody>${rows}</tbody></table><p class="sum">공급가액 ${krw(x.money.subtotal)}<br>부가세 ${krw(x.money.vat)}<br><strong>합계 ${krw(x.money.total)}</strong></p><p>내부 업무용 거래 기록 · 공식 세금계산서 및 납품 확정 증빙 아님</p><button id="jw-print">인쇄 · PDF 저장</button></body></html>`);
  win.document.close();
  win.document.querySelector('#jw-print')?.addEventListener('click',()=>win.print());
}

async function handleAutomationV61(action,id){
  if(action.startsWith('auto-v62-'))return handleAutomationV62(action,id);
  if(action==='auto-refresh'){state.automationSavings=await api('/automation/time-savings');return navigate('automation')}
  if(action==='auto-manual-start'){
    if(automationManualRun)throw Error('이미 측정 중입니다');
    const run=await api('/automation/timing/start','POST',{workflow:'trade_statement',mode:'manual'});
    automationManualRun=run.id;
    const el=$('#jw-auto-status');if(el)el.textContent='수작업 측정 진행 중 · 업무 완료 후 기록하세요';
    return;
  }
  if(action==='auto-manual-finish'){
    if(!automationManualRun)throw Error('먼저 수작업 측정을 시작하세요');
    await api('/automation/timing/'+encodeURIComponent(automationManualRun)+'/finish','POST',{completed:true});
    automationManualRun=null;toast('수작업 시간이 기록됐습니다');return navigate('automation');
  }
  if(action==='auto-timer-cancel'){
    const active=await api('/automation/timing/active');
    if(!active)throw Error('진행 중인 측정이 없습니다');
    await api('/automation/timing/'+encodeURIComponent(active.id)+'/cancel','POST',{});
    automationManualRun=null;toast('미완료 측정을 취소했습니다');return navigate('automation');
  }
  if(action==='auto-create'){
    // Do not start a measurement for already-created documents.
    const trace=await api('/automation/transactions/'+encodeURIComponent(id));
    let run=null, result=null, completed=false;
    if(!trace.statement_id)run=await api('/automation/timing/start','POST',{workflow:'trade_statement',mode:'automated'});
    try{
      result=await api('/automation/statements/from-order','POST',{order_id:id});
      if(run && !result.reused){
        await api('/automation/timing/'+encodeURIComponent(run.id)+'/finish','POST',{completed:true,statement_id:result.id});
        completed=true;
      }
    }finally{
      // A failed request or concurrent conversion must not leave the user locked.
      if(run && !completed){
        try{await api('/automation/timing/'+encodeURIComponent(run.id)+'/cancel','POST',{})}catch{}
      }
    }
    toast(result.reused?'기존 거래명세표를 표시합니다':'거래명세표 작성 완료');
    const detail=automationStatementV61(result);
    modal('거래명세표',detail,'문서 내용을 확인한 후 인쇄하거나 PDF로 저장하세요.',btn('auto-print','인쇄 · PDF 저장',result.id,'primary'));
    return;
  }
  if(action==='auto-print'){
    // Reserve popup in the original click gesture; Safari may block delayed window.open.
    const printWindow=window.open('','_blank');
    if(!printWindow)throw Error('팝업이 차단되었습니다. 팝업을 허용하고 다시 시도하세요.');
    try{const detail=await api('/automation/statements/'+encodeURIComponent(id));return automationPrintV61(detail,printWindow)}
    catch(err){printWindow.close();throw err}
  }
  if(action==='auto-trace'){
    const tx=await api('/automation/transactions/'+encodeURIComponent(id));
    const labels={quote:'견적',order:'발주',trade_statement:'거래명세표',invoice:'청구',payment:'입금'};
    const rows=tx.events.map(ev=>`<tr><td>${e(labels[ev.type]||ev.type)}</td><td>${e(ev.no||'—')}</td><td>${e(ev.status)}</td><td>${e(fmtDate(ev.occurred_at))}</td></tr>`).join('');
    const content=table(['종류','문서 번호','상태','생성일'],rows)+`<div class="details">${info('발주 합계',krw(tx.order_money.total))}${info('청구 합계',tx.invoice_money?krw(tx.invoice_money.total):'미발행')}${info('유효 입금액',krw(tx.active_paid))}${info('미수금',tx.remaining_balance===null?'청구서 미발행':krw(tx.remaining_balance))}</div><p class="muted">기업별 접근권한을 확인한 거래 데이터입니다. 입금 취소 기록은 유효 입금액에 포함되지 않습니다.</p>`;
    modal('거래 통합 이력',content,'원본 문서의 수정 또는 자동 송금은 수행하지 않습니다.');return;
  }
  throw Error('지원하지 않는 자동화 작업입니다');
}
