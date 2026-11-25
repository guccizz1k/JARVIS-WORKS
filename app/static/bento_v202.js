/* V20.2: Reference-led UI renderer. All numbers from authenticated API state.
   No new write paths, credentials, backend privileges or fabricated metrics. */
(function () {
  'use strict';
  const safe = value => e(value);
  const count = value => Number.isFinite(Number(value)) ? Math.max(0,Number(value)) : 0;
  const money = value => krw(count(value));
  const progress = (num,den) => den>0 ? Math.max(0,Math.min(100,Math.round(100*num/den))) : 0;
  function metric(label,value,note,icon,featured,kind) {
    return '<article class="jw-v202-metric'+(featured?' primary':'')+'">'
      +'<span class="metric-icon" aria-hidden="true">'+safe(icon)+'</span>'
      +'<div class="kicker">'+safe(label)+'</div>'
      +'<div class="metric-value'+(kind==='money'?' money':'')+'">'+safe(value)+'</div>'
      +'<div class="metric-note">'+safe(note)+'</div></article>';
  }
  function dataBars(d) {
    const entries=[['견적서',count(d.quotes)],['수주·발주',count(d.orders)],['청구서',count(d.invoices)]];
    const max=Math.max(1,...entries.map(x=>x[1]));
    return entries.map(row=>'<div class="jw-v202-chart-row">'
      +'<span>'+safe(row[0])+'</span><div class="jw-v202-chart-track" role="img" aria-label="'
      +safe(row[0])+' '+row[1]+'건"><i style="--w:'+progress(row[1],max)+'%"></i></div>'
      +'<strong>'+row[1]+'건</strong></div>').join('');
  }
  function taskList(data,max,icon,href) {
    return data.slice(0,max).map(x=>'<div class="jw-v202-task">'+safe(x.title||x.doc_no||'업무 기록')
      +'<small>'+safe(x.doc_no||x.customer_name||'')+'</small></div>').join('');
  }
  function panelTitle(name,desc,action) {
    return '<div class="jw-v202-panel-head"><div><h2>'+safe(name)+'</h2><small>'
      +safe(desc)+'</small></div>'+(action||'')+'</div>';
  }
  function reviewRows(d) {
    const recent=Array.isArray(d.recent_quotes)?d.recent_quotes:[];
    if(!recent.length)return '<div class="jw-v202-empty">등록된 견적서가 없습니다. 문서를 업로드해 시작하세요.</div>';
    return recent.slice(0,4).map(q=>'<div class="jw-v202-work">'
      +'<span class="jw-v202-work-icon" aria-hidden="true">▤</span>'
      +'<div><strong>'+safe(q.doc_no||'견적서')+'</strong><small>'
      +safe(q.customer_name||'거래처 미기재')+' · '+money(q.money?.total)+'</small></div>'
      +badge(q.status||'draft')+'</div>').join('');
  }
  // Replaces only the presentation returned by the existing dashboardPage()
  // function; the API, escape helper, click-action delegation remain original.
  dashboardPage = function dashboardPageV202() {
    const d = state.dashboard || {};
    const issues = Array.isArray(d.issues) ? d.issues : [];
    const drafts = Array.isArray(state.quotes) ? state.quotes.filter(x=>x.status==='draft') : [];
    const finished = Array.isArray(d.recent_orders)
      ? d.recent_orders.filter(x=>x.status==='fulfilled') : [];
    const collected=count(d.collected), outstanding=count(d.outstanding);
    const collectionRate=progress(collected,collected+outstanding);
    const automated=count(state.automationDraftSummary?.total);
    const issueNote=issues.length ? issues.length+'건 확인 필요':'확인할 위험 알림 없음';
    return '<div class="jw-v202-dashboard">'
      +'<div class="jw-v202-welcome"><span class="jw-v202-status-dot" aria-hidden="true"></span> WORKSPACE / OVERVIEW</div>'
      +title('업무 대시보드','오늘의 거래 현황과 승인 대기 업무를 확인하세요.',
        btn('go-imports','＋ 새 문서 등록','','primary'))
      +'<section class="jw-v202-bento" aria-label="실제 업무 지표">'
        +metric('전체 견적서',count(d.quotes)+'건','등록된 견적 기록','▤',true)
        +metric('등록된 기업',count(d.customers)+'곳','현재 기업의 거래처','♧')
        +metric('수주·발주',count(d.orders)+'건','등록된 거래 문서','≡')
        +metric('확인할 업무',issues.length+'건',issueNote,'!',false)
        +'<div class="jw-v202-feature"><small>DOCUMENT AUTOMATION</small>'
          +'<h2>문서 한 장에서<br>연결되는 업무의 흐름</h2>'
          +'<p>원본 확인 → 견적 → 수주·발주 → 청구까지. 모든 단계는 검증·승인 후 처리됩니다.</p>'
          +btn('go-imports','문서 업로드 시작','','primary')+'</div>'
        +'<div class="jw-v202-gauges">'
          +'<div class="jw-v202-gauge"><strong>누적 입금액</strong>'
            +'<div class="gauge-value">'+money(collected)+'</div>'
            +'<div class="gauge-note">서비스에 기록된 입금만 반영</div>'
            +'<div class="jw-v202-track" role="img" aria-label="등록된 입금 대비 미수 포함 비율 '+collectionRate+'퍼센트">'
            +'<b style="--w:'+collectionRate+'%"></b></div></div>'
          +'<div class="jw-v202-gauge"><strong>미수금</strong>'
            +'<div class="gauge-value">'+money(outstanding)+'</div>'
            +'<div class="gauge-note">청구액에서 등록된 입금액 차감</div>'
            +'<div class="jw-v202-track" role="img" aria-label="미수 비중 '+(collected+outstanding>0?100-collectionRate:0)+'퍼센트">'
            +'<b style="--w:'+(collected+outstanding>0?100-collectionRate:0)+'%"></b></div></div>'
        +'</div>'
      +'</section>'
      +'<div class="jw-v202-lower">'
        +'<section class="jw-v202-panel">'
          +panelTitle('업무 단계별 현황','실제 등록 건수 · 시계열 추정치가 아닙니다',
            btn('go-orders','전체 거래','','ghost'))
          +'<div class="jw-v202-bar-chart">'+dataBars(d)
            +'<div class="jw-v202-chart-legend">각 막대는 가장 많은 단계의 건수를 기준으로 표현됩니다.</div></div>'
        +'</section>'
        +'<section class="jw-v202-panel">'
          +panelTitle('최근 견적서','실제 등록된 문서 기준',btn('go-quotes','전체 보기','','ghost'))
          +'<div class="jw-v202-worklist">'+reviewRows(d)+'</div>'
        +'</section>'
      +'</div>'
      +'<section class="jw-v202-board">'
        +panelTitle('업무 보드','실제 확인 요청과 거래 상태에 따라 자동 분류',
          btn('go-automation','문서 자동화','','ghost'))
        +'<div class="jw-v202-columns">'
          +'<div class="jw-v202-column"><h3>확인 필요 <span class="jw-v202-count">'+issues.length+'</span></h3>'
            +(issues.length?taskList(issues,4):'<div class="jw-v202-empty">현재 확인할 업무가 없습니다.</div>')+'</div>'
          +'<div class="jw-v202-column"><h3>견적 초안 <span class="jw-v202-count">'+drafts.length+'</span></h3>'
            +(drafts.length?taskList(drafts,4):'<div class="jw-v202-empty">등록된 초안이 없습니다.</div>')+'</div>'
          +'<div class="jw-v202-column"><h3>납품 완료 <span class="jw-v202-count">'+finished.length+'</span></h3>'
            +(finished.length?taskList(finished,4):'<div class="jw-v202-empty">표시할 완료 내역이 없습니다.</div>')+'</div>'
        +'</div>'
      +'</section>'
      +'<div class="jw-v202-tail"><section class="panel">'
        +head('원클릭 자동 작성 문서',btn('go-automation','문서 작업으로 이동','','primary'))
        +'<div class="panel-body"><strong>'+automated+'건</strong>'
          +'<p class="muted">작성·검증된 내부 초안 기준. 공식 발행·상대방 승인과 구분됩니다.</p>'
          +(state.automationDraftSummary?.recent||[]).slice(0,5).map(doc=>
              '<div class="jw-v62-result"><span>'+safe(doc.document_no)+'</span>'
              +btn('auto-v62-open','초안 보기',doc.id)+'</div>').join('')
          +'</div></section>'
        +evidenceDashboardV64(d.evidence)
        +'<div class="notice">표시된 금액은 실제 등록된 거래 문서와 입금 기록에 근거합니다. '
        +'<b>공식 세금계산서 발행이나 금융기관 자동 입금 조회는 제공하지 않습니다.</b></div>'
      +'</div></div>';
  };
  function applyTheme(theme) {
    const use = theme === 'blue' ? 'blue' : 'green';
    document.documentElement.setAttribute('data-jw-theme',use);
    const control=document.getElementById('jw-v202-theme-toggle');
    if(control){
      control.setAttribute('aria-label','강조색 변경: 현재 '+(use==='blue'?'파랑':'녹색'));
      control.querySelector('span').textContent=use==='blue'?'● 파랑':'● 녹색';
    }
    try{localStorage.setItem('jw-v202-theme',use);}catch(_){}
  }
  document.addEventListener('click',ev=>{
    if(ev.target.closest('#jw-v202-theme-toggle')) {
      const next=document.documentElement.getAttribute('data-jw-theme')==='blue'?'green':'blue';
      applyTheme(next);
    }
  });
  try{applyTheme(localStorage.getItem('jw-v202-theme')||'green');}catch(_){applyTheme('green');}
})();
