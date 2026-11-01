/* V20.4 sunset reference UI renderer: SOURCE-BOUND values only. No fake trend, API,
   timer polling, business writes, authentication/authorization changes. */
(function () {
 'use strict';
 const safe = value => e(value==null?'':String(value));
 const n = value => {const x=Number(value);return Number.isFinite(x)?Math.max(0,x):0;};
 const won = value => krw(n(value));
 const pct = (a,b) => b>0?Math.max(0,Math.min(100,Math.round(a*100/b))):0;
 const iconPaths={
   workflow:'<path d="M5 4v5M5 9h8a3 3 0 0 1 3 3v3M5 9h5M16 15v5M13 17h6"/>',
   doc:'<path d="M8 3h7l5 5v13H5V3h3M15 3v5h5M9 13h7M9 17h7"/>',
   trade:'<path d="m7 7 4-4 4 4M11 3v10M17 17l-4 4-4-4M13 21V11"/>',
   coins:'<ellipse cx="12" cy="5.5" rx="8" ry="3.5"/><path d="M4 5.5v6c0 2 3.5 3.5 8 3.5s8-1.5 8-3.5v-6M4 11v6c0 2 3.5 3.5 8 3.5s8-1.5 8-3.5v-6"/>',
   check:'<path d="m4 13 5 5L20 6"/>',
   message:'<path d="M20 11a8 8 0 0 1-8 8H5l-2 3v-8a8 8 0 1 1 17-3Z"/>',
   arrow:'<path d="M4 12h16m-7-7 7 7-7 7"/>',
   calendar:'<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M7 3v5M17 3v5M3 10h18"/>'
 };
 const ico = (key) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'+(iconPaths[key]||iconPaths.doc)+'</svg>';
 const navBtn=(target,label,content,css='')=>'<button type="button" class="'+css+'" data-v204-nav="'+safe(target)+'" aria-label="'+safe(label)+'">'+content+'</button>';
 function miniCurve(tint){return '<svg class="v204-mini-curve" viewBox="0 0 70 30" fill="none" aria-hidden="true"><path d="M2 23C12 22 15 9 23 15s15 8 23-3S61 15 68 4" stroke="'+tint+'" stroke-width="2" stroke-linecap="round"/></svg>';}
 function stat(label,value,foot,icon,target,tint) {
   return navBtn(target,label+' 자세히 열기','<div class="v204-stat-top"><span class="v204-stat-icon">'+ico(icon)+'</span>'+miniCurve(tint)+'</div>'
    +'<span class="v204-stat-label">'+safe(label)+'</span><strong class="v204-stat-value">'+safe(value)+'</strong>'
    +'<span class="v204-stat-caption">'+safe(foot)+'</span>','v204-glass v204-stat');
 }
 function task(doc,tag,route,good=false) {
  const title=safe(doc.title||doc.doc_no||doc.message||'업무 검토');
  const detail=safe(doc.customer_name||doc.customer_name_snapshot||doc.description||doc.doc_no||'');
  return navBtn(route,title,
   '<span class="v204-task-symbol">'+ico(route==='imports'?'doc':'trade')+'</span>'
   +'<span class="v204-task-copy"><b>'+title+'</b><small>'+detail+'</small></span>'
   +'<span class="v204-tag'+(good?' good':'')+'">'+safe(tag)+'</span>','v204-task');
 }
 function itemList(items,route,tag='확인') {
  if(!items.length)return '<div class="v204-zero">해당 업무 기록이 없습니다. 새로운 항목은 실제 등록된 데이터에서만 표시됩니다.</div>';
  return items.slice(0,4).map(x=>task(x,tag,route,tag==='완료')).join('');
 }
 function sectionHead(name,countText,route){
  return '<div class="v204-panel-heading"><h2>'+safe(name)+(countText?'<span class="v204-bubble-count">'+safe(countText)+'</span>':'')+'</h2>'
   +navBtn(route,name+' 전체 보기','전체보기  ›','v204-link')+'</div>';
 }
 function chartSection(d,selection){
  const all=[['거래처',n(d.customers)],['견적',n(d.quotes)],['수주·발주',n(d.orders)],['청구',n(d.invoices)]];
  const blocks=selection==='documents'?all.map((x,i)=>i===0?['거래처',0]:x):
    selection==='trades'?[all[0],all[1],all[2],['청구',0]]:all;
  const mx=Math.max(1,...blocks.map(x=>x[1]));
  return '<div class="v204-chart-grid"></div><div class="v204-chart-bars">'
   +blocks.map((x,i)=>'<button type="button" class="v204-chart-bar-container" data-v204-inspect="'+safe(x[0])+'" aria-label="'+safe(x[0])+' '+x[1]+'건, 상세 보기"><div class="v204-chart-bar'+(i===2?' chosen':'')+'" style="--bar-height:'+Math.max(4,Math.round(x[1]/mx*83))+'%">'
   +'<span class="v204-chart-value">'+x[1]+'</span></div><span>'+safe(x[0])+'</span></button>').join('')
   +'</div>';
 }
 dashboardPage = function v204Dashboard() {
  const d=state.dashboard||{},user=state.user||{};
  const issues=Array.isArray(d.issues)?d.issues:[];
  const quotes=Array.isArray(d.recent_quotes)?d.recent_quotes:[];
  const orders=Array.isArray(d.recent_orders)?d.recent_orders:[];
  const drafts=Array.isArray(state.quotes)?state.quotes.filter(x=>x.status==='draft'):[];
  const docs=quotes.length?quotes:orders;
  const collected=n(d.collected),outstanding=n(d.outstanding),cashRate=pct(collected,collected+outstanding);
  const docTotal=n(d.quotes)+n(d.orders)+n(d.invoices);
  // Approval counts are not invented: issues are the only confirmed risk/needs-review source.
  const scheduled=[...issues.map(x=>({...x,stage:'확인 필요'})),...drafts.map(x=>({...x,stage:'초안 검토'}))];
  return '<div class="jw-v204 v204-enter" aria-label="JARVIS WORKS 노을 글래스 업무 대시보드">'
   +'<section class="v204-head" aria-label="업무 핵심 현황">'
   +'<div class="v204-glass v204-hero"><div class="v204-kicker">JARVIS WORKS / BUSINESS SPACE</div><h1>안녕하세요, '+safe(user.name||'사용자')+'님</h1>'
     +'<p>기업의 업무 흐름을 더 스마트하게.<br>문서 검토부터 거래·정산까지 하나의 워크스페이스에서 관리합니다.</p></div>'
   +stat('등록된 문서',docTotal+'건','견적 · 발주 · 청구', 'workflow','imports','#94f3c2')
   +stat('검토할 항목',issues.length+'건','실제 업무 위험 알림','doc','automation','#9dccff')
   +stat('미수금',won(outstanding),'기록된 입금만 반영','trade','invoices','#c3aeff')
   +stat('누적 입금',won(collected),'실제 입금 기록','coins','invoices','#ffe4b8')
   +'</section>'
   +'<section class="v204-middle" aria-label="주요 업무">'
   +'<article class="v204-glass v204-approvals">'+sectionHead('확인 필요',issues.length+'건','automation')
    +'<div class="v204-item-list">'+itemList(issues,'automation','확인')+'</div></article>'
   +'<article class="v204-glass v204-chart">'
     +'<div class="v204-chart-head"><div><h2>워크플로우 현황</h2><p>실제 기업 데이터 · 유형별 등록 건수 (시계열 아님)</p></div>'
     +'<div class="v204-tabs" role="group" aria-label="그래프 보기"><button type="button" data-v204-filter="all" aria-pressed="true">전체</button>'
     +'<button type="button" data-v204-filter="documents" aria-pressed="false">문서</button><button type="button" data-v204-filter="trades" aria-pressed="false">거래</button></div></div>'
     +'<div class="v204-chart-canvas" id="v204-chart-canvas">'+chartSection(d,'all')+'</div>'
     +'<div class="v204-chart-description">견적 '+n(d.quotes)+'건 · 수주·발주 '+n(d.orders)+'건 · 청구 '+n(d.invoices)+'건</div>'
    +'</article>'
   +'<article class="v204-glass v204-schedule">'+sectionHead('오늘의 업무',scheduled.length+'건','automation')
    +'<div class="v204-item-list">'+itemList(scheduled,'automation','대기')+'</div></article>'
   +'</section>'
   +'<section class="v204-lower" aria-label="업무 상세 현황">'
   +'<article class="v204-glass v204-docs">'+sectionHead('문서 검토 현황','','imports')
    +'<div class="v204-docs-layout"><div class="v204-doc-art" role="img" aria-label="입체적으로 겹쳐진 문서 파일"><i></i><i></i><i></i></div>'
    +'<div><div class="v204-donut" style="--done:'+cashRate+'%" role="img" aria-label="등록된 입금 비중 '+cashRate+'퍼센트"><strong>'+cashRate+'%</strong></div>'
    +'<span class="v204-donut-note">기록된 입금액 비중<br>문서 인식 정확도 아님</span></div></div></article>'
   +'<article class="v204-glass v204-trades">'+sectionHead('거래 관리 현황','','orders')
    +'<div class="v204-trade-visual"><div class="v204-trade-art" aria-hidden="true"><i></i><i></i></div>'
    +'<div><div class="v204-trade-small">수주·발주 기록</div><div class="v204-trade-big">'+n(d.orders)+'건</div>'
    +'<div class="v204-trade-small">미수금 '+won(outstanding)+'</div>'
    +'<div class="v204-trade-micro"><span>견적 '+n(d.quotes)+'건</span><span>청구 '+n(d.invoices)+'건</span></div></div></div></article>'
   +'<article class="v204-glass v204-chat">'+sectionHead('메신저','','messenger')
    +'<div class="v204-item-list">'
    +navBtn('messenger','기업 거래 메시지 열기','<span class="v204-task-symbol">'+ico('message')+'</span><span class="v204-task-copy"><b>기업 간 업무 대화</b><small>가입 기업과 메시지 및 파일 전송</small></span>','v204-task')
    +navBtn('messenger','거래 파일 공유하기','<span class="v204-task-symbol">'+ico('doc')+'</span><span class="v204-task-copy"><b>거래 자료 공유</b><small>파일 · 사진 · 발주서 전달</small></span>','v204-task')
    +'</div></article>'
   +'</section>'
   +'<section class="v204-glass v204-activity" aria-label="최근 활동"><strong>ϟ 최근 활동</strong><div class="v204-ticker">'
    +(docs.length?docs.slice(0,5).map(x=>navBtn(quotes.length?'quotes':'orders','업무 기록 열기',
     '<b>✓</b><span>'+safe(x.doc_no||x.title||'등록 문서')+' · '+safe(x.customer_name||x.customer_name_snapshot||'거래처')+'</span>','v204-ticker-item')).join('')
     :'<span class="v204-ticker-item">실제 등록된 업무 기록이 없습니다.</span>')
    +'</div></section>'
   +'<p style="font-size:10px;line-height:1.8;color:#fff3e9bc;padding:12px 7px">모든 수치는 현재 로그인 기업의 조회 데이터입니다. 시간대별 변화·가상 회의 일정·AI 실시간 처리율은 제공하지 않습니다. 금액은 기록된 청구 및 입금 데이터 기준입니다.</p>'
   +'</div>';
 };
 // Video reference navigation: floating top pill, while preserving upload-first original menu.
 const dock=document.createElement('nav');dock.id='v204-floating-nav';dock.className='v204-top-tabs v204-floating-nav';
 dock.setAttribute('aria-label','상단 업무 화면 전환');
 [['dashboard','홈','workflow'],['imports','문서','doc'],['orders','거래','trade'],['invoices','정산','coins'],['messenger','메신저','message']].forEach(([page,label,icon])=>{
   const b=document.createElement('button');b.type='button';b.dataset.v204Nav=page;
   b.className='v204-nav-pill';b.setAttribute('aria-label',label+' 화면 열기');
   const symbol=document.createElement('span');symbol.innerHTML=ico(icon);symbol.setAttribute('aria-hidden','true');
   const copy=document.createElement('span');copy.textContent=label;b.append(symbol,copy);dock.appendChild(b);
 });
 document.querySelector('.app-shell .topbar')?.appendChild(dock);
 const syncNav=()=>dock.querySelectorAll('button').forEach(b=>b.setAttribute('aria-current',state.page===b.dataset.v204Nav?'page':'false'));
 document.querySelectorAll('.sidebar .nav-item').forEach(b=>{
   b.setAttribute('data-v204-label',(b.innerText||'업무 메뉴').trim().replace(/대표 기능/g,'').slice(0,29));
   const rail=b.querySelector('.nav-ico'),map={dashboard:'workflow',imports:'doc',automation:'workflow',messenger:'message',customers:'trade',quotes:'doc',orders:'trade',invoices:'coins',audit:'calendar',security:'check'};
   if(rail && map[b.dataset.page])rail.innerHTML=ico(map[b.dataset.page]);
   b.addEventListener('click',()=>requestAnimationFrame(syncNav));
 });
 const navRoot=document.getElementById('nav');
 if(navRoot)new MutationObserver(syncNav).observe(navRoot,{subtree:true,attributes:true,attributeFilter:['class']});
 syncNav();
 let inspectFocus=null;
 function closeInspector(){
   const node=document.querySelector('.jw-v204 > .v204-overlay');if(!node)return;
   node.classList.add('v204-closing');
   if(matchMedia('(prefers-reduced-motion:reduce)').matches){node.remove();inspectFocus?.focus();return;}
   setTimeout(()=>{node.remove();inspectFocus?.focus();},235);
 }
 function openInspector(kind,origin){
   const d=state.dashboard||{};
   const specs={'거래처':['등록된 거래처',n(d.customers),'현재 기업에 등록된 거래처 기준입니다.','customers'],
    '견적':['등록된 견적',n(d.quotes),'현재 기업에 등록된 견적서 기준입니다.','quotes'],
    '수주·발주':['수주·발주 문서',n(d.orders),'현재 기업에 등록된 수주·발주 문서 기준입니다.','orders'],
    '청구':['청구 문서',n(d.invoices),'현재 기업에 등록된 청구 문서 기준입니다.','invoices']};
   const info=specs[kind];if(!info)return;
   document.querySelector('.jw-v204 > .v204-overlay')?.remove();inspectFocus=origin;
   const root=document.querySelector('.jw-v204');if(!root)return;
   const overlay=document.createElement('div');overlay.className='v204-overlay';
   overlay.innerHTML='<section class="v204-details" role="dialog" aria-modal="true" aria-labelledby="v204-inspect-title">'
   +'<button type="button" class="v204-close" aria-label="상세 창 닫기" data-v204-close>×</button>'
   +'<p class="v204-kicker">ACTUAL BUSINESS DATA</p><h2 id="v204-inspect-title">'+safe(info[0])+'</h2>'
   +'<div class="v204-inspect-value">'+info[1]+'<span> 건</span></div><p>'+safe(info[2])+'</p>'
   +'<button type="button" class="v204-inspect-go" data-v204-nav="'+info[3]+'">해당 업무 열기 ↗</button>'
   +'</section>';
   root.appendChild(overlay);overlay.querySelector('.v204-close').focus();
 }
 document.addEventListener('click',function (ev) {
  if(ev.target.closest('[data-v204-close]')||ev.target.classList.contains('v204-overlay')){closeInspector();return;}
  const bar=ev.target.closest('.jw-v204 [data-v204-inspect]');
  if(bar){openInspector(bar.dataset.v204Inspect,bar);return;}
  const nav=ev.target.closest('[data-v204-nav]');
  if(nav){const target=nav.getAttribute('data-v204-nav');if(!['dashboard','imports','automation','messenger','customers','quotes','orders','invoices','audit','security'].includes(target))return;
    const button=document.querySelector('#nav [data-page="'+target+'"]');if(button&&!button.hidden)button.click();return;}
  const filter=ev.target.closest('[data-v204-filter]');
  if(filter){const root=filter.closest('.jw-v204'),canvas=root&&root.querySelector('#v204-chart-canvas');
   if(!canvas)return;const type=filter.getAttribute('data-v204-filter');
   if(!['all','documents','trades'].includes(type))return;
   root.querySelectorAll('[data-v204-filter]').forEach(b=>b.setAttribute('aria-pressed',String(b===filter)));
   canvas.innerHTML=chartSection(state.dashboard||{},type);}
 });
 document.addEventListener('keydown',ev=>{if(ev.key==='Escape')closeInspector();});
})();
