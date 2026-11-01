/* JARVIS WORKS V20.6 · Premium translucent workspace.
 * Additive presentation only. Original authenticated API, forms and routes remain.
 * Preserves source-bound values and does not fabricate business efficiency gains.
 */
(() => {
 'use strict';
 const shell=document.getElementById('app-shell');
 const sidebar=document.getElementById('sidebar');
 const nav=document.getElementById('nav');
 const top=document.querySelector('.app-shell .topbar');
 if(!shell||!sidebar||!nav||!top)return;
 const safe = v=>e(v==null?'':String(v));
 const count=v=>{const n=Number(v);return Number.isFinite(n)?Math.max(0,n):0};
 const money=v=>krw(count(v));
 const allowed=['dashboard','imports','orders','invoices','messenger','automation','customers','quotes','audit','security'];
 const primary=['dashboard','imports','orders','messenger','automation'];
 const labels={dashboard:'대시보드',imports:'문서 자동 등록',orders:'수주·발주',invoices:'청구·입금',messenger:'메신저',automation:'업무 자동화',customers:'거래처',quotes:'견적 관리',audit:'변경 이력',security:'보안 관제'};
 const saved=()=>{try{return window.localStorage.getItem('jw206-theme')==='dark'?'dark':'light'}catch{return 'light'}};
 function setTheme(theme){
   const next=theme==='dark'?'dark':'light';
   document.documentElement.setAttribute('data-jw206-theme',next);
   document.querySelector('meta[name="color-scheme"]')?.setAttribute('content',next);
   document.querySelector('meta[name="theme-color"]')?.setAttribute('content',next==='dark'?'#16191b':'#eef0ed');
   document.querySelectorAll('[data-jw206-theme-choice]').forEach(b=>{
     const on=b.dataset.jw206ThemeChoice===next;
     b.setAttribute('aria-pressed',String(on));
   });
   try{window.localStorage.setItem('jw206-theme',next)}catch{}
 }
 const newEl=(tag,cls)=>{const x=document.createElement(tag);if(cls)x.className=cls;return x};
 const theme=newEl('div','jw206-theme-switch');
 theme.setAttribute('role','group');theme.setAttribute('aria-label','화면 테마');
 [['light','☼','화이트'],['dark','☾','다크']].forEach(([id,icon,label])=>{
   const b=newEl('button','jw206-theme-option');b.type='button';b.dataset.jw206ThemeChoice=id;
   b.setAttribute('aria-label',label+' 모드');b.innerHTML='<span aria-hidden="true">'+icon+'</span>'+label;
   b.addEventListener('click',()=>setTheme(id));theme.appendChild(b);
 });
 top.querySelector('.top-right')?.prepend(theme);
 setTheme(saved());
 // Keep all legacy navigation buttons in the DOM and preserve their data-page
 // handlers, permissions and upload-first order. Change only presentation.
 const head=newEl('div','jw206-right-head');
 const caption=newEl('div','jw206-right-caption');
 const title=newEl('strong');title.textContent='빠른 이동';
 const hint=newEl('small');hint.textContent='원하는 업무를 선택하세요';
 caption.append(title,hint);
 const collapse=newEl('button','jw206-rail-collapse');collapse.type='button';
 collapse.setAttribute('aria-label','우측 메뉴 접기');collapse.textContent='‹';
 head.append(caption,collapse);
 sidebar.insertBefore(head,sidebar.firstChild);
 nav.querySelectorAll('button[data-page]').forEach(b=>{
   const page=b.dataset.page;
   b.setAttribute('aria-label',(labels[page]||'업무')+' 화면 열기');
   if(!primary.includes(page))b.classList.add('jw206-secondary-item');
   const label=b.querySelector('.nav-ico');
   if(label)label.setAttribute('aria-hidden','true');
 });
 const more=newEl('button','jw206-more-toggle');more.type='button';
 more.setAttribute('aria-expanded','false');more.setAttribute('aria-label','추가 업무 메뉴 펼치기');
 more.innerHTML='<span aria-hidden="true">⌄</span> 다른 업무 보기';
 nav.appendChild(more);
 const toggleMore=force=>{
   const open=typeof force==='boolean'?force:!sidebar.classList.contains('jw206-more-open');
   sidebar.classList.toggle('jw206-more-open',open);
   more.setAttribute('aria-expanded',String(open));
   more.innerHTML='<span aria-hidden="true">'+(open?'⌃':'⌄')+'</span> '+(open?'간단히 보기':'다른 업무 보기');
 };
 more.addEventListener('click',()=>toggleMore());
 collapse.addEventListener('click',()=>{
   const minimized=sidebar.classList.toggle('jw206-compact');
   collapse.textContent=minimized?'›':'‹';
   collapse.setAttribute('aria-label',minimized?'우측 메뉴 펼치기':'우측 메뉴 접기');
   collapse.setAttribute('aria-expanded',String(!minimized));
   shell.classList.toggle('jw206-compact-rail',minimized);
 });
 // A concise right-side shortcut replaces full-width query/filter tools.
 const foot=newEl('div','jw206-right-footer');
 const quick=newEl('button','jw206-action');quick.type='button';
 quick.textContent='＋ 새 문서 등록';quick.addEventListener('click',()=>nav.querySelector('[data-page="imports"]')?.click());
 const footNote=newEl('small');footNote.textContent='실제 업무 데이터는 기존 권한을 따릅니다.';
 foot.append(quick,footNote);sidebar.appendChild(foot);
 const brand=document.querySelector('.v204-global-brand .v204-brand-copy');
 if(brand){brand.firstChild.textContent='JARVIS WORKS';brand.querySelector('small')?.replaceChildren(document.createTextNode('비즈니스 워크스페이스'))}
 const dock=document.getElementById('v204-floating-nav');
 if(dock){
   dock.querySelectorAll('[data-v204-nav]').forEach(btn=>{
     const p=btn.dataset.v204Nav;
     const label=btn.querySelector('span:last-child');
     if(label)label.textContent=({dashboard:'홈',imports:'문서',orders:'거래',invoices:'정산',messenger:'메신저'})[p]||p;
   });
 }
 function row(title,sub,action,flag){
   return '<button type="button" class="jw206-work-row" data-v204-nav="'+safe(action)+'">'
    +'<span class="jw206-row-sign" aria-hidden="true">↗</span>'
    +'<span class="jw206-row-content"><b>'+safe(title)+'</b><small>'+safe(sub)+'</small></span>'
    +(flag?'<span class="jw206-row-tag">'+safe(flag)+'</span>':'')
    +'<span class="jw206-row-arrow" aria-hidden="true">›</span></button>';
 }
 const fact=(name,value,desc,route,em=false)=>'<button type="button" class="jw206-metric'+(em?' jw206-metric-strong':'')+'" data-v204-nav="'+route+'"><span class="jw206-metric-label">'+safe(name)+'</span><strong>'+safe(value)+'</strong><small>'+safe(desc)+'</small><span class="jw206-metric-arrow" aria-hidden="true">↗</span></button>';
 function efficiency(s){
   const ready=s&&s.status==='COMPARISON_AVAILABLE'&&Number.isFinite(Number(s.observed_difference_ms))
     &&count(s.samples?.manual)>0&&count(s.samples?.automated)>0;
   if(!ready)return '<div class="jw206-eff-empty"><span class="jw206-eff-mark" aria-hidden="true">◷</span><div><strong>아직 비교할 실측 자료가 없습니다</strong><p>업무 자동화에서 수작업과 자동화 시간을 모두 측정하면 실제 비교 결과가 표시됩니다.</p></div></div>';
   const delta=Number(s.observed_difference_ms);
   const positive=delta>0;
   const sec=Math.round(Math.abs(delta)/1000);
   const msg=delta===0?'중위수 차이 없음':positive?'자동화 관측 시간 '+sec+'초 짧음':'자동화 관측 시간 '+sec+'초 김';
   // No invented percentage improvement. This comparison is observational.
   // A graph requires BOTH measured median durations. Never draw a full-width
   // progress bar when the API only exposes the observed time difference.
   const manual=Number(s.manual_median_ms),automatic=Number(s.automated_median_ms);
   const hasDurations=Number.isFinite(manual)&&Number.isFinite(automatic)&&manual>0&&automatic>0;
   const highest=hasDurations?Math.max(manual,automatic):1;
   const graph=hasDurations?'<div class="jw206-eff-comparison" aria-label="수작업과 자동화 실측 중위수">'
      +[['수작업',manual],['자동화',automatic]].map(([name,time])=>'<div class="jw206-eff-line"><span>'+name+'</span><div class="jw206-eff-meter"><i style="width:'+Math.round(time/highest*100)+'%"></i></div><b>'+Math.round(time/1000)+'초</b></div>').join('')
      +'</div>':'<p class="jw206-eff-note">관측 시간 차이는 확인됐지만 양쪽 중위수 원본값이 없어 그래프를 임의 구성하지 않았습니다.</p>';
   return '<div class="jw206-eff-measured"><div class="jw206-eff-number">'+safe(msg)+'</div>'+graph
    +'<small>수작업 '+count(s.samples.manual)+'건 · 자동화 '+count(s.samples.automated)+'건 · 관찰 비교(인과효과 아님)</small></div>';
 }
 dashboardPage=function premiumV206Dashboard(){
   const d=state.dashboard||{},issues=Array.isArray(d.issues)?d.issues:[],
   quotes=Array.isArray(d.recent_quotes)?d.recent_quotes:[],
   orders=Array.isArray(d.recent_orders)?d.recent_orders:[];
   const docs=count(d.quotes)+count(d.orders)+count(d.invoices);
   const work=issues.length?issues.slice(0,4).map(v=>row(v.title||'확인할 업무',v.doc_no||v.kind||'상세 확인','automation','확인')).join('')
      :'<div class="jw206-empty">확인이 필요한 업무가 없습니다.</div>';
   const recent=quotes.length?quotes.slice(0,4).map(v=>row(v.doc_no||'등록 견적',v.customer_name||'거래처 미기재','quotes',v.status==='draft'?'초안':'등록됨')).join('')
      :'<div class="jw206-empty">최근 견적 기록이 없습니다.</div>';
   return '<div class="jw206-dashboard" aria-label="JARVIS WORKS 업무 대시보드">'
    +'<div class="jw206-greeting"><div><span class="jw206-eyebrow">기업 업무 통합 관리</span><h1>업무 대시보드</h1><p>'+safe(state.user?.org_name||'기업')+'의 업무를 한눈에 확인하세요.</p></div>'
    +'<button type="button" data-v204-nav="imports" class="jw206-new-document">＋ 문서 업로드</button></div>'
    +'<div class="jw206-metrics">'
      +fact('등록 문서',docs+'건','견적 · 발주 · 청구','imports',true)
      +fact('검토할 업무',issues.length+'건','확인이 필요한 항목','automation')
      +fact('거래처',count(d.customers)+'곳','등록된 거래처','customers')
      +fact('미수금',money(d.outstanding),'기록된 청구·입금 기준','invoices')
    +'</div>'
    +'<div class="jw206-feature-grid">'
       +'<section class="jw206-pane jw206-pane-work"><div class="jw206-pane-head"><div><span class="jw206-eyebrow">우선 처리</span><h2>확인할 업무</h2></div><button type="button" data-v204-nav="automation">전체 보기 ↗</button></div><div class="jw206-work-list">'+work+'</div></section>'
       +'<section class="jw206-pane jw206-pane-recent"><div class="jw206-pane-head"><div><span class="jw206-eyebrow">업무 기록</span><h2>최근 문서</h2></div><button type="button" data-v204-nav="quotes">견적 관리 ↗</button></div><div class="jw206-work-list">'+recent+'</div></section>'
    +'</div>'
    +'<div class="jw206-feature-grid jw206-feature-secondary">'
       +'<section class="jw206-pane jw206-pane-eff"><div class="jw206-pane-head"><div><span class="jw206-eyebrow">실측 비교만 표시</span><h2>업무 효율</h2></div><button type="button" data-v204-nav="automation">측정 열기 ↗</button></div>'+efficiency(state.automationSavings)+'<p class="jw206-evidence">표본이 없는 경우 상승률·절감율 그래프를 임의 생성하지 않습니다.</p></section>'
       +'<section class="jw206-pane jw206-pane-shortcuts"><div class="jw206-pane-head"><div><span class="jw206-eyebrow">바로 실행</span><h2>자주 쓰는 업무</h2></div></div><div class="jw206-shortcuts">'
        +'<button type="button" data-v204-nav="imports">문서 자동 등록 <span>↗</span></button>'
        +'<button type="button" data-v204-nav="orders">거래 관리 <span>↗</span></button>'
        +'<button type="button" data-v204-nav="messenger">기업 메신저 <span>↗</span></button>'
       +'</div></section>'
    +'</div>'
    +'<p class="jw206-source-note">표시된 금액과 건수는 로그인한 기업의 조회 데이터입니다. 자동화 효율은 표본이 확보된 경우에만 관측 결과를 표시합니다.</p>'
   +'</div>';
 };
 // Optional measured result retrieval only when on dashboard. No writes, loading
 // spinner or navigation blocking; asynchronous result refresh is opt-in.
 const refreshLabel=document.createElement('span');refreshLabel.className='jw206-route-announcer';
 refreshLabel.setAttribute('aria-live','polite');refreshLabel.setAttribute('aria-atomic','true');
 document.body.appendChild(refreshLabel);
 let previous='';
 const watchNav=()=>{
   if(shell.classList.contains('hidden'))return;
   const current=state.page;
   if(current!==previous){
     previous=current;refreshLabel.textContent=(labels[current]||'업무')+' 화면';
     if(!primary.includes(current))toggleMore(true);
   }
 };
 const obs=new MutationObserver(watchNav);
 obs.observe(document.getElementById('main-content'),{childList:true});
 watchNav();
 window.JW_PREMIUM_V206={version:'20.6',setTheme,theme:()=>document.documentElement.getAttribute('data-jw206-theme')};
})();
