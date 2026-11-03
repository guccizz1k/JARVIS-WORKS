/* V20.9: top navigation adapter; leave all WORKS authenticated routes, APIs and DB untouched. */
(function(){
 'use strict';
 const shell=document.getElementById('app-shell'),top=shell?.querySelector('.topbar');
 const original=document.getElementById('nav'),main=document.getElementById('main-content');
 if(!shell||!top||!original||!main||!window.JW_PREMIUM_V206)return;
 const targets=[['dashboard','대시보드'],['imports','문서 자동등록'],
   ['quotes','견적 관리'],['orders','수주·발주'],['invoices','청구·입금'],
   ['automation','업무 자동화'],['messenger','기업 메신저']];
 const extras=[['customers','거래처 관리'],['audit','변경 이력'],['security','보안 관제']];
 const sourceButton=id=>original.querySelector('button[data-page="'+id+'"]');
 const allowed=id=>!!sourceButton(id)&&!sourceButton(id).hidden;
 const go=id=>{if(!allowed(id))return false;sourceButton(id).click();return true;};
 const make=(tag,cls)=>{let x=document.createElement(tag);x.className=cls;return x};
 const bar=make('nav','jw209-top-nav');bar.setAttribute('aria-label','JARVIS WORKS 주요 업무');
 const tab=(id,label)=>{
   let b=make('button','jw209-tab');b.type='button';b.textContent=label;
   b.dataset.jw209Page=id;b.setAttribute('aria-label',label+' 화면 열기');
   b.addEventListener('click',()=>{if(id==='efficiency'){
     if(typeof state==='undefined')return;
     if(state.page!=='dashboard'){efficiencyPending=true;go('dashboard')}
     else scrollEfficiency();
   }else{go(id)}});
   return b;
 };
 targets.forEach(([id,label])=>bar.appendChild(tab(id,label)));
 bar.appendChild(tab('efficiency','업무 효율'));
 const more=make('button','jw209-more-trigger');
 more.type='button';more.textContent='더보기';more.setAttribute('aria-expanded','false');
 more.setAttribute('aria-haspopup','true');more.setAttribute('aria-controls','jw209-more-menu');
 bar.appendChild(more);
 const menu=make('div','jw209-more-menu');menu.id='jw209-more-menu';menu.hidden=true;
 extras.forEach(([id,label])=>{let b=make('button','');b.type='button';
   b.textContent=label;b.dataset.jw209Extra=id;
   b.addEventListener('click',()=>{if(go(id))close()});menu.appendChild(b)});
 document.body.appendChild(menu);
 function close(){menu.hidden=true;more.setAttribute('aria-expanded','false')}
 function open(){for(const b of menu.querySelectorAll('button')){
   b.hidden=!allowed(b.dataset.jw209Extra);
 }
 const r=more.getBoundingClientRect();
 menu.style.left=Math.max(8,Math.min(r.left,innerWidth-194))+'px';
 menu.style.top=Math.min(r.bottom+8,innerHeight-150)+'px';
 menu.hidden=false;more.setAttribute('aria-expanded','true');
 }
 more.addEventListener('click',()=>{menu.hidden?open():close()});
 document.addEventListener('pointerdown',ev=>{
   if(!menu.hidden&&!more.contains(ev.target)&&!menu.contains(ev.target))close();
 },{passive:true});
 document.addEventListener('keydown',ev=>{
   if(ev.key==='Escape'&&!menu.hidden){close();more.focus()}
 });
 window.addEventListener('resize',close,{passive:true});
 top.appendChild(bar);
 const reduced=()=>matchMedia('(prefers-reduced-motion: reduce)').matches;
 function scrollEfficiency(){
   const t=main.querySelector('.jw206-pane-eff');
   if(t)t.scrollIntoView({block:'center',behavior:reduced()?'instant':'smooth'});
 }
 let efficiencyPending=false;
 function sync(){
   const page=typeof state==='undefined'?'':state.page;
   for(const b of bar.querySelectorAll('[data-jw209-page]')){
     let active=b.dataset.jw209Page===page;
     b.setAttribute('aria-current',active?'page':'false');
     if(active && b.dataset.jw209Page!== 'efficiency'){
       b.scrollIntoView?.({block:'nearest',inline:'nearest',behavior:'instant'});
     }
   }
   if(efficiencyPending&&page==='dashboard'&&main.querySelector('.jw206-pane-eff')){
     efficiencyPending=false;requestAnimationFrame(scrollEfficiency);
   }
 }
 new MutationObserver(sync).observe(original,{subtree:true,attributes:true,attributeFilter:['class','hidden']});
 new MutationObserver(sync).observe(main,{childList:true});
 sync();
 // V20.6 already owns white/dark persistence; alter text only, not stored state.
 top.querySelectorAll('[data-jw206-theme-choice]').forEach(b=>{
   const mode=b.dataset.jw206ThemeChoice;
   const t=b.lastChild;
   if(t?.nodeType===3)t.textContent=mode==='dark'?'블랙':'화이트';
   b.setAttribute('aria-label',(mode==='dark'?'블랙':'화이트')+' 모드 전환');
 });
 // No network request, no business data fabrication, and no new database writes.
 window.JW_PREMIUM_V209=Object.freeze({version:'20.9',go,updateNavigation:sync});
})();
