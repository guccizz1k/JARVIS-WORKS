/* JARVIS-WORKS V21.0: reference-composed, genuine business routes, measured facts only.
 * No API mutation or unsupported generative AI requests. This is a UI-only review patch.
 */
(function(){
 "use strict";
 const shell=document.getElementById("app-shell");
 const main=document.getElementById("main-content");
 const top=shell?.querySelector(".topbar");
 const nav=document.getElementById("nav");
 if(!shell||!main||!top||!nav||!window.JW_PREMIUM_V209)return;
 const pages=[
  ["imports","문서 자동등록","▤"],
  ["quotes","견적·수주","▱"],
  ["orders","발주·납품","⬡"],
  ["invoices","청구·입금","▣"],
  ["automation","업무 자동화","ϟ"],
  ["messenger","기업 메신저","▢"],
  ["dashboard","리포트","▥"]];
 const railPages=[["dashboard","홈","⌂"],["imports","문서","▤"],["quotes","견적","▱"],
   ["orders","수주·발주","⬡"],["invoices","청구·입금","▣"],
   ["automation","자동화","ϟ"],["messenger","메신저","▢"],["dashboard","리포트","▥"]];
 const iconShapes={
 "imports":'<path d="M8 3h7l4 4v14H6a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h2z"/><path d="M15 3v5h5M9 14h6M12 11v6"/>',
 "quotes":'<path d="m12 2 9 5-9 5-9-5 9-5zM3 12l9 5 9-5M3 17l9 5 9-5"/>',
 "orders":'<path d="m12 2 9 5v10l-9 5-9-5V7l9-5zM3 7l9 5 9-5M12 12v10"/>',
 "invoices":'<path d="M6 2h9l4 4v16H6a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zM15 2v5h5M8 12h8M8 16h5"/>',
 "automation":'<path d="m13 2-9 12h7l-1 8 10-13h-7z"/>',
 "messenger":'<path d="M20 4H4a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h4l4 3 4-3h4a2 2 0 0 0 2-2V6a2 2 0 0 0-2-2zM7 11h.01M12 11h.01M17 11h.01"/>',
 "dashboard":'<path d="M4 20V10M10 20V4M16 20v-7M22 20V8M2 21h22"/>',
 "home":'<path d="m3 10 9-7 9 7v11h-7v-7h-4v7H3z"/>',
 "company":'<rect x="4" y="8" width="16" height="13" rx="1"/><path d="M9 21V3h6v18M7 12h.01M7 16h.01M17 12h.01M17 16h.01"/>',
 "clock":'<circle cx="12" cy="12" r="9"/><path d="M12 7v6l4 2"/>'
 };
 function pictogram(key){
   const semantic=key==="▦"?"company":key==="▤"?"imports":key==="◷"?"clock":key==="▱"?"automation":key;
   const path=iconShapes[semantic]||iconShapes.dashboard;
   return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">'+path+'</svg>';
 }
 const escapeHtml=v=>String(v??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
 const num=v=>{let n=Number(v);return Number.isFinite(n)?Math.max(0,Math.trunc(n)):0};
 const canGo=id=>{const el=nav.querySelector('button[data-page="'+id+'"]');return !!el&&!el.hidden};
 const go=id=>{if(!canGo(id))return false;nav.querySelector('button[data-page="'+id+'"]').click();return true};
 const el=(tag,cls,txt)=>{let e=document.createElement(tag);if(cls)e.className=cls;if(txt!==undefined)e.textContent=txt;return e};
 const chrome=el("div","jw210-chrome"),row=el("div","jw210-top-row");
 const brand=el("button","jw210-brand");brand.type="button";
 brand.setAttribute("aria-label","JARVIS WORKS 홈 화면");
 brand.innerHTML='<span class="jw210-brand-mark" aria-hidden="true">∞</span><span><span class="jw210-brand-name">JARVIS-WORKS</span><span class="jw210-brand-sub">AI Business Automation Platform</span></span>';
 brand.addEventListener("click",()=>go("dashboard"));
 const ai=el("button","jw210-ai-launch");ai.type="button";
 ai.setAttribute("aria-haspopup","dialog");ai.setAttribute("aria-expanded","false");
 ai.innerHTML='<span class="jw210-ai-spark" aria-hidden="true">✦</span><span>JARVIS AI 업무 비서</span><span class="jw210-arrow" aria-hidden="true">→</span>';
 const utilities=el("div","jw210-utils");
 const searchBox=el("div","jw210-search-wrap");
 const searchIcon=el("span","jw210-search-ico","⌕");searchIcon.setAttribute("aria-hidden","true");
 const search=el("input","jw210-search");search.type="search";search.placeholder="업무 메뉴 검색";
 search.autocomplete="off";search.setAttribute("aria-label","업무 메뉴 검색");
 const results=el("div","jw210-search-results");results.hidden=true;results.setAttribute("role","group");results.setAttribute("aria-label","업무 메뉴 검색 결과");
 searchBox.append(searchIcon,search,results);
 const alert=el("button","jw210-icon-btn");alert.type="button";alert.setAttribute("aria-label","확인할 업무 열기");
 alert.innerHTML='<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/></svg>';
 alert.title="확인할 업무";alert.addEventListener("click",()=>go("automation"));
 const help=el("button","jw210-icon-btn","?");help.type="button";help.setAttribute("aria-expanded","false");help.setAttribute("aria-label","도움말 열기");
 const theme=top.querySelector(".jw206-theme-switch");
 utilities.append(searchBox,alert,help);
 if(theme)utilities.append(theme);
 row.append(brand,ai,utilities);
 const bar=el("nav","jw210-business-nav");bar.setAttribute("aria-label","주요 업무 메뉴");
 pages.forEach(([id,label,icon])=>{
   const b=el("button","jw210-nav-btn");b.type="button";b.dataset.jw210Page=id;
   b.setAttribute("aria-label",label+" 열기");
   b.innerHTML='<span class="jw210-nav-ico" aria-hidden="true">'+pictogram(id)+'</span><span>'+escapeHtml(label)+'</span>';
   b.addEventListener("click",()=>go(id));bar.appendChild(b);
 });
 chrome.append(row,bar);top.append(chrome);
 // Original v20.9 navigation buttons and their business handlers remain in DOM.
 const rail=el("aside","jw210-rail");rail.dataset.open="false";rail.setAttribute("aria-label","좌측 빠른 메뉴");
 const railPanel=el("div","jw210-rail-panel");
 const railToggle=el("button","jw210-rail-toggle","›");railToggle.type="button";
 railToggle.setAttribute("aria-controls","jw210-rail-menu");railToggle.setAttribute("aria-expanded","false");
 railToggle.setAttribute("aria-label","빠른 메뉴 펼치기");
 railPanel.id="jw210-rail-menu";
 railPages.forEach(([id,label,icon])=>{
   const b=el("button","jw210-rail-item");b.dataset.jw210Page=id;b.type="button";
   b.innerHTML='<span aria-hidden="true">'+pictogram(label==="홈"?"home":id)+'</span><span>'+escapeHtml(label)+'</span>';
   b.addEventListener("click",()=>{if(go(id))setRailOpen(false)});
   railPanel.append(b);
 });
 railPanel.append(railToggle);rail.append(railPanel);shell.append(rail);
 let pinned=false;
 function setRailOpen(on){rail.dataset.open=String(on);railToggle.setAttribute("aria-expanded",String(on));
  railToggle.textContent=on?"‹":"›";pinned=on;
  railToggle.setAttribute("aria-label",on?"빠른 메뉴 접기":"빠른 메뉴 펼치기");
 }
 railToggle.addEventListener("click",()=>setRailOpen(rail.dataset.open!=="true"));
 rail.addEventListener("pointerenter",e=>{if(e.pointerType==="mouse"){rail.dataset.open="true";railToggle.setAttribute("aria-expanded","true")}});
 rail.addEventListener("pointerleave",e=>{if(e.pointerType==="mouse"&&!pinned){rail.dataset.open="false";railToggle.setAttribute("aria-expanded","false")}});
 rail.addEventListener("keydown",e=>{if(e.key==="Escape"){setRailOpen(false);railToggle.focus()}});
 rail.addEventListener("focusout",e=>{if(!rail.contains(e.relatedTarget)&&!pinned)rail.dataset.open="false"});
 // The AI button is an accessible launcher to approved existing workflows; no claim
 // that an LLM is connected, no unreviewed freeform code execution.
 const aiPanel=el("section","jw210-ai-menu");aiPanel.hidden=true;aiPanel.id="jw210-ai-menu";
 aiPanel.setAttribute("role","dialog");aiPanel.setAttribute("aria-modal","false");
 aiPanel.setAttribute("aria-label","JARVIS AI 업무 비서 바로가기");
 const aiTitle=el("h2","","JARVIS AI 업무 비서");
 const aiText=el("p","","업무를 선택하면 현재 승인된 JARVIS-WORKS 기능으로 이동합니다. AI 자연어 자동실행은 별도 검증이 필요합니다.");
 const aiClose=el("button","jw210-close","닫기 ×");aiClose.type="button";
 aiClose.addEventListener("click",()=>setAi(false));
 aiPanel.append(aiTitle,aiClose,aiText);
 [["imports","문서 자동등록"],["quotes","견적 관리"],["orders","수주·발주"],["automation","업무 자동화"]].forEach(([id,label])=>{
   const b=el("button","",label+" 열기 →");b.type="button";b.addEventListener("click",()=>{setAi(false);go(id)});
   aiPanel.append(b);
 });
 document.body.append(aiPanel);
 function setAi(open){aiPanel.hidden=!open;ai.setAttribute("aria-expanded",String(open));if(open)aiClose.focus();else ai.focus()}
 ai.addEventListener("click",()=>setAi(aiPanel.hidden));
 const helpPanel=el("section","jw210-help");helpPanel.hidden=true;helpPanel.id="jw210-help";
 helpPanel.setAttribute("role","dialog");helpPanel.setAttribute("aria-label","사용 도움말");
 helpPanel.innerHTML='<strong>JARVIS-WORKS 사용 안내</strong><p>상단 업무 메뉴를 선택하거나 좌측 가장자리에 마우스를 대면 빠른 이동 메뉴가 나타납니다. 화이트·다크 모드는 오른쪽에서 전환할 수 있습니다.</p>';
 const helpClose=el("button","","닫기");helpClose.type="button";helpClose.addEventListener("click",()=>{helpPanel.hidden=true;help.setAttribute("aria-expanded","false");help.focus()});
 helpPanel.append(helpClose);document.body.append(helpPanel);
 help.addEventListener("click",()=>{helpPanel.hidden=!helpPanel.hidden;help.setAttribute("aria-expanded",String(!helpPanel.hidden));if(!helpPanel.hidden)helpClose.focus()});
 function updateSearch(){
   const q=search.value.trim().toLocaleLowerCase("ko");
   results.replaceChildren();
   if(!q){results.hidden=true;return}
   let matches=pages.filter(([id,name])=>canGo(id)&&name.toLocaleLowerCase("ko").includes(q));
   if(q.includes("문서"))matches=[...new Map([...matches,["imports","문서 자동등록","▤"]].map(x=>[x[0],x])).values()];
   for(const [id,name] of matches.slice(0,8)){
     const b=el("button","",name);b.type="button";b.addEventListener("click",()=>{results.hidden=true;search.value="";go(id)});
     results.append(b);
   }
   if(!results.childElementCount){const label=el("span","", "일치하는 업무 메뉴가 없습니다");label.style.padding="10px";label.style.fontSize="13px";results.append(label)}
   results.hidden=false;
 }
 search.addEventListener("input",updateSearch);
 search.addEventListener("keydown",e=>{if(e.key==="Escape"){results.hidden=true;search.blur()}if(e.key==="Enter"){const b=results.querySelector("button");if(b){b.click();e.preventDefault()}}});
 document.addEventListener("pointerdown",e=>{if(!searchBox.contains(e.target))results.hidden=true;
   if(!aiPanel.hidden&&!aiPanel.contains(e.target)&&!ai.contains(e.target)){aiPanel.hidden=true;ai.setAttribute("aria-expanded","false")}
   if(!helpPanel.hidden&&!helpPanel.contains(e.target)&&!help.contains(e.target)){helpPanel.hidden=true;help.setAttribute("aria-expanded","false")}
 },{passive:true});
 document.addEventListener("keydown",e=>{
  if(e.key!=="Escape")return;
  if(!aiPanel.hidden)setAi(false);
  if(!helpPanel.hidden){helpPanel.hidden=true;help.setAttribute("aria-expanded","false");help.focus()}
  results.hidden=true;
 });
 const originalDashboard=dashboardPage;
 function metric(icon,label,value,small,company=false){
  return '<div class="jw210-metric"><span class="jw210-metric-icon" aria-hidden="true">'+pictogram(icon)+'</span>'
   +'<span class="jw210-metric-copy"><span class="jw210-metric-label">'+escapeHtml(label)+'</span>'
   +'<strong class="jw210-metric-val'+(company?' company':'')+'">'+escapeHtml(value)+'</strong>'
   +(small?'<span class="jw210-metric-help">'+escapeHtml(small)+'</span>':'')+'</span></div>';
 }
 // Counts are read exclusively from the existing authenticated tenant summary.
 // Time saved requires verified paired samples; never show illustration-derived
 // "5821 / 182 / 23" or fictitious improvement percentages.
 dashboardPage=function jw210Dashboard(){
  try {
   const d=state.dashboard||{};
   const docs=num(d.quotes)+num(d.orders)+num(d.invoices);
   const savings=state.automationSavings||{};
   const manual=num(savings.samples?.manual),automated=num(savings.samples?.automated);
   const observed=Number(savings.observed_difference_ms);
   const measured=savings.status==="COMPARISON_AVAILABLE"&&manual>=20&&automated>=20&&Number.isFinite(observed);
   const saved=measured&&observed>0?Math.round(observed/1000)+"초/건":measured?"절감 미확인":"측정 중";
   const automationCount=automated>0?automated.toLocaleString("ko-KR")+"건":"자료 없음";
   const company=state.user?.org_name||"기업";
   return '<section class="jw210-home" aria-label="JARVIS WORKS 홈 화면">'
    +'<div class="jw210-hero-title"><span class="jw210-kicker">기업 업무의 모든 흐름을 하나로</span>'
    +'<h1>JARVIS-WORKS</h1><p>문서부터 거래·정산까지,<br>반복 업무는 AI가 더 빠르고 정확하게.</p></div>'
    +'<div class="jw210-infinity-stage">'
    +'<img class="jw210-infinity-photo" src="/static/jw210_orbit_dark.webp" alt="중앙 유리 무한대 조형물" loading="eager" decoding="async">'
    +'<svg class="jw210-orbit-overlay" viewBox="0 0 1100 570" role="img" aria-label="조형물 주변을 양방향으로 왕복하는 빛">'
    +'<defs><path id="jw210-light-track" d="M115 316 C183 172 435 104 688 147 S971 252 976 314 S785 425 554 406 S147 403 115 316Z"/>'
    +'<path id="jw210-light-back" d="M210 236 C280 121 514 74 758 149 S979 301 864 357 S390 409 210 236Z"/>'
    +'<radialGradient id="jw210-luminance"><stop stop-color="#fff" offset="0"/><stop stop-color="#eaf3ff" stop-opacity=".8" offset=".3"/><stop stop-color="#fff" stop-opacity="0" offset="1"/></radialGradient></defs>'
    +'<circle r="31" fill="url(#jw210-luminance)"><animateMotion dur="7s" repeatCount="indefinite" calcMode="linear" keyPoints="0;1;0" keyTimes="0;.5;1"><mpath href="#jw210-light-track"/></animateMotion></circle>'
    +'<circle r="6" fill="#fff"><animateMotion dur="7s" repeatCount="indefinite" calcMode="linear" keyPoints="0;1;0" keyTimes="0;.5;1"><mpath href="#jw210-light-track"/></animateMotion></circle>'
    +'<circle r="14" fill="url(#jw210-luminance)"><animateMotion dur="10s" repeatCount="indefinite" calcMode="linear" keyPoints="1;0;1" keyTimes="0;.5;1"><mpath href="#jw210-light-back"/></animateMotion></circle></svg>'
    +'</div><div class="jw210-metrics" aria-label="기업별 실제 업무 지표">'
    +metric("▦",company,"기업 운영 워크스페이스","",true)
    +metric("▤","등록된 문서",docs.toLocaleString("ko-KR")+"건","견적·발주·청구")
    +metric("◷","절감한 업무 시간",saved,measured?"비교표본 수작업 "+manual+" · 자동화 "+automated:"실측 비교가 확보되면 표시")
    +metric("▱","자동화 측정 표본",automationCount,"관측된 자동화 업무")
    +'</div></section>';
  } catch(error){
   // On unexpected changes to the original dashboard shape, retain its view.
   return originalDashboard();
  }
 };
 function pauseOrbit(){
   const svg=main.querySelector(".jw210-orbit-overlay");
   if(!svg||typeof svg.pauseAnimations!=="function")return;
   const reduce=window.matchMedia("(prefers-reduced-motion: reduce)").matches;
   if(reduce||document.hidden)svg.pauseAnimations();
   else svg.unpauseAnimations();
 }
 document.addEventListener("visibilitychange",pauseOrbit);
 window.matchMedia("(prefers-reduced-motion: reduce)").addEventListener?.("change",pauseOrbit);
 function syncRoute(){
   if(shell.classList.contains("hidden"))return;
   const current=typeof state==="undefined"?"":state.page;
   const nodes=[...bar.querySelectorAll(".jw210-nav-btn"),...railPanel.querySelectorAll(".jw210-rail-item")];
   for(const b of nodes){
     let chosen=b.dataset.jw210Page===current;
     b.setAttribute("aria-current",chosen?"page":"false");
     if(b.dataset.jw210Page==="dashboard"&&current==="dashboard")chosen=true;
     b.disabled=!canGo(b.dataset.jw210Page);
     if(b.classList.contains("jw210-nav-btn"))b.dataset.jw210HomePrimary=String(current==="dashboard"&&b.dataset.jw210Page==="imports");
   }
   for(const b of railPanel.querySelectorAll("[data-jw210-page]")){
     b.hidden=!canGo(b.dataset.jw210Page);
   }
   pauseOrbit();
 }
 const obs=new MutationObserver(syncRoute);obs.observe(main,{childList:true});
 obs.observe(nav,{subtree:true,attributes:true,attributeFilter:["class","hidden"]});
 syncRoute();
 window.JW_PREMIUM_V210=Object.freeze({version:"21.0",openRail:()=>setRailOpen(true),closeRail:()=>setRailOpen(false),goto:go});
})();
