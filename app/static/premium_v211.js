/* V21.1: One photon inside the actual infinity glass contour; unified sign-in;
   spatial work-screen reveal. Additive to V21.0: original auth and API untouched. */
(() => {
  "use strict";
  const login=document.getElementById("login-view");
  const shell=document.getElementById("app-shell");
  const main=document.getElementById("main-content");
  if(!login||!shell||!main||!window.JW_PREMIUM_V210)return;
  const reduce=matchMedia("(prefers-reduced-motion: reduce)");
  const SVG_NS="http://www.w3.org/2000/svg";
  // Bezier approximately traces the transparent ribbon visible in the approved
  // crop. Unlike the V21.0 orbit tracks, this path stays on the infinity's glass.
  // One shared animateMotion drives the core, halo and reflected glow together.
  const glassTrack="M 352 190 C 298 132 246 84 191 114 C 130 148 121 248 181 254 C 252 271 296 200 350 174 C 416 134 471 96 526 127 C 575 159 580 238 521 261 C 453 288 400 231 352 190 Z";
  const make=(t,cls)=>{const x=document.createElement(t);if(cls)x.className=cls;return x};
  function photonSvg(prefix){
    const id=prefix+"-glass-track",m=prefix+"-light-mask",g=prefix+"-light-gradient";
    const root=document.createElementNS(SVG_NS,"svg");
    root.classList.add("jw211-glass-photon");
    root.setAttribute("viewBox","0 0 800 460");
    root.setAttribute("preserveAspectRatio","xMidYMid meet");
    root.setAttribute("aria-label","무한대 유리 조형물 내부를 순환하는 단일 빛");
    root.setAttribute("role","img");
    // The mask limits photon light to the ribbon, not the surrounding orbit.
    root.innerHTML='<defs><path id="'+id+'" d="'+glassTrack+'"/>'
       +'<mask id="'+m+'" maskUnits="userSpaceOnUse" x="70" y="45" width="580" height="300">'
       +'<use href="#'+id+'" fill="none" stroke="#fff" stroke-width="55"/>'
       +'</mask><radialGradient id="'+g+'"><stop stop-color="#fff" offset="0"/>'
       +'<stop stop-color="#fff" stop-opacity=".98" offset=".13"/>'
       +'<stop stop-color="#dceaff" stop-opacity=".8" offset=".36"/>'
       +'<stop stop-color="#bdcffa" stop-opacity="0" offset="1"/></radialGradient></defs>'
       +'<g mask="url(#'+m+')"><g class="jw211-photon-core">'
       +'<circle r="45" fill="url(#'+g+')" opacity=".94"/>'
       +'<circle r="15" fill="#f9fdff" opacity=".8"/>'
       +'<circle r="5" fill="#fff"/>'
       +'<animateMotion dur="8s" repeatCount="indefinite" rotate="auto" calcMode="linear">'
       +'<mpath href="#'+id+'"/></animateMotion></g></g>';
    return root;
  }
  // Convert the approved image into a transparently composited glass element:
  // brightness controls alpha, rather than showing the screenshot's dark box.
  function glassImage(prefix){
    const svg=document.createElementNS(SVG_NS,"svg");
    const id=prefix+"-isolate",fade=prefix+"-edge";
    svg.classList.add("jw211-transparent-crystal");
    svg.setAttribute("viewBox","0 0 800 460");
    svg.setAttribute("role","img");
    svg.setAttribute("aria-label","투명 유리 무한대 조형물");
    svg.innerHTML='<defs><filter id="'+id+'" color-interpolation-filters="sRGB" x="0" y="0" width="100%" height="100%">'
      +'<feColorMatrix in="SourceGraphic" type="luminanceToAlpha" result="lum"/>'
      +'<feComponentTransfer in="lum" result="opacity">'
      +'<feFuncA type="table" tableValues="0 0 0 .06 .25 .65 1 1"/></feComponentTransfer>'
      +'<feComposite in="SourceGraphic" in2="opacity" operator="in"/>'
      +'</filter><radialGradient id="'+fade+'" cx=".5" cy=".5" r=".72">'
      +'<stop offset=".49" stop-color="#fff"/><stop offset=".78" stop-color="#fff" stop-opacity=".85"/>'
      +'<stop offset="1" stop-color="#fff" stop-opacity="0"/></radialGradient>'
      +'<mask id="'+fade+'-mask"><rect width="800" height="460" fill="url(#'+fade+')"/></mask></defs>'
      +'<image href="/static/jw210_orbit_dark.webp" width="800" height="460"'
      +' preserveAspectRatio="xMidYMid meet" filter="url(#'+id+')" mask="url(#'+fade+'-mask)"/>';
    return svg;
  }
  const oldLoginCard=login.querySelector(".login-card");
  if(!oldLoginCard)return;
  const header=make("header","jw211-login-header");
  const brand=make("div","jw211-login-brand");
  brand.innerHTML='<span aria-hidden="true" class="jw211-login-brand-symbol">∞</span>'
    +'<span><strong>JARVIS-WORKS</strong><small>AI Business Automation Platform</small></span>';
  const mode=make("div","jw211-login-modes");
  mode.setAttribute("role","group");mode.setAttribute("aria-label","로그인 화면 테마");
  [["light","화이트"],["dark","블랙"]].forEach(([v,label])=>{
    const btn=make("button","jw211-login-mode");btn.type="button";
    btn.dataset.jw211Theme=v;btn.textContent=label;
    btn.addEventListener("click",()=>window.JW_PREMIUM_V206?.setTheme(v));
    mode.append(btn);
  });
  header.append(brand,mode);
  const hero=make("div","jw211-login-hero");
  hero.setAttribute("aria-label","JARVIS WORKS 무한대 크리스털");
  const art=make("div","jw211-login-infinity");
  art.append(glassImage("jw211-login"),photonSvg("jw211-login"));
  hero.append(art);
  const headline=make("div","jw211-login-headline");
  headline.innerHTML='<span>하나의 업무 공간, 무한한 가능성</span>'
    +'<h2>기업 업무의 모든 흐름을 하나로.</h2>';
  hero.append(headline);
  login.prepend(header,hero);
  login.classList.add("jw211-login");
  // Compact sign-in without weakening MFA: optional fields remain editable
  // and keep the original input names required by the authentication handler.
  const heading=oldLoginCard.querySelector("h1");
  if(heading)heading.textContent="워크스페이스 로그인";
  const intro=oldLoginCard.querySelector(":scope > p");
  if(intro)intro.textContent="승인된 기업 계정으로 안전하게 로그인하세요.";
  const form=oldLoginCard.querySelector("form");
  if(form && !form.querySelector(".jw211-extra-auth")){
    const authLabels=[...form.querySelectorAll("label")].filter(label=>
      label.querySelector('input[name="otp"],input[name="recovery_code"]'));
    const submit=form.querySelector('button[type="submit"]');
    if(authLabels.length===2 && submit){
      const details=make("details","jw211-extra-auth");
      const summary=make("summary","","추가 인증 · MFA / 복구코드");
      details.append(summary,...authLabels);
      form.insertBefore(details,submit);
    }
  }
  const loginWatch=new MutationObserver(()=>{
    const theme=document.documentElement.getAttribute("data-jw206-theme");
    for(const b of mode.querySelectorAll("button"))b.setAttribute("aria-pressed",String(b.dataset.jw211Theme===theme));
    syncPhoton();
  });
  loginWatch.observe(document.documentElement,{attributes:true,attributeFilter:["data-jw206-theme"]});
  loginWatch.observe(login,{attributes:true,attributeFilter:["class"]});
  // Remove the old surrounding-orbit animation and replace it once per freshly
  // rendered dashboard, with one animated source inside the actual glass ring.
  function mountWorkspacePhoton(){
    const stage=main.querySelector(".jw210-infinity-stage");
    if(!stage || stage.querySelector(".jw211-glass-photon"))return;
    stage.querySelector(".jw210-orbit-overlay")?.remove();
    stage.querySelector(".jw210-infinity-photo")?.replaceWith(glassImage("jw211-workspace"));
    stage.append(photonSvg("jw211-workspace"));
    syncPhoton();
  }
  function syncPhoton(){
    const shouldPause=reduce.matches||document.hidden;
    for(const root of document.querySelectorAll(".jw211-glass-photon")){
      if(typeof root.pauseAnimations!=="function")continue;
      if(shouldPause||root.closest(".jw211-login")?.classList.contains("hidden")
        ||root.closest("#app-shell")?.classList.contains("hidden")){
        root.pauseAnimations();
      }else root.unpauseAnimations();
    }
  }
  let scheduled=false;
  new MutationObserver(()=>{
    if(scheduled)return;
    scheduled=true;
    requestAnimationFrame(()=>{scheduled=false;mountWorkspacePhoton();syncPhoton()});
  }).observe(main,{childList:true});
  document.addEventListener("visibilitychange",syncPhoton);
  reduce.addEventListener?.("change",syncPhoton);
  mountWorkspacePhoton();syncPhoton();
  // Clicking a work tool opens the NEXT screen as a glass aperture growing
  // from that tool, instead of an unrelated card drop-down animation.
  let origin={x:50,y:0},cycle=0;
  document.addEventListener("pointerdown",ev=>{
    const trigger=ev.target.closest(".jw210-nav-btn,.jw210-rail-item,.jw210-brand,.jw211-ai-work");
    if(!trigger)return;
    const b=trigger.getBoundingClientRect();
    const target=main.getBoundingClientRect();
    origin.x=Math.max(4,Math.min(96,((b.left+b.width/2-target.left)/Math.max(target.width,1))*100));
    origin.y=Math.max(0,Math.min(95,((b.top+b.height/2-target.top)/Math.max(target.height,1))*100));
  },{passive:true,capture:true});
  const motion=window.JW_UI_MOTION;
  if(motion && !motion.jw211Wrapped){
    const before=motion.beforeNavigate?.bind(motion);
    const after=motion.afterNavigate?.bind(motion);
    const failed=motion.navigationFailed?.bind(motion);
    motion.beforeNavigate=async function(page){
      main.classList.remove("jw211-portal-reveal");
      const ticket=++cycle;
      main.dataset.jw211RouteTicket=String(ticket);
      if(before)await before(page);
    };
    motion.afterNavigate=function(page,root){
      if(after)after(page,root);
      if(!root)return;
      main.style.setProperty("--jw211-origin-x",origin.x.toFixed(2)+"%");
      main.style.setProperty("--jw211-origin-y",origin.y.toFixed(2)+"%");
      if(!reduce.matches){
        main.classList.remove("jw211-portal-reveal");
        void main.offsetWidth;
        main.classList.add("jw211-portal-reveal");
      }
      mountWorkspacePhoton();
    };
    motion.navigationFailed=function(){main.classList.remove("jw211-portal-reveal");if(failed)failed()};
    motion.jw211Wrapped=true;
  }
  window.JW_PREMIUM_V211=Object.freeze({version:"21.1",glassTrack,orbitCount:1});
})();
