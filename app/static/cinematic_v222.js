/* JARVIS-WORKS V22.2 — reference-led cinematic scroll story.
 * Presentation only: retain original dashboard facts, session, API, business
 * navigation, the existing single-photon infinity renderer and manual approvals.
 * No copied reference imagery or third-party network requests.
 */
(() => {
 'use strict';
 const main=document.getElementById('main-content');
 const shell=document.getElementById('app-shell');
 if(!main||!shell||typeof dashboardPage!=='function'||!window.JW_PREMIUM_V212)return;
 const reduced=matchMedia('(prefers-reduced-motion: reduce)');
 const fine=matchMedia('(hover:hover) and (pointer:fine)');
 const art=(kind,label)=>'<span class="jw222-art-mark jw222-art-mark--'+kind+'" aria-hidden="true">'+label+'</span>';
 const cards=[
  '<div class="jw222-imagecard jw222-imagecard--paper" aria-hidden="true"><div class="jw222-imagecard-texture">'+
  '<span class="jw222-imagecard-circle"></span><span class="jw222-imagecard-arc"></span><span class="jw222-imagecard-shimmer"></span></div></div>',
  '<div class="jw222-imagecard jw222-imagecard--silver" aria-hidden="true"><div class="jw222-imagecard-texture">'+
  '<span class="jw222-imagecard-circle"></span><span class="jw222-imagecard-arc"></span><span class="jw222-imagecard-shimmer"></span></div></div>',
  '<div class="jw222-imagecard jw222-imagecard--ink" aria-hidden="true"><div class="jw222-imagecard-texture">'+
  '<span class="jw222-imagecard-circle"></span><span class="jw222-imagecard-arc"></span><span class="jw222-imagecard-shimmer"></span></div></div>'
 ];
 const story=()=>{
  return '<div class="jw222-scroll-story" aria-label="업무 플랫폼 소개 — 스크롤 체험">'+
  '<div class="jw222-ambient-line" aria-hidden="true"></div>'+
  '<section class="jw222-scene jw222-scene--source" id="jw222-story-source" aria-labelledby="jw222-source-title">'+
   '<div class="jw222-chapter"><span>01 / 03</span><span>문서에서 시작되는 흐름</span></div>'+
   '<div class="jw222-stage"><div class="jw222-stage-copy">'+
    '<span class="jw222-eyebrow">문서 자동화</span>'+
    '<h2 id="jw222-source-title">문서 한 장이<br><em>업무의 흐름</em>이 되다.</h2>'+
    '<p>다양한 자료를 한곳에서 검토하고, 원본을 확인한 뒤 거래 기록으로 연결합니다. 결정적인 단계는 사람이 승인합니다.</p>'+
    '<button class="jw222-cta" type="button" data-jw222-go="imports"><span>문서 작업 열기</span><span aria-hidden="true">↗</span></button>'+
   '</div><div class="jw222-stage-art jw222-stage-art--source" aria-hidden="true">'+
    '<div class="jw222-stage-halo"></div><div class="jw222-object jw222-object--one">'+cards[0]+'</div>'+
    '<div class="jw222-object jw222-object--two">'+cards[1]+'</div>'+
    '<div class="jw222-object jw222-object--three">'+cards[2]+'</div>'+
    '<div class="jw222-lightthread"></div>'+
   '</div></div>'+
   '<span class="jw222-side-note" aria-hidden="true">신뢰할 수 있는 자동화의 시작</span>'+
  '</section>'+
  '<section class="jw222-scene jw222-scene--continuity" id="jw222-story-continuity" aria-labelledby="jw222-continuity-title">'+
   '<div class="jw222-chapter"><span>02 / 03</span><span>하나로 이어지는 거래</span></div>'+
   '<div class="jw222-stage jw222-stage--reversed"><div class="jw222-stage-copy">'+
    '<span class="jw222-eyebrow">거래 흐름</span>'+
    '<h2 id="jw222-continuity-title">연결의 깊이까지<br><em>선명하게.</em></h2>'+
    '<p>견적부터 수주·발주·납품·청구까지. 각 단계에서 누가 무엇을 확인했는지, 필요한 연결을 같은 흐름 안에서 추적합니다.</p>'+
    '<button class="jw222-cta" type="button" data-jw222-go="automation"><span>자동화 작업 열기</span><span aria-hidden="true">↗</span></button>'+
   '</div><div class="jw222-stage-art jw222-stage-art--continuity" aria-hidden="true">'+
    '<div class="jw222-orbit jw222-orbit--outer"></div><div class="jw222-orbit jw222-orbit--inner"></div>'+
    '<div class="jw222-prism jw222-prism--one"></div><div class="jw222-prism jw222-prism--two"></div>'+
    '<div class="jw222-prism jw222-prism--three"></div><span class="jw222-prism-glint"></span>'+
   '</div></div>'+
   '<span class="jw222-side-note" aria-hidden="true">검증과 기록이 연결되는 공간</span>'+
  '</section>'+
  '<section class="jw222-scene jw222-scene--assurance" id="jw222-story-assurance" aria-labelledby="jw222-assurance-title">'+
   '<div class="jw222-chapter"><span>03 / 03</span><span>일을 더 명확하게</span></div>'+
   '<div class="jw222-final-halo" aria-hidden="true"><span></span><span></span><span></span></div>'+
   '<div class="jw222-final-content"><span class="jw222-eyebrow">JARVIS-WORKS</span>'+
   '<h2 id="jw222-assurance-title">복잡한 일은 단순하게.<br><em>중요한 검증은 정확하게.</em></h2>'+
   '<p>화면의 아름다움보다 중요한 것은 실제 업무의 정확성입니다. 모든 시각 효과 뒤에는 기존 데이터·승인·권한 규칙이 그대로 작동합니다.</p>'+
   '<div class="jw222-final-actions"><button type="button" class="jw222-cta" data-jw222-go="dashboard"><span>업무 현황 보기</span><span aria-hidden="true">↗</span></button>'+
   '<button type="button" class="jw222-cta jw222-cta--quiet" data-jw222-go="messenger"><span>기업 메신저 열기</span><span aria-hidden="true">↗</span></button></div>'+
   '</div>'+
  '</section></div>';
 };
 const originalDashboard=dashboardPage;
 dashboardPage=function cinematicDashboard(){
   const result=originalDashboard.apply(this,arguments);
   // The regular dashboard still handles unrecognized states and errors.
   return typeof result==='string'&&result.includes('jw210-home')
     ? result+story() : result;
 };
 let observer=null,scrollFrame=0,activeScenes=[];
 let pointerFrame=0,lastPointer=null;
 const inDashboard=()=>!shell.classList.contains('hidden') &&
   main.querySelector('.jw222-scroll-story')!==null;
 const isMotion=()=>!reduced.matches && !document.hidden;
 function sync(){
   const home=main.querySelector('.jw210-home');
   const stories=main.querySelector('.jw222-scroll-story');
   if(!home||!stories||shell.classList.contains('hidden')){
     activeScenes=[];if(observer){observer.disconnect();observer=null;}
     return;
   }
   if(home.dataset.jw222Decor!=='yes'){
     home.dataset.jw222Decor='yes';
     const decor=document.createElement('div');
     decor.className='jw222-hero-atmosphere';
     decor.setAttribute('aria-hidden','true');
     decor.innerHTML='<span class="jw222-hero-float jw222-hero-float--one"></span>'+
       '<span class="jw222-hero-float jw222-hero-float--two"></span>'+
       '<span class="jw222-hero-float jw222-hero-float--three"></span>'+
       '<span class="jw222-hero-float jw222-hero-float--four"></span>';
     home.prepend(decor);
     const cue=document.createElement('button');
     cue.type='button';cue.className='jw222-scroll-cue';
     cue.innerHTML='<span>아래로 스크롤해 둘러보기</span><span aria-hidden="true">↓</span>';
     cue.addEventListener('click',()=>{
       main.querySelector('#jw222-story-source')?.scrollIntoView({
         behavior:reduced.matches?'instant':'smooth',block:'start'});
     });
     home.append(cue);
   }
   const scenes=[...stories.querySelectorAll('.jw222-scene')];
   if(activeScenes.length===scenes.length && activeScenes.every((x,i)=>x===scenes[i]))return;
   if(observer)observer.disconnect();
   activeScenes=scenes;
   if(!('IntersectionObserver' in window)||!isMotion()){
     scenes.forEach(s=>s.classList.add('jw222-inview'));
     return;
   }
   observer=new IntersectionObserver(entries=>{
     for(const entry of entries){
       if(entry.isIntersecting){
         entry.target.classList.add('jw222-inview');
       }
     }
   },{root:null,rootMargin:'0px 0px -8% 0px',threshold:.08});
   scenes.forEach(s=>{s.classList.add('jw222-motion-ready');observer.observe(s)});
   scheduleScroll();
 }
 function updateScroll(){
   scrollFrame=0;
   if(!inDashboard()||!isMotion())return;
   const height=window.innerHeight||800;
   for(const scene of activeScenes){
     if(!scene.isConnected)continue;
     const r=scene.getBoundingClientRect();
     if(r.bottom < -height*.3 || r.top>height*1.3)continue;
     const p=Math.max(-1,Math.min(1,(height*.55-(r.top+r.height*.5))/Math.max(height*.8,r.height*.7)));
     scene.style.setProperty('--jw222-shift',(p*-78).toFixed(2)+'px');
     scene.style.setProperty('--jw222-rotate',(p*8).toFixed(2)+'deg');
     scene.style.setProperty('--jw222-progress',((p+1)/2).toFixed(3));
   }
 }
 function scheduleScroll(){if(!scrollFrame)scrollFrame=requestAnimationFrame(updateScroll)}
 window.addEventListener('scroll',scheduleScroll,{passive:true});
 window.addEventListener('resize',scheduleScroll,{passive:true});
 reduced.addEventListener?.('change',()=>{sync();scheduleScroll()});
 document.addEventListener('visibilitychange',scheduleScroll);
 document.addEventListener('pointermove',ev=>{
   if(!fine.matches||!isMotion()||!inDashboard())return;
   const scene=ev.target.closest?.('.jw222-scene');
   if(!scene)return;
   lastPointer={scene,x:ev.clientX,y:ev.clientY};
   if(pointerFrame)return;
   pointerFrame=requestAnimationFrame(()=>{
     pointerFrame=0;
     const point=lastPointer;lastPointer=null;
     if(!point?.scene.isConnected)return;
     const rect=point.scene.getBoundingClientRect();
     const dx=(point.x-rect.left)/Math.max(rect.width,1)-.5;
     const dy=(point.y-rect.top)/Math.max(rect.height,1)-.5;
     point.scene.style.setProperty('--jw222-pointer-x',(dx*18).toFixed(2)+'px');
     point.scene.style.setProperty('--jw222-pointer-y',(dy*12).toFixed(2)+'px');
   });
 },{passive:true});
 document.addEventListener('pointerleave',e=>{
   const scene=e.target.closest?.('.jw222-scene');
   if(scene&&!scene.contains(e.relatedTarget)){
     scene.style.setProperty('--jw222-pointer-x','0px');
     scene.style.setProperty('--jw222-pointer-y','0px');
   }
 },true);
 document.addEventListener('click',e=>{
   const target=e.target.closest?.('[data-jw222-go]');
   if(!target||!main.contains(target))return;
   const page=target.dataset.jw222Go;
   if(!/^(dashboard|imports|automation|messenger)$/.test(page))return;
   window.JW_PREMIUM_V210?.goto(page); // click original validated business nav
 });
 let scheduled=false;
 new MutationObserver(()=>{
   if(scheduled)return;
   scheduled=true;
   requestAnimationFrame(()=>{scheduled=false;sync()});
 }).observe(main,{childList:true,subtree:false});
 new MutationObserver(()=>{if(!shell.classList.contains('hidden'))sync()})
   .observe(shell,{attributes:true,attributeFilter:['class']});
 sync();
 window.JW_CINEMATIC_V222=Object.freeze({
   version:'22.2',source:'user-supplied COSMOS reference video',
   storyScenes:3,externalMedia:false,usesExistingSinglePhoton:true,
   isMounted:()=>inDashboard()
 });
})();