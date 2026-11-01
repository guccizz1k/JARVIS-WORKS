/* JARVIS WORKS V20.3 — motion orchestration only. No API calls or business data changes.
   Gated navigation feedback, reduced-motion support, safe DOM-only microinteractions. */
(() => {
 'use strict';
 const prefersReduced = window.matchMedia('(prefers-reduced-motion: reduce)');
 const motionOff = () => prefersReduced.matches;
 const content = document.getElementById('main-content');
 const shell = document.getElementById('app-shell');
 const sidebar = document.getElementById('sidebar');
 const progress = document.createElement('div');
 progress.id = 'jw-v203-progress';
 progress.setAttribute('aria-hidden','true');
 progress.innerHTML = '<i></i>';
 document.body.appendChild(progress);
 const drawerShade = document.createElement('div');
 drawerShade.id = 'jw-v203-mobile-shade';
 drawerShade.setAttribute('aria-hidden','true');
 document.body.appendChild(drawerShade);
 const pause = ms => new Promise(resolve=>window.setTimeout(resolve,ms));
 // V20.5 presentation is a single GPU-friendly reveal, not a stack of blur layers.
 const premium205 = Boolean(document.querySelector('link[href*="premium_v205.css"]'));
 let busy = false;
 let pending = null;
 const panelSelectors='.jw-v202-metric,.jw-v202-feature,.jw-v202-gauge,.jw-v202-panel,.jw-v202-board,.panel,.card';
 function clearBusy() {
   busy=false;
   document.body.classList.remove('jw-v203-loading');
   if(content)content.classList.remove('jw-v203-leaving');
   if(pending){pending.classList.remove('jw-v203-pending');pending=null;}
 }
 function syncDrawer(){
   const open=Boolean(sidebar?.classList.contains('open'))&&window.matchMedia('(max-width:760px)').matches;
   document.body.classList.toggle('jw-v203-drawer-open',open);
   const toggle=document.getElementById('toggle-menu');
   if(toggle){
     toggle.setAttribute('aria-expanded',String(open));
     toggle.setAttribute('aria-label',open?'메뉴 닫기':'메뉴 열기');
   }
 }
 drawerShade.addEventListener('click',()=>{
   sidebar?.classList.remove('open');
   syncDrawer();
 });
 const drawerWatch=new MutationObserver(syncDrawer);
 if(sidebar)drawerWatch.observe(sidebar,{attributes:true,attributeFilter:['class']});
 window.addEventListener('resize',syncDrawer,{passive:true});
 document.addEventListener('keydown',ev=>{
   if(ev.key==='Escape'&&sidebar?.classList.contains('open')){
     sidebar.classList.remove('open');syncDrawer();
   }
 });
 syncDrawer();
 function markStagger(root){
   if(premium205)return;
   let n=0;
   root.querySelectorAll(panelSelectors).forEach(el=>{
     // Avoid nested huge delays; max seven steps.
     el.style.setProperty('--jw-stagger',String(Math.min(n++,7)));
   });
 }
 function revealVisible(root){
   if(premium205||!('IntersectionObserver' in window)||motionOff())return;
   const targets=Array.from(root.querySelectorAll('.jw-v202-board,.jw-v202-panel,.jw-v202-tail > .panel'));
   if(!targets.length)return;
   const observer=new IntersectionObserver(entries=>{
     for(const entry of entries){
       if(entry.isIntersecting){
         entry.target.classList.remove('jw-v203-out-of-view');
         observer.unobserve(entry.target);
       }
     }
   },{threshold:.06,rootMargin:'0px 0px 70px 0px'});
   targets.forEach(el=>{el.classList.add('jw-v203-scroll-target');observer.observe(el);});
   window.setTimeout(()=>observer.disconnect(),8000);
 }
 window.JW_UI_MOTION={
   async beforeNavigate(page){
     if(!content)return;
     if(busy){clearBusy();}
     busy=true;
     pending=document.querySelector('[data-page="'+CSS.escape(page)+'"]');
     pending?.classList.add('jw-v203-pending');
     document.body.classList.add('jw-v203-loading');
     const hasCurrentScreen=content.children.length>0 && !shell.classList.contains('hidden');
     if(hasCurrentScreen && !motionOff()){
       content.classList.remove('jw-v203-entering');
       content.classList.add('jw-v203-leaving');
       await pause(premium205?55:125);
     }
   },
   afterNavigate(page,root){
     clearBusy();
     if(!root)return;
     root.classList.remove('jw-v203-entering');
     if(!motionOff()){
       // Re-trigger animation after DOM replacement without changing any content.
       void root.offsetWidth;
       markStagger(root);
       root.classList.add('jw-v203-entering');
       revealVisible(root);
     }
     syncDrawer();
   },
   navigationFailed(){clearBusy();syncDrawer();}
 };
 // Water ripple on mouse/touch direct press, without blocking clicks or
 // native button behavior. Never attach to form input fields.
 document.addEventListener('pointerdown',ev=>{
   if(motionOff()||ev.button!==0)return;
   const target=ev.target.closest('.btn,.nav-item,.jw-v202-theme-toggle,[data-action]');
   if(!target||target.disabled||target.tagName==='INPUT')return;
   const rect=target.getBoundingClientRect();
   if(rect.width<=0||rect.height<=0)return;
   const ripple=document.createElement('span');
   ripple.className='jw-v203-ripple';
   ripple.setAttribute('aria-hidden','true');
   ripple.style.setProperty('--jw-x',String(ev.clientX-rect.left)+'px');
   ripple.style.setProperty('--jw-y',String(ev.clientY-rect.top)+'px');
   ripple.style.setProperty('--jw-ripple-scale',String(Math.max(rect.width,rect.height)/9+3));
   target.appendChild(ripple);
   ripple.addEventListener('animationend',()=>ripple.remove(),{once:true});
   window.setTimeout(()=>ripple.remove(),750);
 },{passive:true});
 // Micro 3-D card response: pointer-only; reduced-motion/coarse pointers opt out.
 const fine=window.matchMedia('(hover:hover) and (pointer:fine)');
 // Coalesce mouse movement into 1 transform update / animation frame.
 // The old handler read bounding rectangles and wrote styles on every raw event.
 let pendingTilt=null,tiltFrame=0;
 document.addEventListener('pointermove',ev=>{
   if(motionOff()||!fine.matches)return;
   const target=ev.target.closest('.jw-v202-metric,.jw-v202-gauge');
   if(!target)return;
   pendingTilt={target,x:ev.clientX,y:ev.clientY};
   if(tiltFrame)return;
   tiltFrame=window.requestAnimationFrame(()=>{
     tiltFrame=0;
     const data=pendingTilt;pendingTilt=null;
     if(!data||!data.target.isConnected)return;
     const rect=data.target.getBoundingClientRect();
     if(rect.width<=0||rect.height<=0)return;
     const dx=(data.x-rect.left)/rect.width-.5;
     const dy=(data.y-rect.top)/rect.height-.5;
     data.target.style.setProperty('--jw-tilt-x',(-dy*4).toFixed(2)+'deg');
     data.target.style.setProperty('--jw-tilt-y',(dx*4).toFixed(2)+'deg');
   });
 },{passive:true});
 document.addEventListener('pointerout',ev=>{
   const node=ev.target.closest('.jw-v202-metric,.jw-v202-gauge');
   if(node&&!node.contains(ev.relatedTarget)){
     node.style.removeProperty('--jw-tilt-x');
     node.style.removeProperty('--jw-tilt-y');
   }
 },{passive:true});
 // Theme ripple is a visual overlay only, actual theme state stays in V20.2.
 document.addEventListener('click',ev=>{
   const toggle=ev.target.closest('#jw-v202-theme-toggle');
   if(!toggle||motionOff())return;
   const burst=document.createElement('i');
   burst.className='jw-v203-theme-flash';
   burst.setAttribute('aria-hidden','true');
   burst.style.setProperty('--fx',String(ev.clientX)+'px');
   burst.style.setProperty('--fy',String(ev.clientY)+'px');
   const isBlue=document.documentElement.getAttribute('data-jw-theme')==='blue';
   burst.style.setProperty('--flash-color',isBlue?'#a1dabe':'#a6c0fd');
   document.body.appendChild(burst);
   burst.addEventListener('animationend',()=>burst.remove(),{once:true});
   window.setTimeout(()=>burst.remove(),850);
 },{capture:true});
 // Avoid leaking animation state when the original auth flow returns to login.
 const loginWatch=new MutationObserver(()=>{
   if(shell?.classList.contains('hidden')){clearBusy();sidebar?.classList.remove('open');syncDrawer();}
 });
 if(shell)loginWatch.observe(shell,{attributes:true,attributeFilter:['class']});
})();
