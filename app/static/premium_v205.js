/* JARVIS WORKS V20.5 — presentation-only modal exit, no business writes.
 * Original app.js, submit handlers, auth and route actions are preserved.
 * The existing closeModal() only removed DOM instantly. V20.5 animates the
 * same modal out, then removes exactly that old overlay (not a later dialog).
 */
(() => {
 'use strict';
 const root=document.getElementById('modal-root');
 const shell=document.getElementById('app-shell');
 const original=window.closeModal;
 if(!root||typeof original!=='function')return;
 const motionOff=()=>window.matchMedia('(prefers-reduced-motion: reduce)').matches;
 let exitTimer=0;
 window.closeModal=function premiumCloseModal(...args){
   const overlay=root.querySelector('.overlay');
   // Hidden login and assistive reduced-motion retain the exact original path.
   if(!overlay||!shell||shell.classList.contains('hidden')||motionOff()){
     if(exitTimer)window.clearTimeout(exitTimer);
     exitTimer=0;
     return original.apply(this,args);
   }
   if(overlay.classList.contains('jw205-closing'))return;
   overlay.classList.add('jw205-closing');
   // Focus leaves the exiting dialog, avoiding keyboard focus inside hidden UI.
   const active=document.activeElement;
   if(active&&overlay.contains(active))active.blur();
   exitTimer=window.setTimeout(()=>{
     exitTimer=0;
     // A newer modal may have been opened during the closing transition.
     if(root.contains(overlay))overlay.remove();
   },175);
 };
 window.JW_PREMIUM_V205={version:'20.5',closeAnimationMs:175,originalClosePreserved:true};
})();
