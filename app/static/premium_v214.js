/* JARVIS-WORKS V21.4 — desktop-only, dark-only workspace.
 * Presentation layer only; do not touch APIs, authorizations or business math.
 */
(() => {
  'use strict';
  const shell=document.getElementById('app-shell');
  const main=document.getElementById('main-content');
  if(!shell||!main||!window.JW_PREMIUM_V213)return;

  // Respect the confirmed dark-only product policy, including previously
  // persisted light-mode settings. Old UI toggles have been retired.
  function enforceDark(){
    if(document.documentElement.dataset.jw206Theme!=='dark'){
      window.JW_PREMIUM_V206?.setTheme('dark');
      document.documentElement.dataset.jw206Theme='dark';
    }
    document.querySelector('meta[name="color-scheme"]')?.setAttribute('content','dark');
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content','#070b12');
  }
  enforceDark();
  new MutationObserver(enforceDark).observe(document.documentElement,{
    attributes:true,attributeFilter:['data-jw206-theme']
  });
  document.querySelector('.jw206-theme-switch')?.remove();
  document.querySelector('.jw211-login-modes')?.remove();

  // The approved user experience is PC-only. A narrow screen explains why
  // business actions are unavailable instead of presenting a broken form.
  const notice=document.createElement('section');
  notice.className='jw214-desktop-notice';
  notice.setAttribute('role','status');
  const head=document.createElement('h1');
  head.textContent='JARVIS-WORKS';
  const message=document.createElement('p');
  message.textContent='이 업무 시스템은 PC 전용입니다. 데스크톱 브라우저에서 접속해 주세요.';
  const detail=document.createElement('small');
  detail.textContent='데스크톱 권장 해상도: 1366 × 768 이상 · Chrome 또는 Edge';
  notice.append(head,message,detail);
  document.body.append(notice);

  // Preserve the signed-in app, while displaying the requested entrance
  // AFTER the real authenticated dashboard has rendered.
  let entrancePending=false;
  function onAuthenticated(){
    entrancePending=true;
    shell.classList.remove('jw214-entry-playing');
    sync();
  }
  function sync(){
    if(main.querySelector('.jw210-home') && !shell.classList.contains('hidden') && entrancePending){
      entrancePending=false;
      if(!matchMedia('(prefers-reduced-motion: reduce)').matches){
        shell.classList.remove('jw214-entry-playing');
        void shell.offsetWidth;
        shell.classList.add('jw214-entry-playing');
      }
    }
    // Two actual import forms work side by side on a wide desktop.
    const forms=[...main.querySelectorAll(':scope > .import-upload-panel')];
    if(forms.length===2){
      const grid=document.createElement('div');
      grid.className='jw214-upload-grid';
      forms[0].before(grid);
      grid.append(...forms);
    }
  }
  new MutationObserver(sync).observe(main,{childList:true});
  // Remove animated state after its genuine animation completes. Future
  // app interactions continue to use the existing V21.1 aperture transition.
  shell.addEventListener('animationend',event=>{
    if(event.animationName==='jw214-auth-enter' &&
       event.target===main){
      shell.classList.remove('jw214-entry-playing');
    }
  });
  window.JW_DESKTOP_V214=Object.freeze({
    version:'21.4',mode:'desktop-dark-only',onAuthenticated
  });
  sync();
})();
