/* V21.3: retained real authenticated controls, no alternate auth/session path. */
(() => {
  'use strict';
  const bar=document.querySelector('.jw210-utils');
  const logout=document.getElementById('logout');
  if(!bar||!logout||document.querySelector('.jw213-logout'))return;
  // Move the EXISTING logout button (and its registered backend POST handler),
  // do not clone or emulate authorization, do not fabricate a logged-out state.
  logout.classList.add('jw213-logout');
  logout.setAttribute('aria-label','안전하게 로그아웃');
  logout.setAttribute('title','로그아웃');
  bar.appendChild(logout);
  logout.addEventListener('click',()=>{
    const pw=document.querySelector('#login-form [name="password"]');
    if(pw)pw.value='';
  },{capture:true});
  window.JW_PREMIUM_V213=Object.freeze({version:'21.3',auth:'original-server-auth',home:'dashboard'});
})();
