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
  // Restore all 10 approved legacy modules in the hover rail, without
  // exposing admin-only security to non-admin users or bypassing route guards.
  const rail=document.querySelector('.jw210-rail-panel');
  const railToggle=rail?.querySelector('.jw210-rail-toggle');
  const nav=document.getElementById('nav');
  if(rail&&railToggle&&nav){
    const homes=rail.querySelectorAll('.jw210-rail-item[data-jw210-page="dashboard"]');
    if(homes.length>1)homes[homes.length-1].remove(); // avoid duplicate "리포트"
    const legacy=[['customers','거래처 관리','♧'],['audit','변경 이력','◷'],['security','보안 관제','◇']];
    for(const [id,name,mark] of legacy){
      const original=nav.querySelector('button[data-page="'+id+'"]');
      if(!original)continue;
      const button=document.createElement('button');button.type='button';
      button.className='jw210-rail-item jw213-additional-link';
      button.dataset.jw210Page=id;
      const glyph=document.createElement('span');glyph.textContent=mark;glyph.setAttribute('aria-hidden','true');
      const title=document.createElement('span');title.textContent=name;
      button.append(glyph,title);
      button.setAttribute('aria-label',name);
      const sync=()=>{button.hidden=original.hidden;button.disabled=original.disabled;};
      button.addEventListener('click',()=>{
        if(original.hidden||original.disabled)return;
        original.click();
        window.JW_PREMIUM_V210?.closeRail();
      });
      new MutationObserver(sync).observe(original,{attributes:true,attributeFilter:['hidden','disabled']});
      rail.insertBefore(button,railToggle);sync();
    }
  }
  window.JW_PREMIUM_V213=Object.freeze({version:'21.3',auth:'original-server-auth',home:'dashboard'});
})();
