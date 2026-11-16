/* V22.3 isolated owner review: self-owned profile and preferences only.
 * No local storage, no business-ledger changes, no arbitrary account target.
 */
(function(g){
'use strict';
const t=(tag,cls,text)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(text!==undefined)x.textContent=String(text);return x};
const message=e=>({
  STALE_VERSION:'다른 창에서 변경됐습니다. 최신 값을 조회한 뒤 다시 저장하세요.',
  SESSION_EXPIRED:'세션이 종료되었습니다. 다시 로그인하세요.',
  STALE_SESSION:'이전 사용자 응답은 적용할 수 없습니다.',
  FORBIDDEN:'이 작업은 허용되지 않습니다.',
  INVALID_PROFILE:'서버 프로필 검증에 실패했습니다.',
  INVALID_PREFERENCES:'서버 설정 검증에 실패했습니다.',
  NETWORK_ERROR:'서버 연결 상태를 확인할 수 없습니다.'
}[e?.code]||'서버 요청을 완료하지 못했습니다.');
const same=(a,b)=>Boolean(a&&b&&a.id===b.id&&a.org_id===b.org_id);
function apply(prefs){
  if(!prefs||typeof prefs.compact_view!=='boolean')return;
  document.body.classList.toggle('jw-compact-view',prefs.compact_view);
}
async function applySaved({bridge}){
  const who=bridge?.identity;
  if(!who)return;
  try{
    const prefs=await bridge.preferencesRead();
    if(same(who,bridge.identity))apply(prefs);
  }catch{/* Presentation remains functional without cosmetic preferences. */}
}
function note(parent,content){
  const n=t('p','jw-review-muted',content);n.setAttribute('role','status');parent.append(n);return n;
}
async function render({bridge,view,page,isCurrent}){
  if(!['account','settings'].includes(page)||!view||typeof isCurrent!=='function')throw Error('INVALID_CONTEXT');
  const who=bridge.identity;
  if(!who)throw Error('LOGIN_REQUIRED');
  const alive=()=>isCurrent()&&same(who,bridge.identity)&&bridge.signedIn;
  const card=t('section','jw-review-card');view.append(card);
  const status=note(card,'서버 데이터를 확인 중입니다.');
  const label=(text,control)=>{const l=t('label','jw-review-muted',text);l.append(control);return l};
  if(page==='account'){
    try {
      let profile=await bridge.profileRead();if(!alive())return;
      card.insertBefore(t('h3','jw-review-cardtitle','내 계정 · 서버 프로필'),status);
      note(card,profile.email+' · '+profile.org_name+' · '+profile.role);
      const form=t('form','jw-review-action-form'),input=t('input','jw-review-input'),button=t('button','jw-review-button','표시 이름 저장');
      input.type='text';input.maxLength=80;input.required=true;input.value=profile.name;
      input.setAttribute('aria-label','표시 이름');button.type='submit';
      form.append(label('표시 이름',input),button);card.append(form);
      form.addEventListener('submit',async ev=>{
        ev.preventDefault();if(!alive()||button.disabled)return;
        button.disabled=true;status.textContent='서버 저장 및 재조회 중';
        try {
          const changed=await bridge.profileSave(input.value,profile.version);
          const latest=await bridge.profileRead();
          if(!alive())return;
          if(latest.version!==changed.version||latest.name!==changed.name)throw Error('READBACK_MISMATCH');
          profile=latest;input.value=latest.name;
          const userLabel=document.querySelector('.jw-review-user');
          if(userLabel)userLabel.textContent=latest.name+' · '+latest.org_name;
          status.textContent='프로필을 서버에 저장하고 다시 확인했습니다.';
        }catch(err){if(alive()){status.textContent=message(err);status.setAttribute('role','alert')}}
        finally{button.disabled=false}
      });
    }catch(e){if(alive()){status.textContent=message(e);status.setAttribute('role','alert')}}
    return;
  }
  try{
    let pref=await bridge.preferencesRead();if(!alive())return;
    apply(pref);
    card.insertBefore(t('h3','jw-review-cardtitle','개인 업무 설정 · 서버 저장'),status);
    const form=t('form','jw-review-action-form');
    const compact=t('input','');compact.type='checkbox';compact.checked=pref.compact_view;compact.setAttribute('aria-label','간결한 업무 목록');
    const refresh=t('input','');refresh.type='checkbox';refresh.checked=pref.messenger_auto_refresh;refresh.setAttribute('aria-label','메신저 자동 새로고침');
    const button=t('button','jw-review-button','설정 저장');button.type='submit';
    form.append(label('간결한 업무 목록 사용',compact),
      label('메신저 자동 갱신 사용',refresh),button);card.append(form);
    note(card,'서버에서 저장된 설정입니다. 업무 데이터 또는 권한은 변경되지 않습니다.');
    form.addEventListener('submit',async ev=>{
      ev.preventDefault();if(!alive()||button.disabled)return;
      button.disabled=true;status.textContent='설정 서버 저장 및 재조회 중';
      try{
        const changed=await bridge.preferencesSave({version:pref.version,
          compact_view:compact.checked,messenger_auto_refresh:refresh.checked});
        const latest=await bridge.preferencesRead();
        if(!alive())return;
        if(changed.version!==latest.version||latest.compact_view!==changed.compact_view||
          latest.messenger_auto_refresh!==changed.messenger_auto_refresh)throw Error('READBACK_MISMATCH');
        pref=latest;apply(pref);
        status.textContent='설정을 서버에 저장하고 다시 확인했습니다.';
      }catch(e){if(alive()){status.textContent=message(e);status.setAttribute('role','alert')}}
      finally{button.disabled=false}
    });
  }catch(e){if(alive()){status.textContent=message(e);status.setAttribute('role','alert')}}
}
g.JWOwnerProfile={render,applySaved};
if(typeof module==='object'&&module.exports)module.exports={render,applySaved};
})(typeof window==='object'?window:globalThis);
