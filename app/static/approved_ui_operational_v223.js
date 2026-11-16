/* V22.3 owner-approved server-only review: messenger & admin controls.
 * Exact original UI is immutable. No local DB, HTML injection or background writes.
 * All mutations are explicit and use the authenticated bridge's allowlisted CSRF API.
 */
(function (g) {
  'use strict';
  const M32 = /^[a-f0-9]{32}$/;
  let activeCleanup=null;
  function dispose(){if(activeCleanup){const fn=activeCleanup;activeCleanup=null;fn()}}
  const ERRORS = Object.freeze({
    LOGIN_REQUIRED: '로그인이 필요합니다.', SESSION_EXPIRED: '세션이 종료되었습니다.',
    STALE_SESSION: '사용자 세션이 변경됐습니다. 다시 조회하세요.', AUTH_BUSY: '인증 상태를 확인하고 다시 요청하세요.',
    FORBIDDEN: '접근 권한이 없습니다.', ADMIN_ONLY: '관리자 전용 기능입니다.',
    NETWORK_ERROR: '서버 연결을 확인할 수 없습니다.', TENANT_MISMATCH: '기업 간 데이터 접근이 차단됐습니다.',
    BAD_THREAD: '대화 정보를 검증할 수 없습니다.', INVALID_MESSAGES: '서버 메시지 응답을 검증할 수 없습니다.',
    INVALID_PEOPLE: '직원 정보를 검증할 수 없습니다.', INVALID_SECURITY: '보안 정보를 검증할 수 없습니다.',
    API_FAILURE: '서버에서 요청을 처리하지 못했습니다.'
  });
  function el(tag, klass, value) {
    const node = document.createElement(tag);
    if (klass) node.className = klass;
    if (value !== undefined) node.textContent = String(value);
    return node;
  }
  function notice(root, message, error = false) {
    const node = el('p', error ? 'jw-review-failure' : 'jw-review-muted', message);
    node.setAttribute('role', error ? 'alert' : 'status'); root.append(node); return node;
  }
  function why(error) { return ERRORS[error?.code] || '요청을 처리할 수 없습니다. 서버 상태를 확인하세요.'; }
  function sameIdentity(a,b) { return Boolean(a && b && a.id === b.id && a.org_id === b.org_id); }
  function exactBridge(bridge) {
    if (!bridge || !bridge.identity || !bridge.signedIn) throw Object.assign(new Error('LOGIN_REQUIRED'), {code:'LOGIN_REQUIRED'});
    return bridge.identity;
  }
  function current(bridge, user, isCurrent) {
    return isCurrent() && sameIdentity(user, bridge.identity) && bridge.signedIn;
  }
  function randomRequestId() {
    if (!globalThis.crypto || typeof globalThis.crypto.getRandomValues !== 'function')
      throw Object.assign(new Error('SECURE_RANDOM_REQUIRED'), {code:'SECURE_RANDOM_REQUIRED'});
    const bytes = new Uint8Array(16); globalThis.crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2,'0')).join('');
  }
  function formButton(label) {
    const button = el('button', 'jw-review-action-button', label); button.type='button'; return button;
  }
  async function messenger({bridge, view, isCurrent}) {
    const user = exactBridge(bridge);
    let active = null, requestId = null, requestText = null, sending = false, autoRefreshEnabled=false;
    const header = el('section','jw-review-card');
    header.append(el('h3','jw-review-cardtitle','기업 간 보안 메신저'));
    notice(header,'서버 저장된 메시지만 표시합니다. 발송 결과가 불확실하면 먼저 서버에서 재조회하세요.');
    const directory = el('select','jw-review-input'); directory.setAttribute('aria-label','대화 상대 기업');
    const option = el('option','', '상대 기업 선택'); option.value=''; directory.append(option);
    const create = formButton('기업 대화 시작');
    const refresh = formButton('대화 목록 새로고침');
    const status = el('div','jw-review-muted'); status.setAttribute('role','status');
    const threadsBox = el('section','jw-review-card'), messagesBox = el('section','jw-review-card');
    header.append(directory, create, refresh, status); view.append(header,threadsBox,messagesBox);
    const fail = e => { if (current(bridge,user,isCurrent)) {status.textContent=why(e);status.setAttribute('role','alert');} };
    async function showMessages(thread) {
      if (!current(bridge,user,isCurrent)) return;
      const previousThread=active;
      active = thread.id;
      const savedDraft=previousThread===thread.id ? (messagesBox.querySelector('textarea')?.value || '') : '';
      messagesBox.replaceChildren(el('h3','jw-review-cardtitle',thread.other_company+' · 대화'));
      const requestFor = thread.id;
      try {
        const messages = await bridge.messengerMessages(requestFor, thread.other_org_id);
        if (!current(bridge,user,isCurrent) || active !== requestFor) return;
        for (const msg of messages) {
          const item = el('div','jw-review-row', (msg.mine?'나':'상대 기업')+' · '+msg.body);
          messagesBox.append(item);
        }
        if (!messages.length) notice(messagesBox,'아직 서버 메시지가 없습니다.');
        if (messages.length && !messages[messages.length-1].mine) {
          // Explicit user action only, not an automatic read-side effect.
          const mark = formButton('여기까지 읽음 처리');
          mark.onclick = async () => {
            mark.disabled = true;
            try {
              await bridge.messengerMarkRead(requestFor,messages[messages.length-1].id);
              if (current(bridge,user,isCurrent) && active===requestFor) status.textContent='읽음 상태를 서버에서 확인했습니다.';
            } catch(e) {fail(e)} finally {mark.disabled=false}
          };
          messagesBox.append(mark);
        }
        const entry = el('form','jw-review-action-form'), input = el('textarea','jw-review-input');
        input.maxLength=2000;input.required=true;input.rows=3;input.value=savedDraft;input.setAttribute('aria-label','전송할 메시지');
        const send = el('button','jw-review-button','메시지 전송');send.type='submit';
        const delivery = el('p','jw-review-muted','전송 전'); delivery.setAttribute('role','status');
        entry.append(input,send,delivery);messagesBox.append(entry);
        entry.addEventListener('submit',async event => {
          event.preventDefault(); if (sending || !current(bridge,user,isCurrent) || active !== requestFor) return;
          const body = input.value.trim(); if (!body || body.length>2000) return;
          if (requestText !== body) {requestText=body;requestId=randomRequestId();}
          sending=true;send.disabled=true;delivery.textContent='서버 저장 및 재조회 확인 중';
          try {
            const result = await bridge.messengerSend(requestFor,body,requestId);
            const after = await bridge.messengerMessages(requestFor, thread.other_org_id);
            if (!current(bridge,user,isCurrent) || active!==requestFor) return;
            if (!after.some(x=>x.id===result.id && x.body===body && x.mine===true))
              throw Object.assign(new Error('READBACK_MISMATCH'),{code:'READBACK_MISMATCH'});
            input.value=''; requestId=null;requestText=null;
            await showMessages(thread);
            if (current(bridge,user,isCurrent)) status.textContent='메시지 서버 저장·재조회 완료';
          } catch(e) {
            if (current(bridge,user,isCurrent) && active===requestFor) {
              delivery.textContent=why(e)+' 전송 결과가 불확실하면 목록을 다시 확인하세요.';
              delivery.setAttribute('role','alert');
            }
          } finally {sending=false;send.disabled=false;}
        });
      } catch(e) {fail(e)}
    }
    // SSE is a change signal only. All data always comes from authorized GETs.
    // Timer remains a bounded fallback if SSE is unavailable or disconnected.
    function beginLive(thread){
      dispose();
      if(!autoRefreshEnabled||!current(bridge,user,isCurrent)||active!==thread.id)return;
      let stopped=false,source=null,retry=null,retryMs=1000,running=false;
      const isLive=()=>!stopped&&current(bridge,user,isCurrent)&&active===thread.id;
      async function sync(){
        if(!isLive()){dispose();return}
        if(running||sending)return;
        running=true;
        try{await showMessages(thread);if(isLive())await listThreads()}
        catch(e){fail(e)}
        finally{running=false}
      }
      function connect(){
        if(!isLive()||typeof g.EventSource!=='function')return;
        try{
          source=new g.EventSource(location.origin+'/api/messenger/threads/'+thread.id+'/events',
            {withCredentials:true});
          source.addEventListener('open',()=>{retryMs=1000});
          source.addEventListener('change',()=>{void sync()});
          source.addEventListener('revoked',()=>{
            if(!isLive())return;
            dispose();
            if(current(bridge,user,isCurrent))status.textContent='메신저 접근 권한 또는 세션이 종료됐습니다.';
          });
          source.onerror=()=>{
            source?.close();source=null;
            if(!isLive())return;
            retry=setTimeout(connect,retryMs);
            retryMs=Math.min(retryMs*2,30000);
          };
        }catch{
          if(isLive()){retry=setTimeout(connect,retryMs);retryMs=Math.min(retryMs*2,30000)}
        }
      }
      const tick=setInterval(()=>{if(!document.hidden)void sync()},8000);
      activeCleanup=()=>{stopped=true;clearInterval(tick);if(retry!==null)clearTimeout(retry);source?.close();source=null};
      connect();
    }
    async function listThreads() {
      const rows = await bridge.messengerThreads();
      if (!current(bridge,user,isCurrent)) return;
      threadsBox.replaceChildren(el('h3','jw-review-cardtitle','대화 목록'));
      if (!rows.length) notice(threadsBox,'연결된 기업 대화가 없습니다.');
      for (const thread of rows) {
        const btn = formButton(thread.other_company+' · 안 읽음 '+thread.unread_count+'건');
        btn.onclick=async()=>{await showMessages(thread);beginLive(thread)};threadsBox.append(btn);
      }
    }
    create.onclick = async () => {
      if (!directory.value || !M32.test(directory.value)) return;
      create.disabled = true;
      try {const thread=await bridge.messengerCreateThread(directory.value);if (!current(bridge,user,isCurrent)) return;await listThreads();await showMessages(thread);beginLive(thread)}
      catch(e){fail(e)} finally{create.disabled=false}
    };
    refresh.onclick=async()=>{refresh.disabled=true;try{await listThreads();if(active){const x=(await bridge.messengerThreads()).find(t=>t.id===active);if(x)await showMessages(x)}}catch(e){fail(e)}finally{refresh.disabled=false}};
    try {
      const [companies,prefs] = await Promise.all([bridge.messengerDirectory(),bridge.preferencesRead(),listThreads()]);
      autoRefreshEnabled=prefs.messenger_auto_refresh;
      if (!current(bridge,user,isCurrent)) return;
      for(const company of companies){
        const opt=el('option','',company.company_name);opt.value=company.org_id;directory.append(opt);
      }
      if (!companies.length) status.textContent='기업 인증된 대화 상대가 없습니다.';
    } catch(e){fail(e)}
  }
  async function admin({bridge, view, page, isCurrent}) {
    const user = exactBridge(bridge);
    if(user.role!=='admin'){notice(view,'관리자에게만 허용된 화면입니다.',true);return}
    const status = notice(view,'조직·보안 정보를 서버에서 조회합니다.');
    const details = el('section','jw-review-card');view.append(details);
    async function display() {
      const result=await bridge.securityManageOverview();
      if(!current(bridge,user,isCurrent))return;
      details.replaceChildren(el('h3','jw-review-cardtitle',page==='team'?'직원 관리':'보안·세션 관리'));
      if(page==='team'){
        for(const person of result.users){
          const line=el('div','jw-review-row'), name=el('span','',(person.name||'이름 없음')+' · '+person.role+(person.disabled_at?' · 비활성':' · 활성'));
          line.append(name);
          if(person.id!==user.id){
            const passwordInput=el('input','jw-review-input');
            passwordInput.type='password';passwordInput.autocomplete='current-password';
            passwordInput.setAttribute('aria-label','관리자 재인증 비밀번호');
            const btn=formButton(person.disabled_at?'직원 재활성화':'직원 비활성화');
            btn.onclick=async()=>{
              if(!current(bridge,user,isCurrent))return;
              if(!window.confirm('이 직원의 계정 상태를 변경하시겠습니까? 세션이 영향을 받을 수 있습니다.'))return;
              // Existing server requires reauthentication; do not log or store credentials.
              const password=passwordInput.value; passwordInput.value='';
              if(!password){status.textContent='관리자 재인증 비밀번호를 입력하세요.';return;}
              btn.disabled=true;
              try{await bridge.securitySetStaffActive(person.id,Boolean(person.disabled_at),password);
                if(current(bridge,user,isCurrent)){await display();status.textContent='서버에서 직원 상태 변경을 확인했습니다.'}}
              catch(e){if(current(bridge,user,isCurrent)){status.textContent=why(e);status.setAttribute('role','alert')}}
              finally{btn.disabled=false}
            };
            const roleButton=formButton(person.role==='admin'?'관리자 권한 해제':'관리자로 지정');
            roleButton.disabled=Boolean(person.disabled_at);
            roleButton.onclick=async()=>{
              if(!current(bridge,user,isCurrent)||roleButton.disabled)return;
              if(!window.confirm('직원 권한 변경 후 기존 로그인 세션을 종료하시겠습니까?'))return;
              const password=passwordInput.value;passwordInput.value='';
              if(!password){status.textContent='관리자 재인증 비밀번호를 입력하세요.';return}
              roleButton.disabled=true;
              try{
                const nextRole=person.role==='admin'?'member':'admin';
                await bridge.securityChangeStaffRole(person.id,person.role,nextRole,password);
                if(current(bridge,user,isCurrent)){
                  await display();status.textContent='직원 권한과 세션 상태를 서버에서 다시 확인했습니다.';
                }
              }catch(e){
                if(current(bridge,user,isCurrent)){status.textContent=why(e);status.setAttribute('role','alert')}
              }finally{roleButton.disabled=false}
            };
            line.append(passwordInput,btn,roleButton);
          }
          details.append(line);
        }
      } else {
        notice(details,'활성 세션 '+result.sessions.length+'건 · 보안 이벤트 '+result.events.length+'건');
        notice(details,'DB RLS '+(result.db_row_level_security_enabled?'활성':'미확인')+' · MFA 등록 '+result.mfa_enabled_user_count+'명');
        for(const session of result.sessions){
          const line=el('div','jw-review-row','세션 · '+(session.is_current?'현재 기기':'다른 기기'));
          if(!session.is_current){
            const btn=formButton('세션 회수');
            btn.onclick=async()=>{
              if(!window.confirm('이 로그인 세션을 회수하시겠습니까?'))return;
              btn.disabled=true;
              try {await bridge.securityRevokeSession(session.id);if(current(bridge,user,isCurrent)){await display();status.textContent='서버 세션 회수 확인'}}
              catch(e){if(current(bridge,user,isCurrent)){status.textContent=why(e);status.setAttribute('role','alert')}}
              finally{btn.disabled=false}
            };
            line.append(btn);
          }
          details.append(line);
        }
      }
    }
    try{await display()}catch(e){if(current(bridge,user,isCurrent)){status.textContent=why(e);status.setAttribute('role','alert')}}
  }
  async function render({bridge,view,page,isCurrent}) {
    dispose();
    if(!view||typeof isCurrent!=='function')throw new Error('RENDER_CONTEXT_REQUIRED');
    if(page==='messenger')return messenger({bridge,view,isCurrent});
    if(page==='team'||page==='security')return admin({bridge,view,page,isCurrent});
    throw new Error('UNSUPPORTED_OPERATIONAL_PAGE');
  }
  g.JWOwnerOperational={render,dispose,randomRequestId};
  if(typeof module==='object'&&module.exports)module.exports={render,randomRequestId};
})(typeof window==='object'?window:globalThis);
