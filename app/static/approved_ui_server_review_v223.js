/* Dedicated server review shell, never auto-activates in the protected original. */
(function(g){
'use strict';
const MENUS=[['home','홈','all'],['docs','문서',''],['deals','거래','quotes'],['papers','거래 문서','quotes'],
['money','입금·미수금','invoices'],['partners','거래처','customers'],['messenger','메신저',''],
['automation','자동화',''],['stats','통계',''],['export','내보내기',''],['inbox','승인함',''],
['files','첨부 파일',''],['activity','감사 이력',''],['team','직원',''],['security','보안',''],['settings','설정',''],['account','내 계정','identity']];
const t=(tag,cls,text)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(text!==undefined)x.textContent=String(text);return x};
const clear=e=>e.replaceChildren();
const msg=e=>({'SESSION_EXPIRED':'세션이 종료되었습니다.','TENANT_MISMATCH':'다른 회사의 데이터가 확인되어 조회를 차단했습니다.','NETWORK_ERROR':'서버 연결 실패','FORBIDDEN':'접근 권한 없음','HTTPS_REQUIRED':'HTTPS 연결이 필요합니다.','ADMIN_ONLY':'관리자에게만 허용된 보안 정보입니다.','INVALID_STATISTICS':'서버 통계 형식을 확인할 수 없습니다.','INVALID_STATEMENT_RESPONSE':'거래명세표 응답을 검증할 수 없습니다.','STATEMENT_IDENTITY_MISMATCH':'문서 원장과 서버 문서가 일치하지 않습니다.','INVALID_TRANSACTION_TRACE':'거래 이력 검증에 실패했습니다.','INVALID_ACTIVE_TIMER':'측정 상태 검증에 실패했습니다.','TIMER_NOT_ACTIVE':'진행 중인 측정을 다시 확인하세요.','INVALID_TIMER_COMPLETION':'서버 측정 결과를 검증할 수 없습니다.','AUTOMATED_REQUIRES_NEW_STATEMENT':'자동화 측정은 새 확정 문서가 필요합니다.'}[e&&e.code]||'요청을 처리할 수 없습니다.');
function start(){
  const root=document.getElementById('app'), login=document.getElementById('login');document.getElementById('intro')?.remove();
  const ownerVisual=document.body?.dataset.jwReviewMode==='owner-visual';
  if(ownerVisual)document.body.classList.add('jw-owner-visual');
  document.documentElement.dataset.theme='dark';document.body.classList.add('jw-approved-review');clear(root);clear(login);login.hidden=false;
  let bridge;try{bridge=new g.JWOwnerServerBridge()}catch(e){login.append(t('p','jw-review-failure',msg(e)));return}
  let epoch=0,submitting=false;
  function entry(note){
    g.JWOwnerOperational?.dispose?.();
    ++epoch;root.classList.remove('on');clear(root);clear(login);login.hidden=false;
    if(ownerVisual)window.JWOwnerVisualGL?.setMode('login');
    const c=t('section','jw-review-entry');c.append(t('small','jw-review-kicker','JARVIS WORKS · SECURE REVIEW'),t('h2','jw-review-heading',ownerVisual?'다시 오신 것을 환영합니다':'WORK WITHOUT EDGES.'),t('p','jw-review-muted','실제 서버 인증 · 읽기 전용 연결 검토'));
    if(ownerVisual){
      c.classList.add('lcard','go');
      const brand=t('div','lbrand');const logo=t('div','logo','JW');brand.append(logo,t('span','', 'JARVIS WORKS'));
      const poster=t('div','poster jw-owner-brand');poster.append(t('div','mono','JARVIS WORKS · 기업 업무 자동화'));
      const mega=t('h1','mega go');
      for(const [word,klass] of [['WORK',''],['WITHOUT','o'],['EDGES.','l']]){
        const line=t('span',klass);line.append(t('b','',word));mega.append(line);
      }
      poster.append(mega,t('p','tag','문서에서 정산까지, 경계 없이 이어지는 하나의 업무 흐름.'));
      login.append(brand,poster);
    }
    const form=t('form','jw-review-form'),em=t('input','jw-review-input'),pw=t('input','jw-review-input'),otp=t('input','jw-review-input'),btn=t('button','jw-review-button','서버 로그인'),alert=t('p','jw-review-muted',note||'등록된 서버 계정으로 로그인하세요.');
    em.type='email';em.required=true;em.autocomplete='username';em.placeholder='이메일';em.setAttribute('aria-label','이메일');
    pw.type='password';pw.required=true;pw.autocomplete='current-password';pw.placeholder='비밀번호';pw.setAttribute('aria-label','비밀번호');
    otp.autocomplete='one-time-code';otp.placeholder='MFA 코드 (선택)';otp.setAttribute('aria-label','MFA 코드');
    btn.type='submit';if(ownerVisual)form.classList.add('form');form.append(em,pw,otp,btn,alert);c.append(form,t('p','jw-review-muted','로컬 회사 등록 · 브라우저 거래 저장 · 서버 미검증 거래 수정 비활성'));login.append(c);
    form.addEventListener('submit',async e=>{e.preventDefault();if(submitting)return;submitting=true;btn.disabled=true;
      try{const who=await bridge.login(em.value,pw.value,otp.value);pw.value='';otp.value='';dashboard(who)}
      catch(err){pw.value='';otp.value='';alert.textContent=msg(err);alert.setAttribute('role','alert')}
      finally{submitting=false;btn.disabled=false}});
  }
  function dashboard(who){
    ++epoch;clear(login);login.hidden=true;clear(root);root.classList.add('on');
    if(ownerVisual)window.JWOwnerVisualGL?.setMode('home');
    const shell=t('div','jw-review-shell'),nav=t('nav','jw-review-nav'),content=t('main','jw-review-main'),head=t('header','jw-review-top'),view=t('section','jw-review-view');
    nav.setAttribute('aria-label','업무 메뉴');
    const navList=ownerVisual?t('div','rsc'):nav;
    if(ownerVisual){
      shell.classList.add('jw-owner-shell');
      nav.classList.add('rail');
      content.classList.add('main');
      head.classList.add('top');
      view.classList.add('view');
      const brand=t('div','jw-owner-rlogo rlogo');brand.append(t('div','logo','JW'),t('span','', 'JARVIS WORKS'));
      nav.append(brand,navList);
    }else nav.append(t('strong','jw-review-mark','JW ∞'));
    const ownerGlyphs=['⌂','▤','⇄','▧','₩','▦','◉','⚙','▥','↓','✓','▣','◷','♧','◇','⚙','◌'];
    for(const [i,[key,label]] of MENUS.entries()){
      const b=t('button',ownerVisual?'jw-review-navitem ritem':'jw-review-navitem');
      b.type='button';b.dataset.page=key;b.setAttribute('aria-label',label);b.title=label;
      if(ownerVisual){b.append(t('b','jw-owner-glyph',ownerGlyphs[i]),t('span','jw-owner-nav-label',label));}
      else b.textContent=label;
      b.onclick=()=>open(key);navList.append(b);
    }
    const logout=t('button','jw-review-logout','로그아웃');logout.onclick=async()=>{let note='서버에서 로그아웃했습니다.';try{await bridge.logout()}catch{note='서버 로그아웃을 확인하지 못했습니다. 연결 상태를 확인한 뒤 다시 시도하세요.'}entry(note)};
    head.append(t('span','jw-review-kicker','서버 데이터 연결 검토'),t('span','jw-review-user',who.name+' · '+who.org_name),logout);content.append(head,view);shell.append(nav,content);root.append(shell);
    void g.JWOwnerProfile?.applySaved?.({bridge});
    if(ownerVisual){
      // The original source's mobile bottom navigation has 5 shortcuts.
      // '전체' exposes all 17 routes with a keyboard-accessible dialog.
      const bottom=t('nav','jw-owner-bottomnav bottomnav');
      bottom.setAttribute('aria-label','모바일 주요 메뉴');
      const menu=t('div','jw-owner-menu-dialog');
      menu.id='jw-owner-menu';menu.setAttribute('role','dialog');menu.setAttribute('aria-modal','true');
      menu.setAttribute('aria-label','전체 메뉴');menu.setAttribute('aria-hidden','true');
      const panel=t('div','jw-owner-menu-panel');const heading=t('h2','', '전체 업무 메뉴');
      const close=t('button','btn ghost sm','닫기');close.type='button';
      function closeMobile(){menu.setAttribute('aria-hidden','true');navList.querySelector('.selected')?.focus();}
      close.onclick=closeMobile;
      const list=t('div','jw-owner-menu-grid');
      for(const [key,label] of MENUS){
        const btn=t('button','',label);btn.type='button';btn.dataset.page=key;
        btn.onclick=()=>{closeMobile();open(key)};
        list.append(btn);
      }
      menu.addEventListener('click',e=>{if(e.target===menu)closeMobile()});
      menu.addEventListener('keydown',e=>{if(e.key==='Escape'){e.preventDefault();closeMobile()}});
      panel.append(heading,close,list);menu.append(panel);
      for(const [key,label,glyph] of [['home','홈','⌂'],['docs','문서','▤'],['deals','거래','⇄'],['automation','자동화','⚙'],['stats','통계','▥']]){
        const b=t('button','',label);b.type='button';b.dataset.page=key;
        b.replaceChildren(t('span','jw-owner-mobile-glyph',glyph),t('span','',label));b.onclick=()=>open(key);bottom.append(b);
      }
      const more=t('button','','전체');more.type='button';more.dataset.action='show-all';
      more.replaceChildren(t('span','jw-owner-mobile-glyph','☷'),t('span','', '전체'));
      more.onclick=()=>{menu.setAttribute('aria-hidden','false');close.focus();};
      bottom.append(more);root.append(bottom,menu);
    }
    async function open(key){
      g.JWOwnerOperational?.dispose?.();
      let selected=MENUS.find(m=>m[0]===key)||MENUS[0];let token=++epoch;
      if(ownerVisual)window.JWOwnerVisualGL?.setMode(key==='home'?'home':'away');
      nav.querySelectorAll('button').forEach(b=>b.classList.toggle('selected',b.dataset.page===key));
      if(ownerVisual)root.querySelectorAll('.jw-owner-bottomnav button[data-page]').forEach(b=>b.classList.toggle('selected',b.dataset.page===key));
      clear(view);view.append(t('small','jw-review-kicker','JARVIS WORKS'),t('h2','jw-review-title',selected[1]));
      if(['messenger','team','security'].includes(key)){
        if(!g.JWOwnerOperational){view.append(t('p','jw-review-unwired','업무 모듈을 불러오지 못했습니다.'));return}
        await g.JWOwnerOperational.render({bridge,view,page:key,isCurrent:()=>token===epoch});return;
      }
      if(key==='papers'){
        if(!g.JWOwnerStatements){view.append(t('p','jw-review-unwired','거래 문서 서버 모듈이 없습니다.'));return}
        await g.JWOwnerStatements.render({bridge,view,isCurrent:()=>token===epoch});return;
      }
      if(['account','settings'].includes(key)){
        if(!g.JWOwnerProfile){view.append(t('p','jw-review-unwired','계정 설정 서버 모듈을 불러오지 못했습니다.'));return}
        await g.JWOwnerProfile.render({bridge,view,page:key,isCurrent:()=>token===epoch});return;
      }

      if(key==='export'){
        if(!g.JWOwnerDocumentExport){view.append(t('p','jw-review-unwired','문서 내보내기 모듈을 불러오지 못했습니다.'));return}
        await g.JWOwnerDocumentExport.render({bridge,view,isCurrent:()=>token===epoch});return;
      }

      if(['docs','inbox','files'].includes(key)){
        if(!g.JWOwnerEvidenceReview){view.append(t('p','jw-review-unwired','문서 검토 모듈을 불러오지 못했습니다.'));return}
        await g.JWOwnerEvidenceReview.render({bridge,view,page:key,isCurrent:()=>token===epoch});return;
      }

      // Operational read-only panels: server is the sole source of truth.
      const readOnlyPanels=new Set(['stats','automation','activity','messenger','docs','files','inbox','security','team']);
      if(readOnlyPanels.has(key)){
        try{
          const data=await bridge.readPanel(key);
          if(token!==epoch)return;
          const card=(heading)=>{
            const section=t('section','jw-review-card');
            section.append(t('h3','jw-review-cardtitle',heading));view.append(section);return section;
          };
          const line=(box,content)=>box.append(t('div','jw-review-row',content));
          const empty=()=>line(card('서버 조회 결과'),'자료 없음');
          if(key==='stats'){
            const box=card('기업별 실제 서버 현황');
            const labels={customers:'거래처',quotes:'견적',orders:'수주',invoices:'청구'};
            for(const [k,v] of Object.entries(data.counts))line(box,(labels[k]||k)+' · '+v+'건');
            line(box,'미수금 '+data.money.outstanding.toLocaleString('ko-KR')+'원');
            line(box,'입금 누계 '+data.money.collected.toLocaleString('ko-KR')+'원');
            line(box,'견적 누계 '+data.money.quote_total.toLocaleString('ko-KR')+'원');
            const measured=card('업무 절감시간 · 서버 실측');
            line(measured,data.measured?'관측된 중위수 차이 '+data.observed_difference_ms+'ms':'측정 중 · 비교 가능한 실측 자료 없음');
            if(data.issues.length){
              const items=card('확인이 필요한 업무');
              for(const x of data.issues)line(items,x.title);
            }
          }else if(key==='automation'){
            const box=card('업무 처리시간 · 실측 자료');
            line(box,'수동 작업 '+data.samples.manual+'건 · 자동화 '+data.samples.automated+'건');
            line(box,data.status==='COMPARISON_AVAILABLE'?'관측된 중위수 차이 '+data.observed_difference_ms+'ms':'측정 중');
            if(data.disclaimer)line(box,data.disclaimer);

            // Measurements are created by server timers only. Recovered after reload,
            // never persisted as timing evidence in client-side storage.
            const timerPanel=card('거래명세표 작업시간 실측');
            line(timerPanel,'같은 업무의 수작업·자동화 시간을 서버에서 측정합니다. 측정 종료를 직접 확인해야 합니다.');
            const timerState=t('p','jw-review-muted','실제 서버 측정 상태 조회 중');
            const timerButtons=t('div','jw-review-timing-buttons');
            timerPanel.append(timerState,timerButtons);
            let measuring=false;
            async function renderTimer(){
              const active=await bridge.activeTiming();
              if(token!==epoch)return active;
              timerButtons.replaceChildren();
              if(active){
                timerState.textContent=(active.mode==='manual'?'수작업':'자동화')+
                  ' 측정 진행 중 · 시작 '+new Date(active.started_at).toLocaleString('ko-KR')+
                  ' · 측정 시간은 서버 기준';
                if(active.mode==='manual'){
                  const finish=t('button','jw-review-action-button','수작업 완료 기록');
                  finish.type='button';finish.dataset.action='timing-manual-finish';
                  finish.addEventListener('click',async()=>{
                    if(measuring||token!==epoch)return;
                    if(!window.confirm('실제 수작업을 끝냈습니까? 자기 보고 완료 기록으로 저장됩니다.'))return;
                    measuring=true;finish.disabled=true;
                    try{
                      const done=await bridge.finishTiming(active.id);
                      if(token!==epoch)return;
                      await renderTimer();
                      if(token!==epoch)return;
                      timerState.textContent='수작업 서버 측정 완료 · '+done.elapsed_ms+'ms (사용자 완료 확인)';
                      timerState.setAttribute('role','status');
                    }catch(e){if(token===epoch){timerState.textContent=msg(e);timerState.setAttribute('role','alert')}}
                    finally{measuring=false;finish.disabled=false}
                  });
                  timerButtons.append(finish);
                }else{
                  line(timerPanel,'자동화 측정은 이 화면에서 새 거래명세표를 생성하면 자동으로 완료됩니다. 기존 문서를 재사용하면 실측에서 제외합니다.');
                }
                const cancel=t('button','jw-review-action-button','측정 취소 · 통계 제외');
                cancel.type='button';cancel.dataset.action='timing-cancel';
                cancel.addEventListener('click',async()=>{
                  if(measuring||token!==epoch)return;
                  if(!window.confirm('현재 측정을 취소하고 통계에서 제외하시겠습니까?'))return;
                  measuring=true;cancel.disabled=true;
                  try{await bridge.cancelTiming(active.id);if(token===epoch){await renderTimer();timerState.textContent='측정 취소 · 통계 제외'}}
                  catch(e){if(token===epoch){timerState.textContent=msg(e);timerState.setAttribute('role','alert')}}
                  finally{measuring=false;cancel.disabled=false}
                });timerButtons.append(cancel);
              }else{
                timerState.textContent='진행 중인 측정 없음 · 비교 실측 자료가 없으면 “측정 중”으로 표시';
                for(const mode of ['manual','automated']){
                  const start=t('button','jw-review-action-button',mode==='manual'?'수작업 측정 시작':'자동화 측정 시작');
                  start.type='button';start.dataset.action='timing-start-'+mode;
                  start.addEventListener('click',async()=>{
                    if(measuring||token!==epoch)return;
                    measuring=true;start.disabled=true;
                    try{
                      await bridge.startTiming(mode);
                      // Release the prior action lock BEFORE rendering the next clickable control.
                      measuring=false;
                      if(token===epoch)await renderTimer()
                    }
                    catch(e){if(token===epoch){timerState.textContent=msg(e);timerState.setAttribute('role','alert')}}
                    finally{measuring=false;start.disabled=false}
                  });timerButtons.append(start);
                }
              }
              return active;
            }
            await renderTimer();
            if(token!==epoch)return;
            const orders=await bridge.list('orders');
            if(token!==epoch)return;
            const candidates=orders.filter(r=>r.status==='fulfilled'&&r.review_state!=='pending');
            const controls=card('납품 완료 수주 → 거래명세표 자동 생성');
            line(controls,'확정 수주 데이터를 재사용합니다. 세금계산서 발행이나 입금 처리는 수행하지 않습니다.');
            if(!candidates.length)line(controls,'전환 가능한 수주 자료 없음');
            for(const order of candidates.slice(0,15)){
              const button=t('button','jw-review-action-button',(order.doc_no||'수주')+' · 거래명세표 생성');
              button.type='button';button.dataset.action='statement-from-order';button.dataset.order=order.id;
              const alert=t('p','jw-review-muted','서버가 문서를 확정한 뒤 결과를 다시 조회합니다.');
              button.addEventListener('click',async()=>{
                if(button.disabled||token!==epoch)return;
                if(!window.confirm((order.doc_no||'선택한 수주')+'의 거래명세표를 생성하시겠습니까?'))return;
                button.disabled=true;
                try{
                  const created=await bridge.statementFromOrder(order.id);
                  const verified=await bridge.statementDetail(created.id,order.id);
                  const trace=await bridge.orderTransactionTrace(order.id);
                  if(token!==epoch)return;
                  if(trace.statement_id!==created.id ||
                     trace.order_money.total!==verified.document.money.total)
                    throw new Error('SNAPSHOT_TRACE_MISMATCH');
                  let timingNote='';
                  const running=await bridge.activeTiming();
                  if(token!==epoch)return;
                  if(running&&running.mode==='automated'){
                    if(created.reused){
                      // Reuse is not new automation work and must not inflate savings.
                      await bridge.cancelTiming(running.id);
                      timingNote=' · 기존 문서 재사용: 자동화 실측 제외';
                    }else{
                      const measured=await bridge.finishTiming(running.id,created.id);
                      timingNote=' · 자동화 서버 실측 '+measured.elapsed_ms+'ms';
                    }
                    if(token!==epoch)return;
                    await renderTimer();
                    if(token!==epoch)return;
                  }
                  alert.textContent=(created.reused?'기존 확정 문서 재사용 · ':'새 문서 생성 · ')+
                    verified.doc_no+' · 합계 '+verified.document.money.total.toLocaleString('ko-KR')+
                    '원 · 기록 '+trace.events.length+'건 (내부 거래명세표)'+timingNote;
                  alert.setAttribute('role','status');
                }catch(err){
                  if(token===epoch){alert.textContent=msg(err);alert.setAttribute('role','alert')}
                }finally{button.disabled=false;}
              });
              controls.append(button,alert);
            }
          }else if(key==='security'||key==='team'){
            const box=card('관리자 전용 보안·조직 현황');
            line(box,'활성 세션 '+data.sessions+'건 · 보안 이벤트 '+data.security_events+'건');
            line(box,'MFA 등록 사용자 '+data.mfa_enabled_user_count+'명');
            line(box,data.db_row_level_security_enabled?'DB RLS 활성':'DB RLS 미인증 · 정식 운영 차단');
            line(box,data.security_monitoring_automated?'보안 모니터링 자동화 연결':'보안 모니터링 자동화 미연결');
            for(const x of data.users)line(box,(x.name||'이름 없음')+' · '+(x.role||'권한 없음')+(x.disabled_at?' · 사용 중지':''));
          }else{
            const rows=Array.isArray(data)?data:[];
            if(!rows.length)empty();
            else{
              const box=card('서버 저장 데이터 · '+rows.length+'건');
              for(const x of rows.slice(0,100)){
                let label='';
                if(key==='activity')label=[x.actor_name,x.action,x.entity_type,x.created_at].filter(Boolean).join(' · ');
                else if(key==='messenger')label=[x.other_company,x.status,'안읽음 '+x.unread_count+'건'].filter(Boolean).join(' · ');
                else if(key==='docs'||key==='files')label=[x.kind,x.counterparty,x.document_date,x.gross_amount].filter(v=>v!==null&&v!==undefined).join(' · ');
                else if(key==='inbox')label=[x.filename,x.document_kind,x.status].filter(Boolean).join(' · ');
                line(box,label||'자료 없음');
              }
            }
          }
        }catch(e){
          if(token!==epoch)return;
          const error=t('p','jw-review-failure',msg(e));error.setAttribute('role','alert');
          view.append(error);
          if(!bridge.signedIn)entry('세션이 종료되었습니다.');
        }
        return;
      }
      if(!selected[2]){view.append(t('p','jw-review-unwired','서버 연결 검증 전입니다. 조회·등록·수정·승인 기능을 사용할 수 없습니다.'));return}
      const names=selected[2]==='all'?['customers','quotes','orders','invoices']:[selected[2]];
      try{
        const values=await Promise.all(names.map(async name=>({name,rows:await bridge.list(name)})));
        if(token!==epoch)return;
        for(const section of values){const box=t('section','jw-review-card');box.append(t('h3','jw-review-cardtitle',section.name+' · '+section.rows.length+'건'));
          for(const r of section.rows.slice(0,50)){const row=t('div','jw-review-row');
            for(const value of [r.doc_no,r.name,r.title,r.customer_name,r.status])if(typeof value==='string'||typeof value==='number')row.append(t('span','',value));
            box.append(row)}if(!section.rows.length)box.append(t('p','jw-review-muted','데이터가 없습니다.'));view.append(box)}

        // Mutations are review-only, user-triggered and committed by the server.
        // Every response is tenant-bound by JWOwnerServerBridge.write(), never by browser storage.
        if(['home','partners','deals','money'].includes(key)){
          const actions=t('section','jw-review-card');
          actions.append(t('h3','jw-review-cardtitle','서버 업무 처리 · 검토 모드'));
          function form(title,fields,send){
            const f=t('form','jw-review-action-form');
            f.append(t('h4','jw-review-action-title',title));
            const controls={};
            for(const field of fields){
              const wrap=t('label','jw-review-action-label',field.label);
              const input=field.choices?t('select','jw-review-input'):t('input','jw-review-input');
              input.setAttribute('aria-label',field.label);
              if(field.choices){
                for(const [value,label] of field.choices){
                  const op=t('option','',label);op.value=value;input.append(op);
                }
              }else{
                input.type=field.type||'text';
                if(field.type==='number'){input.min=String(field.min??0);input.step='1';}
                if(field.value)input.value=field.value;
                if(field.maxlength)input.maxLength=field.maxlength;
              }
              input.required=field.required!==false;
              controls[field.name]=input;
              wrap.append(input);f.append(wrap);
            }
            const button=t('button','jw-review-button',title);
            button.type='submit';const alert=t('p','jw-review-muted','서버 응답을 확인한 뒤에만 반영합니다.');
            f.append(button,alert);
            f.addEventListener('submit',async e=>{
              e.preventDefault();if(button.disabled)return;
              button.disabled=true;
              try{
                const vals=Object.fromEntries(Object.entries(controls).map(([name,x])=>[name,x.type==='number'?Number(x.value):x.value]));
                await send(vals);
                if(token===epoch)await open(key);
              }catch(err){
                if(token===epoch){alert.textContent=msg(err);alert.setAttribute('role','alert');}
              }finally{button.disabled=false;}
            });
            actions.append(f);
          }
          function rowset(name){return values.find(x=>x.name===name)?.rows||[];}
          async function fetched(name){
            return selected[2]==='all'||selected[2]===name?rowset(name):await bridge.list(name);
          }
          if(key==='home'||key==='partners'){
            form('거래처 서버 등록',[
              {name:'name',label:'거래처명',maxlength:120},
              {name:'business_number',label:'사업자번호 (선택)',required:false,maxlength:20},
              {name:'contact_name',label:'담당자 (선택)',required:false,maxlength:100}
            ],v=>bridge.write('/api/customers',{...v,email:'',phone:''}));
            if(key==='partners'){
              if(!g.JWOwnerCustomerEdit){
                actions.append(t('p','jw-review-unwired','거래처 수정 검토 모듈이 없습니다.'));
              }else{
                await g.JWOwnerCustomerEdit.render({
                  bridge,view:actions,isCurrent:()=>token===epoch
                });
                if(token!==epoch)return;
              }
            }
          }
          if(key==='home'||key==='deals'){
            const customers=await fetched('customers');
            if(token!==epoch)return;
            if(customers.length){
              form('견적서 서버 생성',[
                {name:'customer_id',label:'거래처',choices:customers.map(r=>[r.id,r.name])},
                {name:'title',label:'견적 제목',maxlength:150},
                {name:'item',label:'품목명',maxlength:150},
                {name:'quantity',label:'수량',type:'number',min:1,value:'1'},
                {name:'unit_price',label:'단가(원)',type:'number',min:0,value:'0'}
              ],v=>bridge.write('/api/quotes',{
                customer_id:v.customer_id,title:v.title,vat_mode:'taxable',
                items:[{name:v.item,quantity:v.quantity,unit_price:v.unit_price}]
              }));
            }
            const quotes=await fetched('quotes');
            for(const r of quotes.slice(0,12)){
              if(!['draft','sent'].includes(r.status))continue;
              const label=r.status==='draft'?'견적 발송':'견적 승인';
              const next=r.status==='draft'?'sent':'accepted';
              const b=t('button','jw-review-action-button',r.doc_no+' · '+label);
              b.type='button';b.onclick=async()=>{
                if(b.disabled||!window.confirm(r.doc_no+' '+label+'하시겠습니까?'))return;
                b.disabled=true;
                try{await bridge.write('/api/quotes/'+r.id+'/status',{status:next});if(token===epoch)await open(key);}
                catch(e){b.disabled=false;const a=t('p','jw-review-failure',msg(e));a.setAttribute('role','alert');actions.append(a)}
              };actions.append(b);
            }
            const accepted=quotes.filter(r=>r.status==='accepted');
            if(accepted.length){
              form('승인 견적에서 수주 생성',[
                {name:'quote_id',label:'승인 견적',choices:accepted.map(r=>[r.id,r.doc_no])},
                {name:'due_date',label:'납기일',type:'date',value:new Date(Date.now()+45*86400000).toISOString().slice(0,10)}
              ],v=>bridge.write('/api/orders/from-quote',v));
            }
          }
          if(key==='home'||key==='money'){
            const orders=await fetched('orders');
            if(token!==epoch)return;
            for(const r of orders.slice(0,12)){
              const next=r.status==='received'?'processing':r.status==='processing'?'fulfilled':null;
              if(!next)continue;
              const label=next==='processing'?'수주 처리 시작':'납품 완료';
              const b=t('button','jw-review-action-button',r.doc_no+' · '+label);
              b.type='button';b.onclick=async()=>{
                if(b.disabled||!window.confirm(r.doc_no+' '+label+' 처리하시겠습니까?'))return;
                b.disabled=true;
                try{await bridge.write('/api/orders/'+r.id+'/status',{status:next});if(token===epoch)await open(key);}
                catch(e){b.disabled=false;const a=t('p','jw-review-failure',msg(e));a.setAttribute('role','alert');actions.append(a)}
              };actions.append(b);
            }
            const fulfilled=orders.filter(r=>r.status==='fulfilled');
            if(fulfilled.length){
              form('납품 완료 수주에서 청구서 생성',[
                {name:'order_id',label:'납품 완료 수주',choices:fulfilled.map(r=>[r.id,r.doc_no])},
                {name:'due_date',label:'입금기한',type:'date',value:new Date(Date.now()+45*86400000).toISOString().slice(0,10)}
              ],v=>bridge.write('/api/invoices/from-order',v));
            }
            const invoices=await fetched('invoices');
            if(token!==epoch)return;
            const unpaid=invoices.filter(r=>typeof r.balance==='number'&&r.balance>0);
            if(unpaid.length){
              form('청구서 입금 기록',[
                {name:'invoice_id',label:'미수 청구서',choices:unpaid.map(r=>[r.id,r.doc_no+' · 잔액 '+r.balance+'원'])},
                {name:'amount',label:'입금액(원)',type:'number',min:1,value:'1'},
                {name:'reference',label:'고유 입금 요청번호',maxlength:100},
                {name:'paid_at',label:'입금일',type:'date',value:new Date().toISOString().slice(0,10)}
              ],v=>bridge.write('/api/invoices/'+v.invoice_id+'/payments',{
                reference:v.reference,amount:v.amount,paid_at:v.paid_at,note:''
              }));
            }
          }
          if(actions.childElementCount>1)view.append(actions);
        }
      }catch(err){if(token!==epoch)return;clear(view);view.append(t('h2','jw-review-title','조회 차단'),t('p','jw-review-failure',msg(err)));if(!bridge.signedIn)entry('세션이 종료되었습니다.')}
    }
    open('home');
  }
  bridge.restore().then(dashboard).catch(()=>entry());
}
g.JWOwnerServerUI={start,routeCount:MENUS.length};
})(window);
