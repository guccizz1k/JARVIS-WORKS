/* JARVIS WORKS v1 — browser client. API is authoritative for money and authorization. */
'use strict';
const state = {csrf:'', user:null, page:'imports', customers:[], quotes:[], orders:[], invoices:[], audit:[], security:null, dashboard:null, importPreview:null, importBatchPreviews:[], importBatchFiles:{}, importAnalytics:null, importQueue:null, evidenceQueue:null, evidencePreview:null, reconciliationQueueV65:null, messengerDirectory:[], messengerThreads:[], messengerMessages:[], messengerThreadId:null, messengerSearch:'', messengerDirectoryMore:null, messengerSearchSeq:0, messengerPollBusy:false, messengerOlder:false, messengerMoreBusy:false};
const $ = (selector, root=document)=>root.querySelector(selector);
const $$ = (selector, root=document)=>Array.from(root.querySelectorAll(selector));
const e = value => String(value===null||value===undefined?'':value).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const requestRef=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
const krw = n => `${new Intl.NumberFormat('ko-KR').format(n||0)}원`;
const fmtDate = n=> n? String(n).slice(0,10):'—';
const kstToday=()=>new Intl.DateTimeFormat('sv-SE',{timeZone:'Asia/Seoul',year:'numeric',month:'2-digit',day:'2-digit'}).format(new Date());
const plusDays=(d)=>{const x = new Date(`${kstToday()}T00:00:00Z`);x.setUTCDate(x.getUTCDate()+d);return x.toISOString().slice(0,10)};
const badge=(type)=>{const cfg={draft:['초안',''],sent:['발송','blue'],accepted:['승인','green'],rejected:['거절','red'],received:['접수',''],processing:['진행 중','blue'],fulfilled:['납품 완료','green'],cancelled:['취소','red'],issued:['청구 완료','blue'],paid:['입금 완료','green'],unpaid:['미수금','orange'],overdue:['연체','red'],pending:['변경 확인 필요','orange'],acknowledged:['변경 승인됨','green'],clean:['일치','green']};const x=cfg[type]||[type,''];return `<span class="badge ${x[1]}">${e(x[0])}</span>`};
let toastTimer;
function toast(message,isError=false){const el=$('#toast');el.textContent=message;el.className=(isError?'error ':'')+'visible';clearTimeout(toastTimer);toastTimer=setTimeout(()=>el.className='',4500)}
async function api(path,method='GET',data){const options={method,headers:{'Accept':'application/json'}};if(!['GET','HEAD'].includes(method)&&path!='/login'&&state.csrf)options.headers['X-CSRF-Token']=state.csrf;if(data!==undefined){options.headers['Content-Type']='application/json';options.body=JSON.stringify(data)}
  let response;try{response=await fetch('/api'+path,options)}catch{throw new Error('서버에 연결하지 못했습니다. 실행 상태를 확인하세요.')}
  let result;try{result=await response.json()}catch{throw new Error('서버 응답을 읽을 수 없습니다')}
  if(!response.ok){if(response.status===401&&path!='/login'){state.csrf='';state.user=null;showLogin()}const msg=Array.isArray(result.detail)?result.detail.map(x=>x.msg).join(', '):(result.detail||'처리에 실패했습니다');throw new Error(msg)}return result;
}
function showLogin(){messengerStopStream();$('#login-view').classList.remove('hidden');$('#app-shell').classList.add('hidden');$('#modal-root').innerHTML='';for(const name of ['otp','recovery_code']){const input=$(`#login-form [name=${name}]`);if(input)input.value=''}}
function showApp(){$('#security-nav').hidden=state.user.role!=='admin';$('#login-view').classList.add('hidden');$('#app-shell').classList.remove('hidden');$('#side-org').textContent=state.user.org_name;$('#user-circle').textContent=state.user.name.slice(0,1);$('#today-label').textContent=`${kstToday()} · KST`}
async function begin(){try{const config=await api('/config');if(config.demo_mode){$('#login-form [name=email]').value='demo@hanbit.example';$('#login-form [name=password]').value='Demo!2026secure'}else{$('.demo-box')?.classList.add('hidden');$('.fineprint')?.classList.add('hidden');$('#login-form [name=email]').value='';$('#login-form [name=password]').value=''}}catch{}try{state.user=await api('/me');state.csrf=state.user.csrf_token;showApp();await navigate('imports')}catch{showLogin()}}
async function loadAll(){const [customers,quotes,orders,invoices,dashboard]=await Promise.all([api('/customers'),api('/quotes'),api('/orders'),api('/invoices'),api('/dashboard')]);Object.assign(state,{customers,quotes,orders,invoices,dashboard})}
const labels={dashboard:'대시보드',customers:'거래처 관리',quotes:'견적 관리',orders:'수주·발주 관리',invoices:'청구·입금 관리',audit:'변경 이력',security:'보안 관제 센터',imports:'문서 업로드 · 자동 처리',messenger:'기업 거래 메신저',automation:'원클릭 문서 작성 · 자동화'};
async function navigate(page){try{if(window.JW_UI_MOTION)await window.JW_UI_MOTION.beforeNavigate(page);messengerStopStream();state.page=page;if(page==='messenger'){[state.messengerDirectoryPage,state.messengerThreads]=await Promise.all([api('/messenger/directory/search?q='+encodeURIComponent(state.messengerSearch)+'&offset=0&limit=30'),api('/messenger/threads')]);state.messengerDirectory=state.messengerDirectoryPage.items;state.messengerDirectoryMore=state.messengerDirectoryPage.next_offset;if(!state.messengerThreads.some(x=>x.id===state.messengerThreadId))state.messengerThreadId=state.messengerThreads.find(x=>x.status==='active')?.id||null;const historyPage=state.messengerThreads.find(x=>x.id===state.messengerThreadId)?.status==='active'?await api('/messenger/threads/'+state.messengerThreadId+'/messages/page?limit=50'):{items:[],has_more:false};state.messengerMessages=historyPage.items;state.messengerOlder=historyPage.has_more}else if(page==='imports'){[state.importAnalytics,state.importQueue,state.evidenceQueue,state.reconciliationQueueV65]=await Promise.all([api('/order-analytics'),api('/imports/queue'),api('/evidence/queue'),api('/evidence/reconciliation/queue')])}else if(page==='security'){if(state.user.role!=='admin')throw new Error('관리자만 접근할 수 있습니다');[state.security,state.mfaStatus]=await Promise.all([api('/security/overview'),api('/security/mfa/status')])}else if(page==='audit')state.audit=await api('/audit');else if(page==='dashboard'){await loadAll();state.automationDraftSummary=await api('/automation/drafts/summary')}else if(page==='automation'){await loadAll();[state.automationSavings,state.automationActive]=await Promise.all([api('/automation/time-savings'),api('/automation/timing/active')]);automationManualRun=state.automationActive?.mode==='manual'?state.automationActive.id:null}else await loadAll();$('#crumb-title').textContent=labels[page];$$('[data-page]').forEach(x=>x.classList.toggle('active',x.dataset.page===page));$('#sidebar').classList.remove('open');const out=$('#main-content');out.innerHTML=({dashboard:dashboardPage,customers:customerPage,quotes:quotePage,orders:orderPage,invoices:invoicePage,audit:auditPage,security:securityPage,imports:importPage,messenger:messengerPage,automation:automationPageV61}[page]||dashboardPage)();out.focus({preventScroll:true});window.scrollTo({top:0,behavior:'instant'});window.JW_UI_MOTION?.afterNavigate(page,out);if(page==='messenger'){
  const list=$('#jw-message-list');if(list){list.scrollTop=list.scrollHeight;messengerMarkReadAtBottom();}messengerStartStream();
 }}catch(err){window.JW_UI_MOTION?.navigationFailed();toast(err.message,true)}}
const title=(name,desc,btn='')=>`<div class="page-head"><div><h1>${e(name)}</h1><p>${e(desc)}</p></div><div class="page-actions">${btn}</div></div>`;
const head=(name,right='')=>`<div class="panel-header"><h2>${e(name)}</h2>${right}</div>`;
const empty=(txt)=>`<div class="empty"><span class="empty-symbol">▢</span><b>아직 ${e(txt)}이(가) 없습니다.</b><p>상단의 추가 버튼으로 시작하세요.</p></div>`;
const listTools=(statuses=[])=>`<div class="list-tools"><label class="list-search-label"><span aria-hidden="true">⌕</span><input id="list-search" type="search" placeholder="현재 목록에서 검색 / 키보드 /" aria-label="현재 목록 검색" autocomplete="off"></label>${statuses.length?`<label class="status-filter-label">상태 <select id="status-filter" aria-label="상태 필터"><option value="">전체</option>${statuses.map(x=>`<option value="${e(x)}">${e(x)}</option>`).join('')}</select></label>`:''}<span class="search-count" id="search-count" aria-live="polite"></span></div>`;
function applyListFilter(){const q=($('#list-search')?.value||'').trim().toLocaleLowerCase('ko-KR');const status=$('#status-filter')?.value||'';const rows=$$('.main-content .panel .table tbody tr');let visible=0;rows.forEach(r=>{const text=r.textContent.toLocaleLowerCase('ko-KR');const ok=text.includes(q)&&(!status||text.includes(status.toLocaleLowerCase('ko-KR')));r.hidden=!ok;if(ok)visible++});const counter=$('#search-count');if(counter)counter.textContent=`${visible} / ${rows.length}건`}
const table=(columns,rows)=>`<div class="table-scroll"><table class="table"><thead><tr>${columns.map(x=>`<th>${e(x)}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table></div>`;
const btn=(action,label,id,kind='ghost')=>`<button class="btn small ${kind}" data-action="${action}" data-id="${e(id)}">${e(label)}</button>`;
const find=(type,id)=>state[type].find(x=>x.id===id);
function dashboardPage(){const d=state.dashboard;
  const cards=[['거래처',d.customers+'곳','등록된 거래 기업','♧'],['견적',d.quotes+'건','생성한 견적서','▤'],['누적 입금액',krw(d.collected),'등록된 실제 입금','✓'],['미수금',krw(d.outstanding),'청구총액 − 입금총액','₩']];
  return title('업무 대시보드','문서 자동 처리 결과와 확인이 필요한 업무를 한눈에 확인하세요.',btn('go-imports','＋ 문서 업로드','','primary'))+`<section class="import-dashboard-cta"><div><strong>파일 하나로 업무를 시작하세요.</strong><p>PDF·엑셀 문서를 읽고 원본 대조·승인 후 관련 거래 기록을 생성합니다.</p><small>현재 자동 등록: 정형 견적서(초안)·발주서·수주서·주문서 · 그 외 문서는 차단</small></div>${btn('go-imports','문서 업로드 · 자동 처리','','primary')}</section>`+
  `<div class="cards">${cards.map(x=>`<div class="card"><span class="card-icon">${x[3]}</span><div class="card-title">${x[0]}</div><div class="number">${x[1]}</div><div class="card-sub">${x[2]}</div></div>`).join('')}</div>
   <div class="flow-strip">${[['01','거래처 등록'],['02','견적 작성·승인'],['03','발주·납품'],['04','청구·입금']].map(x=>`<div class="flow-step"><b>${x[0]}</b>${x[1]}</div>`).join('')}</div>
   <div class="dash-cols"><section class="panel">${head('최근 견적서',btn('go-quotes','전체 보기',''))}${d.recent_quotes.length?table(['견적번호','거래처','금액','상태'],d.recent_quotes.map(x=>`<tr><td><strong>${e(x.doc_no)}</strong></td><td>${e(x.customer_name)}</td><td class="amount">${krw(x.money.total)}</td><td>${badge(x.status)}</td></tr>`).join('')):empty('견적서')}</section>
   <section class="panel">${head('확인할 업무',`<span class="badge ${d.issues.length?'orange':'green'}">${d.issues.length}건</span>`)}<div class="panel-body">${d.issues.length?d.issues.map(x=>`<div class="issue"><div class="issue-sign">!</div><div><h3>${e(x.title)}</h3><small>${e(x.doc_no)}</small></div><div style="margin-left:auto">${btn('go-'+(x.kind==='overdue_invoice'?'invoices':'orders'),'확인',x.id)}</div></div>`).join(''):`<div class="empty" style="padding:27px 12px"><span class="empty-symbol">✓</span><b>지금 확인할 위험 알림이 없습니다.</b></div>`}</div></section></div>
   <section class="panel" style="margin-top:22px"><div class="panel-header"><h2>자동 작성된 업무 문서</h2>${btn('go-automation','원클릭 문서 작성','','primary')}</div><div class="panel-body"><strong>${state.automationDraftSummary?.total??0}건</strong><p class="muted">수주서·납품서·입금요청서 내부 검토용 초안입니다.</p>${(state.automationDraftSummary?.recent||[]).map(doc=>`<div class="jw-v62-result"><span>${e(doc.document_no)}</span>${btn('auto-v62-open','초안 보기',doc.id)}</div>`).join('')||'<p class="muted">자동 작성된 문서가 없습니다.</p>'}</div></section>
   ${evidenceDashboardV64(d.evidence)}
   <div class="notice" style="margin-top:22px">표시된 금액은 실제 DB에 저장된 거래 문서와 입금 기록에서 계산됩니다. <b>송장·세금계산서 공식 발행, 금융기관 입금 조회 기능은 포함되지 않습니다.</b></div>`;
}

// V2.3: Simple business chat; authenticated companies only, no prior conversation acceptance.
const safeDate = value=>e(String(value||'').replace('T',' ').slice(5,16));
function messengerThreadCards(){
 return state.messengerThreads.length?state.messengerThreads.map(x=>`<button type="button" class="jw-thread ${state.messengerThreadId===x.id?'chosen':''}" data-action="messenger-open" data-id="${e(x.id)}"><span class="jw-company-avatar">${e(x.other_company.slice(0,1))}</span><span class="jw-thread-summary"><strong>${e(x.other_company)}</strong><small>기업 대화</small></span>${x.unread_count>0?`<span class="jw-unread" aria-label="읽지 않은 메시지 ${x.unread_count}개">${x.unread_count>99?'99+':x.unread_count}</span>`:''}</button>`).join(''):'<p class="jw-hint">아직 대화가 없습니다. 기업을 검색해 시작하세요.</p>';
}
function messengerCompanyCards(){
 return state.messengerDirectory.map(x=>`<button type="button" class="jw-company-option" data-action="messenger-connect" data-id="${e(x.org_id)}"><span class="jw-company-avatar">${e(x.company_name.slice(0,1))}</span><span>${e(x.company_name)}</span><span class="jw-directory-arrow">›</span></button>`).join('')||'<p class="jw-hint">검색 결과가 없습니다.</p>';
}
function messengerMessageCards(){
 const history=state.messengerOlder?'<div class="jw-older-bar"><button type="button" class="btn small" data-action="messenger-older">이전 대화 더 보기</button></div>':'';
 return history+(state.messengerMessages||[]).map(m=>{
  const attachment=m.attachment;
  const content=attachment?`<div class="jw-attachment">${attachment.mime.startsWith('image/')?`<a target="_blank" rel="noopener noreferrer" href="${e(attachment.url)}"><img class="jw-photo" src="${e(attachment.url)}" alt="${e(attachment.filename)}" loading="lazy"></a>`:''}<a href="${e(attachment.url)}" class="jw-attachment-link" download>${attachment.mime.startsWith('image/')?'사진':'파일'} · ${e(attachment.filename)} (${Math.ceil(attachment.size_bytes/1024)}KB)</a></div>`:`<p>${e(m.body)}</p>`;
  const order=m.kind==='order'?`<div class="jw-document"><strong>발주서 ${e(m.order_snapshot?.doc_no||'')}</strong><span>${krw(m.order_snapshot?.money?.total||0)} · 납기 ${e(m.order_snapshot?.due_date)}</span><span>처리자(입력): ${e(m.actor_name)}</span><span>${m.received_at?'수신 확인: '+e(m.receipt_actor_name):'전송됨 · 거래 승인 아님'}</span>${!m.mine&&!m.received_at?btn('messenger-receipt','수신 확인',m.id,'primary'):''}</div>`:'';
  const actions=m.mine&&!attachment&&m.kind==='text'&&Date.now()-Date.parse(m.created_at)<1800000?btn('messenger-edit','수정',m.id+'|'+m.version):'';
  const history=m.version>1?btn('messenger-history','이력',m.id):'';
  return `<article class="jw-msg ${m.mine?'jw-msg-mine':''}"><div class="jw-msg-head"><strong>${e(m.company_name)}</strong><small>${safeDate(m.created_at)}${m.edited_at?' · 수정됨':''}</small></div>${content}${order}<div class="jw-msg-actions">${actions}${history}</div></article>`;
 }).join('')||(state.messengerOlder?'':'<p class="jw-hint jw-conversation-empty">메시지를 보내 대화를 시작하세요.</p>');
}
function messengerPage(){
 const selected=state.messengerThreads.find(x=>x.id===state.messengerThreadId);
 const composer=selected?`<div class="jw-compose-wrap"><div class="jw-plus-menu" id="jw-plus-menu" hidden><button type="button" data-action="messenger-pick-photo">📷 사진 전송</button><button type="button" data-action="messenger-pick-file">📎 파일 전송</button><button type="button" data-action="messenger-send-order" data-id="${e(selected.id)}">▤ 발주서 전송</button></div><form id="messenger-send-form" class="jw-compose"><button type="button" data-action="messenger-toggle-plus" class="jw-plus" aria-label="첨부 메뉴 열기" aria-expanded="false">+</button><textarea name="content" maxlength="2000" rows="2" required aria-label="메시지 입력" placeholder="메시지를 입력하세요"></textarea><button class="jw-send" type="submit">전송</button></form><input id="jw-photo-file" class="jw-hidden-upload" type="file" accept="image/png,image/jpeg,image/webp"><input id="jw-regular-file" class="jw-hidden-upload" type="file" accept=".pdf,.xlsx,.docx,.txt,.csv,image/png,image/jpeg,image/webp"><small class="jw-message-policy">수정 30분 · 삭제 불가 · 원본 첨부 보존</small></div>`:'<div class="jw-hint jw-no-chat">왼쪽에서 기업을 찾아 선택하세요.</div>';
 return `<div class="jw-simple-header"><h1>기업 메신저</h1><p>가입이 확인된 기업끼리 바로 대화하고 거래 문서를 주고받습니다.</p></div>`+
 `<div class="jw-messenger"><aside class="jw-partners"><div class="jw-company-search"><label for="jw-company-query">기업 검색</label><input id="jw-company-query" type="search" autocomplete="off" value="${e(state.messengerSearch)}" placeholder="회사명을 입력하세요"></div><div id="jw-company-results" class="jw-company-results" tabindex="0" aria-label="가입 기업 검색 결과. 마우스 휠로 더 보기">${messengerCompanyCards()}</div><div class="jw-connections-head">대화 목록</div><div id="jw-thread-list" class="jw-thread-list">${messengerThreadCards()}</div></aside><section class="jw-conversation"><div class="jw-chat-head"><span class="jw-chat-avatar">${e(selected?.other_company?.slice(0,1)||'J')}</span><div><h2>${e(selected?.other_company||'회사를 선택하세요')}</h2><small>${selected?'가입된 기업 · 바로 대화 가능':'검색 또는 스크롤로 기업 선택'}</small></div></div><div id="jw-message-list" class="jw-message-list" role="log" aria-live="polite">${messengerMessageCards()}</div>${composer}</section></div>`+
 `<p class="jw-security-foot">개발 검증용 · 메신저 전송은 계약·거래 승인으로 간주하지 않습니다. 중요 거래는 별도 원본 대조 후 전산 반영됩니다.</p>`;
}
let messengerSearchTimer;
let messengerReadBusy=false;
async function messengerMarkReadAtBottom(){
 const box=$('#jw-message-list'),thread=state.messengerThreadId;
 if(!box||!thread||document.hidden||state.page!=='messenger'||messengerReadBusy)return;
 if(box.scrollHeight-box.scrollTop-box.clientHeight>80)return;
 const messages=state.messengerMessages,last=messages[messages.length-1];
 if(!last||!messages.some(m=>!m.mine))return;
 const candidate=state.messengerThreads.find(x=>x.id===thread);
 if(!candidate||candidate.unread_count<=0)return;
 messengerReadBusy=true;
 try{await api('/messenger/threads/'+thread+'/read','POST',{last_message_id:last.id});
   if(state.messengerThreadId===thread&&state.page==='messenger'){
     candidate.unread_count=0;const list=$('#jw-thread-list');if(list)list.innerHTML=messengerThreadCards();
   }
 }catch{/* Failed read acknowledgment must never clear unread state. */}
 finally{messengerReadBusy=false;}
}
async function messengerSearch(reset=true){
 const seq=++state.messengerSearchSeq,offset=reset?0:state.messengerDirectoryMore;
 if(offset===null||offset===undefined)return;
 const result=await api('/messenger/directory/search?q='+encodeURIComponent(state.messengerSearch)+'&offset='+offset+'&limit=30');
 if(seq!==state.messengerSearchSeq||state.page!=='messenger')return;
 state.messengerDirectory=reset?result.items:[...state.messengerDirectory,...result.items];
 state.messengerDirectoryMore=result.next_offset;
 const el=$('#jw-company-results');if(el)el.innerHTML=messengerCompanyCards();
}
let messengerEventSource=null;
function messengerStopStream(){if(messengerEventSource){messengerEventSource.close();messengerEventSource=null;}}
function messengerStartStream(){
 messengerStopStream();
 // API cookies are HttpOnly. EventSource uses same-origin session cookies only.
 if(!state.messengerThreadId||!window.EventSource||!['https:','http:'].includes(location.protocol))return;
 const tid=state.messengerThreadId;
 const stream=new EventSource('/api/messenger/threads/'+encodeURIComponent(tid)+'/events');
 messengerEventSource=stream;
 let failures=0;
 stream.onopen=()=>{failures=0};
 stream.onerror=()=>{if(++failures>=3&&messengerEventSource===stream)messengerStopStream()}; // fallback polling stays active
 stream.addEventListener('ready',()=>{if(state.messengerThreadId===tid)messengerReceiveUpdates()});
 stream.addEventListener('change',()=>{if(state.messengerThreadId===tid)messengerReceiveUpdates()});
 stream.addEventListener('revoked',()=>{if(messengerEventSource===stream){messengerStopStream();toast('기업 메신저 권한이 변경되었습니다. 새로고침하세요.',true)}});
}
async function messengerLoadOlder(){
 if(state.page!=='messenger'||state.messengerMoreBusy||!state.messengerOlder)return;
 const tid=state.messengerThreadId,first=state.messengerMessages[0]?.id,box=$('#jw-message-list');
 if(!tid||!first||!box)return;
 state.messengerMoreBusy=true;
 const button=box.querySelector('[data-action=messenger-older]');if(button)button.disabled=true;
 const height=box.scrollHeight,top=box.scrollTop;
 try{
  const page=await api('/messenger/threads/'+tid+'/messages/page?before='+encodeURIComponent(first)+'&limit=50');
  if(state.page!=='messenger'||state.messengerThreadId!==tid)return;
  const known=new Set(state.messengerMessages.map(x=>x.id));
  state.messengerMessages=[...page.items.filter(x=>!known.has(x.id)),...state.messengerMessages];
  state.messengerOlder=page.has_more;
  box.innerHTML=messengerMessageCards();
  box.scrollTop=Math.max(0,box.scrollHeight-height+top);
 }catch(err){toast(err.message,true)}finally{state.messengerMoreBusy=false;if(button?.isConnected)button.disabled=false;}
}
async function messengerReceiveUpdates(){
 if(state.page!=='messenger'||document.hidden||state.messengerPollBusy||state.messengerMoreBusy)return;
 state.messengerPollBusy=true;
 const tid=state.messengerThreadId;
 try{
  if(!tid){
   // An organization with zero chats must still discover new incoming threads.
   const threads=await api('/messenger/threads');
   if(state.page!=='messenger'||state.messengerThreadId)return;
   state.messengerThreads=threads;
   const list=$('#jw-thread-list');if(list)list.innerHTML=messengerThreadCards();
   return;
  }
  const current=state.messengerMessages;
  const last=current.at(-1)?.id;
  const base='/messenger/threads/'+tid+'/messages/page';
  // Fresh latest page keeps recent edits, receipts and company names updated.
  const [latest,threads]=await Promise.all([api(base+'?limit=50'),api('/messenger/threads')]);
  let additions=[];
  if(last){
   let cursor=last;
   for(let batch=0;batch<10;batch++){
    const page=await api(base+'?after='+encodeURIComponent(cursor)+'&limit=100');
    additions.push(...page.items);
    if(!page.has_more||!page.next_after)break;
    cursor=page.next_after;
   }
  }else{additions=latest.items;state.messengerOlder=latest.has_more;}
  if(state.page!=='messenger'||state.messengerThreadId!==tid)return;
  const oldFingerprint=JSON.stringify(current.map(m=>[m.id,m.version,m.received_at]));
  const byId=new Map([...latest.items,...additions].map(m=>[m.id,m]));
  const merged=current.map(m=>byId.get(m.id)||m);
  const known=new Set(merged.map(m=>m.id));
  for(const m of additions){if(!known.has(m.id)){merged.push(m);known.add(m.id)}}
  // Only append latest page messages when the thread started empty.
  state.messengerMessages=merged;
  state.messengerThreads=threads;
  const t=$('#jw-thread-list');if(t)t.innerHTML=messengerThreadCards();
  const changed=oldFingerprint!==JSON.stringify(merged.map(m=>[m.id,m.version,m.received_at]));
  if(changed){const box=$('#jw-message-list');if(box){const atBottom=box.scrollHeight-box.scrollTop-box.clientHeight<80;const top=box.scrollTop;box.innerHTML=messengerMessageCards();if(atBottom){box.scrollTop=box.scrollHeight;messengerMarkReadAtBottom()}else box.scrollTop=top;}}
  else messengerMarkReadAtBottom();
 }catch{/* Polling failure: no draft loss; next cycle and SSE reconnect will retry. */}
 finally{state.messengerPollBusy=false;}
}
setInterval(messengerReceiveUpdates,4500); // bounded fallback even without SSE
async function messengerSendAttachment(file){
 if(!file||!state.messengerThreadId)return;
 if(file.size>5*1024*1024)throw new Error('첨부는 최대 5MB입니다');
 const form=new FormData();form.append('file',file,file.name);form.append('request_id',requestRef());
 let response=await fetch('/api/messenger/threads/'+state.messengerThreadId+'/attachments',{method:'POST',headers:{'Accept':'application/json','X-CSRF-Token':state.csrf},body:form});
 const result=await response.json();if(!response.ok)throw new Error(result.detail||'파일 전송 실패');
 await messengerReceiveUpdates();const log=$('#jw-message-list');if(log)log.scrollTop=log.scrollHeight;toast('첨부파일 전송 완료');
}
function customerPage(){const x=state.customers;return title('거래처 관리','기업 정보와 연락처를 한곳에서 확인하세요.',btn('go-imports','문서에서 거래처 자동 등록','','primary')+btn('new-customer','예외 수동 입력',''))+
  `<section class="panel">${head(`전체 거래처 ${x.length}곳`)}${listTools()}${x.length?table(['회사명','사업자번호','담당자','이메일','연락처','작업'],x.map(y=>`<tr><td><strong>${e(y.name)}</strong></td><td>${e(y.business_number)||'—'}</td><td>${e(y.contact_name)||'—'}</td><td>${e(y.email)||'—'}</td><td>${e(y.phone)||'—'}</td><td>${btn('edit-customer','수정',y.id)}</td></tr>`).join('')):empty('거래처')}</section>`}
function quotePage(){const x=state.quotes;return title('견적 관리','금액 자동 계산부터 견적 승인까지 관리합니다.',btn('go-imports','문서 업로드','','primary')+btn('new-quote','예외 수동 작성',''))+
  `<section class="panel">${head(`견적서 ${x.length}건`)}${listTools(['초안','발송','승인','거절'])}${x.length?table(['견적번호 / 제목','거래처','공급가액','합계','상태','작업'],x.map(y=>`<tr><td><strong>${e(y.doc_no)}</strong><div class="muted">${e(y.title)}</div></td><td>${e(y.customer_name)}</td><td>${krw(y.money.subtotal)}</td><td class="amount">${krw(y.money.total)}</td><td>${badge(y.status)}</td><td><div class="row-buttons">${btn('view-quote','상세',y.id)}${y.status==='draft'?btn('edit-quote','수정',y.id):''}${y.status==='accepted'&&!state.orders.some(z=>z.quote_id===y.id)?btn('from-quote','발주 전환',y.id,'primary'):''}</div></td></tr>`).join('')):empty('견적서')}</section>`}
function orderPage(){const x=state.orders;return title('수주·발주 관리','납기, 주문 변경, 견적 대비 불일치를 확인하세요.',btn('go-imports','파일로 자동 발주','','primary'))+
  `<div class="notice">발주는 <b>승인된 견적서</b>에서 생성합니다. 금액이 달라지면 관리자의 변경 확인 후 청구할 수 있습니다.</div><section class="panel">${head(`발주 ${x.length}건`)}${listTools(['접수','진행 중','납품 완료','취소','확인 대기'])}${x.length?table(['발주번호','거래처','합계','납기','진행 상태','검증','작업'],x.map(y=>`<tr><td><strong>${e(y.doc_no)}</strong><div class="muted">${e(y.title)}</div></td><td>${e(y.customer_name||'')}</td><td class="amount">${krw(y.money.total)}</td><td>${fmtDate(y.due_date)}</td><td>${badge(y.status)}</td><td>${badge(y.review_state)}</td><td><div class="row-buttons">${btn('view-order','검증/관리',y.id)}${y.status==='fulfilled'&&!state.invoices.some(z=>z.order_id===y.id)?btn('from-order','청구',y.id,'primary'):''}</div></td></tr>`).join('')):empty('발주')}</section>`}
function invoicePage(){const x=state.invoices;return title('청구·입금 관리','발행한 청구서와 실제 입금 기록을 대조합니다.',btn('go-imports','문서 업로드','','primary')+btn('go-orders','기존 발주로 청구',''))+
  `<div class="notice warning">이 화면은 <b>거래대금 청구 및 입금 기록</b>을 위한 기능입니다. 국세청 전자세금계산서 발행 또는 은행 거래내역 자동 연동이 아닙니다.</div><section class="panel">${head(`청구서 ${x.length}건`)}${listTools(['미수금','입금 완료'])}${x.length?table(['청구번호','거래처','청구 합계','입금 누계','잔액','상태','작업'],x.map(y=>`<tr><td><strong>${e(y.doc_no)}</strong></td><td>${e(y.customer_name||'')}</td><td class="amount">${krw(y.settlement?.adjusted_total??y.money.total)}</td><td>${krw(y.paid)}</td><td class="amount">${krw(y.balance)}</td><td>${badge(y.payment_status)}</td><td><div class="row-buttons">${btn('view-invoice','상세',y.id)}${y.balance>0?btn('pay','입금 기록',y.id,'primary'):''}</div></td></tr>`).join('')):empty('청구서')}</section>`}
function auditPage(){const x=state.audit;const names={create:'생성',edit:'변경',status:'상태 변경',acknowledge:'변경 승인'};return title('변경 이력','누가 언제 거래 정보를 수정했는지 확인합니다.')+
 `<section class="panel">${head('최근 변경 이력 · 최대 30건')}${listTools()}${x.length?table(['일시','담당자','대상','작업','기록'],x.map(y=>`<tr><td class="nowrap">${e(String(y.created_at).replace('T',' ').slice(0,19))}</td><td>${e(y.actor_name)}</td><td>${e(y.entity_type)}</td><td>${e(names[y.action]||y.action)}</td><td><code style="word-break:break-word;font-size:11px">${e(y.detail).slice(0,350)}</code></td></tr>`).join('')):empty('이력')}</section>`}
function securityPage(){const data=state.security;
  const count=data.sessions.length;
  const events={login_success:'로그인 성공',login_failed:'로그인 실패',logout:'로그아웃',session_revoked:'관리자가 세션 종료',staff_disabled:'직원 계정 중지',staff_enabled:'직원 계정 복구'};
  const users=`<div class="staff-list" aria-label="소속 직원과 관리 상태">${data.users.map(u=>`<div class="staff-entry"><div class="staff-entry__main"><strong>${e(u.name)}</strong><div class="staff-entry__meta"><span>${u.role==='admin'?'관리자':'직원'}</span><span>${u.disabled_at?'중지됨':'활성'}</span><span>접속 ${data.sessions.filter(s=>s.user_id===u.id).length}건</span></div></div><div class="staff-entry__actions">${u.id===state.user.id?'본인 계정':btn('staff-status',u.disabled_at?'계정 복구':'접속·계정 중지',u.id+'|'+(u.disabled_at?'enable':'disable'),u.disabled_at?'':'danger')}</div></div>`).join('')}</div>`;
  const sessions=table(['사용자','시작 시각','만료 예정','조치'],data.sessions.map(s=>`<tr><td><strong>${e(s.user_name)}</strong>${s.is_current?' <span class="badge green">현재 세션</span>':''}</td><td>${e(s.created_at||'기존 세션')}</td><td>${e(s.expires_at)}</td><td>${s.is_current?'로그아웃에서 종료':btn('revoke-session','세션 종료',s.id,'danger')}</td></tr>`).join(''));
  const log=table(['발생 시각','사용자','이벤트'],data.events.map(x=>`<tr><td>${e(x.created_at)}</td><td>${e(x.actor_name||'알 수 없음')}</td><td>${e(events[x.event_type]||x.event_type)}</td></tr>`).join(''));
  return title('보안 관제 센터','우리 회사 계정·접속 기록과 보호 상태를 확인하고 대응합니다.',btn('refresh-security','↻ 새로고침','','ghost'))+
    `<div class="notice warning security-notice"><b>운영 보안 미완료</b> · MFA(TOTP) 등록은 가능하나 DB 행 수준 격리·완전한 악성파일 차단·자동 침입 탐지는 아직 없습니다. 운영 인증이 아닙니다.</div>
    <div class="security-kpis"><div class="card"><div class="card-title">등록된 사용자</div><div class="number">${data.users.length}명</div><div class="card-sub">현재 회사 소속</div></div><div class="card"><div class="card-title">활성 접속 세션</div><div class="number">${count}건</div><div class="card-sub">현재 유효한 접속</div></div><div class="card"><div class="card-title">최근 24시간 로그인 실패</div><div class="number">${data.failed_logins_24h}건</div><div class="card-sub">인식된 소속 계정 기준</div></div></div>
    <section class="panel security-checks">${head('보안 조치 상태')}<div class="security-check-list"><div><span class="state-ok">적용</span> 서버 관리 세션·CSRF 보호</div><div><span class="state-ok">부분 적용</span> 사용자별 TOTP MFA — 활성 ${data.mfa_enabled_user_count||0}명 / 일회용 복구 코드 지원</div><div><span class="state-pending">예정</span> DB 수준 기업별 강제 격리</div><div><span class="state-pending">예정</span> 비정상 접근 자동 차단·알림</div></div></section>
    <section class="panel">${head('본인 2단계 인증 및 계정 복구')}<div class="panel-body"><p>인증 앱 등록 시 복구 코드 8개가 한 번만 표시됩니다. 각 코드는 한 번만 사용할 수 있으며 서버에는 해시만 저장됩니다.</p>${state.mfaStatus?.enabled?`<p>2단계 인증 사용 중 · 남은 복구 코드: <b>${state.mfaStatus.recovery_codes_remaining}개</b></p>${btn('mfa-recovery-rotate','복구 코드 재발급','','ghost')}`:(data.mfa_setup_available?btn('mfa-start','인증 앱 등록 시작','','ghost'):'관리자가 암호화 키를 구성하면 본인 인증 앱을 등록할 수 있습니다.')}<p class="muted">복구 코드는 오프라인에 보관하세요. 별도 관리자 계정 초기화 절차는 아직 제공하지 않습니다.</p></div></section>
    <div class="security-panels"><section class="panel">${head('직원 및 관리자 · 비활성화 시 접속 즉시 종료')}${users}</section><section class="panel">${head('접속 세션 · 관리자 종료')}${sessions}</section></div>
    <section class="panel">${head('보안 이벤트 · 최근 50건')}${log}</section>
    <div class="notice">일시가 같은 이벤트는 여러 건일 수 있습니다. 로그인 실패는 기존 회사 계정이 확인된 경우만 집계하며, IP·접속 기기 식별이나 실시간 침입 탐지는 제공하지 않습니다.</div>`;
}
function modal(titleText,body,subtitle='',actions=''){const root=$('#modal-root');root.innerHTML=`<div class="overlay"><section class="modal" role="dialog" aria-modal="true" aria-label="${e(titleText)}"><div class="modal-top"><div><h2>${e(titleText)}</h2><p>${e(subtitle)}</p></div><button class="close-x" data-action="close" aria-label="닫기">×</button></div><div class="modal-body">${body}</div>${actions?`<div class="modal-bottom">${actions}</div>`:''}</section></div>`;$('.overlay').addEventListener('click',ev=>{if(ev.target.classList.contains('overlay'))closeModal()});}
function closeModal(){$('#modal-root').innerHTML=''}
function showRecoveryCodes(codes){
 if(!Array.isArray(codes)||codes.length!==8)throw new Error('복구 코드 응답이 올바르지 않습니다');
 // Recovery codes are displayed only once; never persisted or logged by the browser.
 modal('일회용 복구 코드 보관',`<div class="notice warning"><b>지금 한 번만 표시됩니다.</b> 안전한 오프라인 장소에 보관하세요. 각 코드는 1회만 사용하고 8개 모두 다른 값입니다.</div><div class="details">${codes.map((c,i)=>`<div class="detail-row"><span>${i+1}번</span><code>${e(c)}</code></div>`).join('')}</div><p>보관을 마쳤다면 닫고 다시 로그인하세요.</p>`);
}
const field=(name,label,value='',opts={})=>`<label class="form-field ${opts.wide?'wide':''}">${e(label)}<input name="${e(name)}" type="${e(opts.type||'text')}" value="${e(value)}" ${opts.required?'required':''} ${opts.min!==undefined?`min="${opts.min}"`:''} ${opts.max!==undefined?`max="${opts.max}"`:''} ${opts.step?`step="${opts.step}"`:''} maxlength="${opts.maxlength||200}" /></label>`;
const choose=(name,label,options,value='')=>`<label class="form-field">${e(label)}<select name="${e(name)}" required>${options.map(x=>`<option value="${e(x[0])}" ${x[0]===value?'selected':''}>${e(x[1])}</option>`).join('')}</select></label>`;
const formActions=label=>`<button class="btn ghost" type="button" data-action="close">취소</button><button type="submit" class="btn primary">${e(label)}</button>`;
function customerForm(customer=null){modal(customer?'거래처 수정':'거래처 추가',`<form id="entity-form" data-submit="${customer?'edit-customer':'customer'}" data-id="${e(customer?.id||'')}"><div class="form-grid">${field('name','기업명',customer?.name||'',{required:true})}${field('business_number','사업자등록번호',customer?.business_number||'')}${field('contact_name','담당자',customer?.contact_name||'')}${field('email','이메일',customer?.email||'',{type:'email'})}${field('phone','연락처',customer?.phone||'')}</div><div class="modal-bottom">${formActions(customer?'변경 저장':'거래처 저장')}</div></form>`,'거래처의 기존 견적·발주·청구 기록은 유지됩니다.')}
function lineMarkup(item={}){return `<div class="line-editor" data-line data-source="${e(item.source_quote_item_id||'')}"><div class="line-fields"><div class="field-group"><label>품목 이름</label><input name="item_name" maxlength="150" required value="${e(item.name||'')}" placeholder="품목 또는 서비스" /></div><div class="field-group"><label>수량</label><input name="quantity" type="number" min="1" max="100000" step="1" required value="${e(item.quantity??1)}" /></div><div class="field-group"><label>단가 (원)</label><input name="unit_price" type="number" min="0" max="1000000000" step="1" required value="${e(item.unit_price??0)}" /></div><button type="button" class="remove-line" data-action="remove-line" aria-label="품목 삭제">×</button></div></div>`}
function readLines(form,isOrder=false){const els=$$('[data-line]',form);if(!els.length)throw new Error('품목을 한 개 이상 입력하세요');if(els.length>40)throw new Error('품목은 최대 40개입니다');return els.map(line=>{const name=$('[name=item_name]',line).value.trim(),q=Number($('[name=quantity]',line).value),p=Number($('[name=unit_price]',line).value);if(!name||name.length>150||!Number.isSafeInteger(q)||q<1||q>100000||!Number.isSafeInteger(p)||p<0||p>1e9)throw new Error('품목의 이름·수량·단가를 다시 확인하세요');const out={name,quantity:q,unit_price:p};if(isOrder)out.source_quote_item_id=line.dataset.source||null;return out})}
function renderPreview(){const form=$('#entity-form');if(!form||!$$('[data-line]',form).length)return;try{const lines=readLines(form);const subtotal=lines.reduce((s,x)=>s+x.quantity*x.unit_price,0);const taxable=$('[name=vat_mode]',form)?.value!=='exempt';const vat=taxable?Math.floor((subtotal+5)/10):0;const preview=$('#money-preview');if(preview)preview.innerHTML=`<span>공급가액 ${krw(subtotal)}</span><span>부가세 ${krw(vat)}</span><strong>합계 ${krw(subtotal+vat)}</strong>`}catch{const preview=$('#money-preview');if(preview)preview.innerHTML='<span>품목을 입력하면 금액이 표시됩니다.</span>'}}
function quoteForm(quote=null){if(!state.customers.length){toast('거래처를 먼저 등록하세요',true);navigate('customers');return}
  const lines=quote?quote.items:[{name:'',quantity:1,unit_price:0}];modal(quote?'견적서 수정':'새 견적서 작성',`<form id="entity-form" data-submit="${quote?'edit-quote':'quote'}" data-id="${e(quote?.id||'')}"><div class="form-grid">${choose('customer_id','거래처',state.customers.map(x=>[x.id,x.name]),quote?.customer_id||'')}${choose('vat_mode','부가세', [['taxable','과세 · 공급가액의 10%'],['exempt','면세 · 부가세 없음']],quote?.vat_mode||'taxable')}${field('title','견적 제목',quote?.title||'',{wide:true,required:true})}</div><h3 class="section-title">견적 품목</h3><div id="line-container">${lines.map(lineMarkup).join('')}</div><button class="btn small ghost" type="button" data-action="add-line">＋ 품목 추가</button><div id="money-preview" class="preview-money" style="margin-top:15px"></div><div class="modal-bottom">${formActions(quote?'변경 저장':'견적서 저장')}</div></form>`,'정수 원화 기준 · 수량 × 단가 후 부가세 합계 반올림');renderPreview()}
const info=(label,value)=>`<div class="detail-row"><span>${e(label)}</span><strong>${value}</strong></div>`;
const moneyDetail=x=>`<div class="details">${info('공급가액',krw(x.money.subtotal))}${info('부가세',krw(x.money.vat))}${info('청구/거래 합계',krw(x.money.total))}</div>`;
const itemDetail=x=>table(['품목','수량','단가','합계'],x.items.map(y=>`<tr><td><strong>${e(y.name)}</strong></td><td>${y.quantity}</td><td>${krw(y.unit_price)}</td><td class="amount">${krw(y.quantity*y.unit_price)}</td></tr>`).join(''));
function viewQuote(id){const x=find('quotes',id);if(!x)return;const customer=state.customers.find(c=>c.id===x.customer_id);let actions=`${btn('print-quote','인쇄 · PDF 저장',id)}`;
  if(x.status==='draft')actions+=btn('status-quote','발송 처리',`${id}|sent`,'primary')+btn('edit-quote','초안 수정',id);
  if(x.status==='sent')actions+=btn('status-quote','승인 처리',`${id}|accepted`,'primary')+btn('status-quote','거절 처리',`${id}|rejected`,'danger');
  if(x.status==='accepted'&&!state.orders.some(y=>y.quote_id===id))actions+=btn('from-quote','발주로 전환',id,'primary');
  modal('견적서 상세',`<div class="details">${info('견적번호',e(x.doc_no))}${info('거래처',e(x.customer_name_snapshot||customer?.name||''))}${info('견적 제목',e(x.title))}${info('상태',badge(x.status))}</div><h3 class="section-title">품목 내역</h3>${itemDetail(x)}<hr class="divider">${moneyDetail(x)}`,'상태가 발송된 견적은 금액을 수정할 수 없습니다.',actions)}
function fromQuote(id){const quote=find('quotes',id);if(!quote)return;modal('견적 → 발주 전환',`<form id="entity-form" data-submit="order" data-id="${e(id)}"><div class="notice">${e(quote.doc_no)} / ${krw(quote.money.total)}<br>견적 승인 내용이 발주에 복사됩니다.</div>${field('due_date','납품 예정일',plusDays(14),{type:'date',required:true})}<div class="modal-bottom">${formActions('발주 생성')}</div></form>`,'한 견적서에서는 발주를 한 건만 생성할 수 있습니다.')}
function orderForm(x){modal('발주 수정',`<form id="entity-form" data-submit="edit-order" data-id="${e(x.id)}"><div class="notice warning">품목 변경 시 견적과의 차이를 자동 검출합니다. 차이가 있으면 관리자가 확인해야 청구할 수 있습니다.</div>${field('due_date','납기 예정일',x.due_date,{type:'date',required:true})}<h3 class="section-title">발주 품목</h3><div id="line-container">${x.items.map(lineMarkup).join('')}</div><button type="button" data-action="add-line" class="btn ghost small">＋ 품목 추가</button><div class="form-grid" style="margin-top:16px">${field('change_reason','변경 사유 (최소 5자)','',{wide:true,required:true})}</div><div id="money-preview" class="preview-money" style="margin-top:15px"></div><div class="modal-bottom">${formActions('변경 저장·검증')}</div></form>`,'원본 견적과 대조하여 검토 상태를 갱신합니다.');renderPreview()}
const fieldNames={missing:'품목 누락',extra:'추가 품목',name:'품목명',quantity:'수량',unit_price:'단가',vat_mode:'부가세 유형'};
function diffBox(diffs,label){return `<h3 class="section-title">${e(label)}</h3>${diffs.length?`<div class="diff-list">${diffs.map(x=>`<div class="diff"><strong>${e(x.item)} · ${e(fieldNames[x.field]||x.field)}</strong><span>원본: ${e(x.expected)} → 현재: ${e(x.actual)}</span></div>`).join('')}</div>`:'<div class="notice">✓ 문서 간 품목 및 단가가 일치합니다.</div>'}`}
async function viewOrder(id){const x=find('orders',id);if(!x)return;const d=await api(`/reconciliation/${encodeURIComponent(id)}`);const actions=[];
 if(['received','processing'].includes(x.status)&&!d.has_invoice)actions.push(btn('edit-order','발주 수정',id));
 if(x.review_state==='pending'&&state.user.role==='admin')actions.push(btn('approve-order','변경 확인 승인',id,'primary'));
 if(x.status==='received')actions.push(btn('status-order','업무 시작',`${id}|processing`,'primary'));
 if(x.status==='processing')actions.push(btn('status-order','납품 완료',`${id}|fulfilled`,'primary'));
 if(x.status==='fulfilled'&&!d.has_invoice)actions.push(btn('from-order','청구서 발행',id,'primary'));
 if(['received','processing'].includes(x.status)&&!d.has_invoice)actions.push(btn('status-order','발주 취소',`${id}|cancelled`,'danger'));
 modal('발주 및 문서 대조',`<div class="details">${info('발주번호',e(x.doc_no))}${info('원본 견적',e(find('quotes',x.quote_id)?.doc_no||''))}${info('납기',e(x.due_date))}${info('진행 상태',badge(x.status))}${info('변경 검증',badge(x.review_state))}</div><h3 class="section-title">품목 내역</h3>${itemDetail(x)}<hr class="divider">${moneyDetail(x)}${diffBox(d.quote_to_order,'견적 → 발주 차이')}${d.has_invoice?diffBox(d.order_to_invoice,'발주 → 청구 차이'):''}`,'원본 문서와 변경 데이터를 함께 검토하세요.',actions.join(''));
}
function fromOrder(id){const x=find('orders',id);if(!x)return;modal('발주 → 청구서 발행',`<form id="entity-form" data-submit="invoice" data-id="${e(id)}"><div class="notice">${e(x.doc_no)} / 청구 합계 ${krw(x.money.total)}<br>이 청구서는 공식 전자세금계산서가 아닙니다.</div>${field('due_date','입금 기한',plusDays(30),{type:'date',required:true})}<div class="modal-bottom">${formActions('청구서 생성')}</div></form>`,'발주당 청구서 한 건 · 납품 완료 발주만 청구 가능')}
async function viewInvoice(id){const x=find('invoices',id);if(!x)return;
 const payments=await api(`/invoices/${encodeURIComponent(id)}/payments`);
 const actions=(x.balance>0?btn('pay','입금 기록',id,'primary'):'')+`<button class="btn small ghost" data-v69-open="${e(id)}">반품·할인·운임</button>`;
 const history=payments.length?table(['입금일','금액','메모','상태','작업'],payments.map(p=>`<tr><td>${e(p.paid_at)}</td><td class="amount">${krw(p.amount)}</td><td>${e(p.note||'—')}</td><td>${p.reversed_at?badge('cancelled'):badge('paid')}</td><td>${!p.reversed_at&&state.user.role==='admin'?btn('reverse-payment','기록 취소',id+'|'+p.id,'danger'):'—'}</td></tr>`).join('')):'<p class="muted">아직 기록된 입금이 없습니다.</p>';
 modal('청구서 상세',`<div class="details">${info('청구번호',e(x.doc_no))}${info('입금 기한',e(x.due_date))}${info('입금 상태',badge(x.payment_status))}</div><h3 class="section-title">청구 품목</h3>${itemDetail(x)}<hr class="divider">${moneyDetail(x)}<hr class="divider"><div class="details">${info('입금 누계',krw(x.paid))}${info('남은 잔액',krw(x.balance))}${x.settlement?.approved_adjustments?info('조정 후 청구 합계',krw(x.settlement.adjusted_total)):''}</div><h3 class="section-title">입금 이력 (${payments.length}건)</h3>${history}`,'취소한 입금도 삭제하지 않고 이력에 보존합니다.',actions)}
function paymentForm(id){const x=find('invoices',id);if(!x)return;modal('입금 기록',`<form id="entity-form" data-submit="payment" data-id="${e(id)}" data-reference="${e(requestRef())}"><div class="notice">현재 잔액 <b>${krw(x.balance)}</b><br>입금 확인 후 기록하세요. 잘못 입력한 기록은 관리자가 감사 이력을 남기며 취소할 수 있습니다.</div><div class="form-grid">${field('amount','입금 금액 (원)',x.balance,{type:'number',required:true,min:1,step:'1'})}${field('paid_at','실제 입금 날짜',kstToday(),{type:'date',required:true})}${field('note','입금 메모','',{wide:true})}</div><div class="modal-bottom">${formActions('입금 확정 기록')}</div></form>`,'잔액 초과 입금과 미래 날짜 입금은 차단됩니다.')}
function printQuote(id){const q=find('quotes',id);if(!q)return;const company=state.customers.find(c=>c.id===q.customer_id);
 const win=window.open('','_blank');if(!win){toast('팝업이 차단되었습니다. 팝업 허용 후 다시 시도하세요',true);return}
 const rows=q.items.map(x=>`<tr><td>${e(x.name)}</td><td>${x.quantity}</td><td>${krw(x.unit_price)}</td><td>${krw(x.quantity*x.unit_price)}</td></tr>`).join('');
 win.document.open();win.document.write(`<!doctype html><html lang="ko"><head><meta charset="utf-8"><title>${e(q.doc_no)} 견적서</title><style>body{font:14px sans-serif;max-width:800px;margin:45px auto;color:#203243}h1{font-size:32px}p{line-height:1.8}table{width:100%;border-collapse:collapse;margin:30px 0}th,td{padding:13px;border-bottom:1px solid #dce3e8;text-align:left}th{background:#f3f6f8}.totals{text-align:right;font-weight:700;font-size:19px}@media print{button{display:none}}</style></head><body><h1>견 적 서</h1><p>번호: ${e(q.doc_no)}<br>수신: ${e(q.customer_name_snapshot||company?.name||'')}<br>제목: ${e(q.title)}<br>작성일: ${e(fmtDate(q.quote_date||q.created_at))}<br>상태: ${e(q.status)}</p><table><thead><tr><th>품목</th><th>수량</th><th>단가 (원)</th><th>합계 (원)</th></tr></thead><tbody>${rows}</tbody></table><p class="totals">공급가액: ${krw(q.money.subtotal)}<br>부가세: ${krw(q.money.vat)}<br>합계: ${krw(q.money.total)}</p><p>JARVIS WORKS에서 작성한 거래 견적서</p><button id="print-document">인쇄 · PDF 저장</button></body></html>`);win.document.close();win.document.getElementById('print-document')?.addEventListener('click',()=>win.print());}
async function handleAction(action,id){if(action.startsWith('auto-'))return handleAutomationV61(action,id);if(action==='messenger-older')return messengerLoadOlder();if(action==='messenger-refresh')return navigate('messenger');
 if(action==='messenger-toggle-plus'){const menu=$('#jw-plus-menu');if(!menu)return;menu.hidden=!menu.hidden;const b=$('[data-action=messenger-toggle-plus]');if(b)b.setAttribute('aria-expanded',String(!menu.hidden));return}
 if(action==='messenger-pick-photo'){$('#jw-photo-file')?.click();return}
 if(action==='messenger-pick-file'){$('#jw-regular-file')?.click();return}
 if(action==='messenger-connect'){const x=await api('/messenger/threads','POST',{recipient_org_id:id});state.messengerThreadId=x.id;await navigate('messenger');return}
 if(action==='messenger-open'){state.messengerThreadId=id;return navigate('messenger')}
 
 if(action==='messenger-edit'){
    const [mid,ver]=id.split('|'),m=state.messengerMessages.find(x=>x.id===mid);
    if(!m)return;const edited=prompt('30분 이내 수정 가능 · 이전 메시지는 보존됩니다.',m.body);if(edited===null)return;
    await api('/messenger/messages/'+mid,'PATCH',{content:edited,expected_version:Number(ver)});return navigate('messenger');
 }
 if(action==='messenger-history'){const history=await api('/messenger/messages/'+id+'/history');modal('메시지 수정 이력',history.length?history.map(x=>`<div class="notice"><strong>${e(x.version)}차 수정 · ${e(x.edited_at)}</strong><p>수정 전: ${e(x.previous_body)}</p><p>수정 후: ${e(x.new_body)}</p></div>`).join(''):'<div class="notice">수정 이력이 없습니다.</div>');return}
 if(action==='messenger-send-order'){
    const x=state.messengerThreads.find(t=>t.id===id);const available=await api('/orders');state.orders=available;
    modal('발주서 전송',`<div class="notice warning">${e(x?.other_company||'')}로 전송할 발주서를 선택하세요. 수신 기업 사업자번호와 발주서 거래처 사업자번호가 일치해야 하며, 송신은 계약 승인으로 간주하지 않습니다.</div><form id="messenger-order-form" data-thread="${e(id)}"><label>발주서<select name="order_id" required>${available.map(o=>`<option value="${e(o.id)}">${e(o.doc_no)} · ${e(o.customer_name_snapshot)} · ${krw(o.money.total)}</option>`).join('')}</select></label>${field('actor_name','실제 처리자 이름 (본인 입력)','',{required:true,maxlength:80})}<div class="modal-bottom">${formActions('검토 후 발주서 전송')}</div></form>`);return;
 }
 if(action==='staff-status'){
   const [uid,operation]=id.split('|');if(!['disable','enable'].includes(operation))throw new Error('알 수 없는 계정 조치');
   const subject=state.security?.users?.find(x=>x.id===uid);if(!subject)throw new Error('대상 직원이 없습니다');
   const verb=operation==='disable'?'중지':'복구';
   modal('직원 계정 '+verb,`<div class="notice warning">${e(subject.name)} 계정을 ${verb}합니다. 중지하면 모든 기존 접속 세션이 즉시 무효화되며, 복구 후에도 다시 로그인해야 합니다. 과거 업무 기록은 보존됩니다.</div><form id="staff-status-form" data-target="${e(uid)}" data-operation="${e(operation)}"><label>관리자 현재 비밀번호<input name="admin_password" type="password" autocomplete="current-password" required></label><div class="modal-bottom"><button type="submit" class="btn primary">계정 ${verb} 확정</button></div></form>`);
   return;
 }
 if(action==='messenger-receipt'){
   const name=prompt('발주서 수신을 확인한 처리자 이름을 입력하세요. 계약 승인이나 발주 자동 등록은 수행하지 않습니다.');if(!name)return;
   await api('/messenger/messages/'+id+'/receipt','POST',{actor_name:name});return navigate('messenger');
 }
 if(action==='close'){closeModal();return}if(action==='refresh-security')return navigate('security');if(action==='revoke-session'){if(!confirm('이 직원의 접속 세션을 종료할까요? 사용 중인 업무가 중단될 수 있습니다.'))return;await api('/security/sessions/'+encodeURIComponent(id)+'/revoke','POST',{});toast('접속 세션을 종료했습니다');return navigate('security')}if(action==='new-customer')return customerForm();if(action==='open-import-source'){if(!state.importLocalFile)throw new Error('원본 파일이 없습니다. 다시 업로드하세요');if(state.importSourceUrl)URL.revokeObjectURL(state.importSourceUrl);state.importSourceUrl=URL.createObjectURL(state.importLocalFile);const opened=window.open(state.importSourceUrl,'_blank','noopener,noreferrer');if(!opened)toast('브라우저에서 새 창이 차단되었다면 업로드한 원본 파일을 직접 열어 비교하세요');return;}if(action==='mfa-recovery-rotate'){
    modal('MFA 복구 코드 재발급',`<div class="notice warning">기존 복구 코드 8개는 모두 폐기되고 모든 접속 세션이 종료됩니다. 현재 비밀번호와 새 인증 앱 코드 또는 기존 복구 코드가 필요합니다.</div><form id="mfa-rotate-form">${field('password','현재 비밀번호','',{required:true,type:'password'})}${field('otp','인증 앱 6자리 코드 (복구 코드 사용 시 비움)','',{maxlength:6})}${field('recovery_code','복구 코드 32자리 (인증 앱 코드 사용 시 비움)','',{maxlength:32,type:'password'})}<div class="modal-bottom">${formActions('복구 코드 재발급')}</div></form>`);
    return;
  }
  if(action==='mfa-start'){
    const password=prompt('현재 로그인 비밀번호를 입력하세요. 인증 앱 등록에만 사용하며 저장하지 않습니다.');
    if(password===null)return;
    const setup=await api('/security/mfa/start','POST',{password});
    modal('인증 앱 등록',`<div class="notice warning">비밀 키는 한 번만 표시됩니다. 절대 제3자에게 전달하지 마세요.</div><p>인증 앱에 아래 키를 등록한 뒤 6자리 코드를 입력하세요.</p><code>${e(setup.secret)}</code><form id="mfa-confirm-form">${field('otp','인증 앱 6자리 코드','',{required:true,maxlength:6})}<div class="modal-bottom">${formActions('2단계 인증 활성화')}</div></form>`);
    return;
  }
  if(action==='evidence-v64-open'){const preview=await api('/evidence/preview/'+encodeURIComponent(id));state.evidencePreview=preview;return navigate('imports')}
  if(action==='import-batch-open'){const p=(state.importBatchPreviews||[]).find(x=>x.id===id);if(!p)throw new Error('검토 문서를 다시 불러오세요');state.importPreview=p;state.importLocalFile=state.importBatchFiles?.[id]||null;return navigate('imports')}if(action==='confirm-import')return approveImportedOrder();if(action==='go-imported-order'){closeModal();await navigate('orders');return viewOrder(id)}if(action==='go-imported-quote'){closeModal();await navigate('quotes');return viewQuote(id)}if(action==='edit-customer')return customerForm(find('customers',id));if(action==='new-quote')return quoteForm();if(action==='edit-quote'){const q=find('quotes',id);if(q)return quoteForm(q)}if(action==='view-quote')return viewQuote(id);if(action==='view-order')return viewOrder(id);if(action==='view-invoice')return viewInvoice(id);if(action==='edit-order'){const x=find('orders',id);if(x)return orderForm(x)}if(action==='from-quote')return fromQuote(id);if(action==='from-order')return fromOrder(id);if(action==='pay')return paymentForm(id);if(action==='print-quote')return printQuote(id);
 if(action==='reverse-payment'){const [invoiceId,paymentId]=id.split('|');if(!confirm('선택한 입금 기록을 취소하고 미수금에 다시 반영하시겠습니까?\n이미 기록된 정보는 감사 이력에 남습니다.'))return;await api(`/invoices/${encodeURIComponent(invoiceId)}/payments/${encodeURIComponent(paymentId)}/reverse`,'POST',{});closeModal();toast('입금 기록을 취소했습니다');await navigate(state.page);return}

 if(action==='add-line'){const box=$('#line-container');if($$('[data-line]',box).length>=40){toast('품목은 최대 40개입니다',true);return}box.insertAdjacentHTML('beforeend',lineMarkup());renderPreview();return}
 if(action==='remove-line'){const line=event.target.closest('[data-line]');if(line){line.remove();renderPreview()}return}
 if(action.startsWith('go-'))return navigate(action.slice(3));
 if(action==='status-quote'){const [qid,next]=id.split('|');if(!confirm(`견적을 '${{sent:'발송',accepted:'승인',rejected:'거절'}[next]}' 상태로 변경할까요?`))return;await api(`/quotes/${encodeURIComponent(qid)}/status`,'POST',{status:next})}
 else if(action==='status-order'){const [oid,next]=id.split('|');if(!confirm(`발주 상태를 '${{processing:'진행 중',fulfilled:'납품 완료',cancelled:'취소'}[next]}'로 변경할까요?`))return;await api(`/orders/${encodeURIComponent(oid)}/status`,'POST',{status:next})}
 else if(action==='approve-order'){if(!confirm('견적과 달라진 발주 품목을 확인하고 변경을 승인합니까?'))return;await api(`/orders/${encodeURIComponent(id)}/acknowledge`,'POST',{})}
 else return;closeModal();toast('변경 사항을 저장했습니다');await navigate(state.page);
}
function safePaymentAmount(value){if(!/^[0-9]+$/.test(value)||!Number.isSafeInteger(Number(value))||Number(value)<1)throw new Error('입금액은 1원 이상의 정확한 정수로 입력하세요');return Number(value)}
async function submitForm(form){const data=Object.fromEntries(new FormData(form));let result;
 switch(form.dataset.submit){case 'customer':result=await api('/customers','POST',data);break;
 case 'edit-customer':result=await api(`/customers/${encodeURIComponent(form.dataset.id)}`,'PUT',data);break;
 case 'quote': result=await api('/quotes','POST',{customer_id:data.customer_id,title:data.title,vat_mode:data.vat_mode,items:readLines(form)});break;
 case 'edit-quote':result=await api(`/quotes/${encodeURIComponent(form.dataset.id)}`,'PUT',{customer_id:data.customer_id,title:data.title,vat_mode:data.vat_mode,items:readLines(form)});break;
 case 'order':result=await api('/orders/from-quote','POST',{quote_id:form.dataset.id,due_date:data.due_date});break;
 case 'edit-order':result=await api(`/orders/${encodeURIComponent(form.dataset.id)}`,'PUT',{items:readLines(form,true),change_reason:data.change_reason,due_date:data.due_date});break;
 case 'invoice':result=await api('/invoices/from-order','POST',{order_id:form.dataset.id,due_date:data.due_date});break;
 case 'payment':result=await api(`/invoices/${encodeURIComponent(form.dataset.id)}/payments`,'POST',{amount:safePaymentAmount(data.amount),paid_at:data.paid_at,note:data.note,reference:form.dataset.reference});break;
 default:throw new Error('알 수 없는 처리 요청입니다');}
 closeModal();toast('저장되었습니다 · '+(result.doc_no||result.name||''));await navigate(state.page);
}

function importPage(){const a=state.importAnalytics||{totals:{order_count:0,ordered_quantity:0,subtotal:0,vat:0,total:0},companies:[]};const t=a.totals;
const info=`<div class="cards import-kpis">${[['수주 건수',t.order_count+'건'],['수주 수량 합계',t.ordered_quantity+(a.mixed_units?' (단위 혼합)':'')] ,['공급가액',krw(t.subtotal)],['수주 총액',krw(t.total)]].map(x=>`<div class="card"><div class="card-title">${e(x[0])}</div><div class="number">${e(x[1])}</div></div>`).join('')}</div>`;
const p=state.importPreview;
const incomplete=Boolean(p?.document?.missing_fields?.length);const quoteImport=p?.document?.record_type==='quote';const dateName=quoteImport?'견적일':'수주일';const recordName=quoteImport?'견적 초안':'발주서';
const supplementable=p?[...new Set([...(p.document.missing_fields||[]),...(p.document.user_filled_fields||[])])]:[];
const supplementForm=supplementable.length?`<form id="import-supplement-form" class="import-supplement"><div class="notice warning">원본에 누락된 필수 정보입니다. 입력한 항목은 ‘사용자 보완’으로 기록됩니다. 추출된 금액·품목은 수정할 수 없습니다.</div><div class="import-supplement-grid">${supplementable.map(key=>{const name={company:'거래처명',ordered_at:'수주일',due_date:'납품예정일',quote_date:'견적일'}[key];const val=p.document[key]||'';return `<label>${e(name)} <input name="${e(key)}" ${key==='company'?'type="text" maxlength="120"':'type="date"'} value="${e(val)}" required></label>`}).join('')}</div><button class="btn primary" type="submit">누락 정보 저장·재검증</button></form>`:'';
const multi=(state.importBatchPreviews||[]).length?`<section class="panel"><div class="panel-header"><h2>일괄 분석 결과 · ${state.importBatchPreviews.length}건</h2></div><div class="panel-body"><p class="muted">각 문서의 원본을 확인한 뒤 개별 승인하세요. 현재는 검토함에만 저장되며 매출·발주는 생성되지 않습니다.</p>${state.importBatchPreviews.map((item,i)=>`<div class="jw-v62-result"><span>${e(item.document.filename)} · ${e(item.document.document_kind)}</span>${btn('import-batch-open','검토하기',item.id,item.id===p?.id?'primary':'ghost')}</div>`).join('')}</div></section>`:'';
const preview=p?`<section class="panel import-review"><div class="panel-header"><h2>추출 결과 검토 — 승인 전 최종 확인</h2><span class="badge orange">${incomplete?'정보 보완 필요':'승인 대기'}</span></div><div class="panel-body"><div class="notice warning">원본 파일과 회사명·문서 날짜·품목·수량·단가·금액 및 추가 필드를 반드시 비교하세요. 확실하지 않다면 생성하지 말고 수정한 파일을 다시 업로드하세요.</div><div class="import-source-tools">${btn('open-import-source','원본 파일 다시 열기','','')}<span class="muted">PDF는 새 창, 엑셀은 내려받아 원본 셀과 비교하세요. 원본은 서버에 별도 저장되지 않습니다.</span></div>${supplementForm}<div class="details import-meta">${[['파일',p.document.filename],['원본 문서 유형',p.document.document_kind],['거래처',p.document.company],['사업자번호',p.document.business_number||'미기재'],[dateName,quoteImport?p.document.quote_date:p.document.ordered_at],...(quoteImport?[]:[['납기일',p.document.due_date]]),['과세 구분',p.document.vat_mode==='taxable'?'과세 10%':'면세'],['거래처 매칭',p.customer_status==='existing'?'기존 거래처 연결':'신규 거래처 생성 예정']].map(x=>`<div class="detail-row"><span>${e(x[0])}</span><strong>${e(x[1])}</strong></div>`).join('')}</div><h3 class="section-title">추가 문서 항목</h3>${Object.keys(p.document.additional_fields||{}).length?`<div class="details import-meta">${Object.entries(p.document.additional_fields).map(([key,value])=>`<div class="detail-row"><span>${e(({reference_number:quoteImport?'견적번호':'발주번호',project_name:'프로젝트명',delivery_address:'납품장소',buyer_contact:'담당자',payment_terms:'결제조건',remarks:'특기사항',valid_until:'견적유효일',expected_delivery_date:'견적상 납품예정일'})[key]||key)}</span><strong>${e(value)}</strong></div>`).join('')}</div>`:'<p class="muted">추가 문서 항목 없음</p>'}<h3 class="section-title">추출 품목 ${p.document.item_count}개</h3>${table(['품목 / 품목코드','규격','수량','단위','단가','금액'],p.document.items.map(x=>`<tr><td>${e(x.name)}${x.sku?'<br><small>'+e(x.sku)+'</small>':''}</td><td>${e(x.spec||'—')}</td><td>${e(x.quantity)}</td><td>${e(x.unit||'미기재')}</td><td>${krw(x.unit_price)}</td><td class="amount">${krw(x.line_total)}</td></tr>`).join(''))}<p class="muted">단위별 수량: ${e(Object.entries(p.document.quantity_by_unit||{}).map(([unit,qty])=>unit+' '+qty).join(' / '))}</p><div class="preview-money">공급가액 ${krw(p.document.money.subtotal)} · 부가세 ${krw(p.document.money.vat)}<strong>총액 ${krw(p.document.money.total)}</strong></div><label class="import-confirm"><input id="import-approval" type="checkbox"> 원본과 모든 필수 항목을 직접 대조했고 위 내용으로 ${recordName}를 생성하는 데 동의합니다.</label><div class="import-actions">${incomplete?'필수 정보를 보완해야 승인할 수 있습니다.':btn('confirm-import',quoteImport?'확인 후 견적 초안 생성':'확인 후 발주 생성','','primary')}</div></div></section>`:'';
const queue=state.importQueue||{pending:[],confirmed:[],pending_count:0,confirmed_count:0};
const queueHtml=`<section class="panel import-queue">${head('검토 대기 문서',`<span class="badge ${queue.pending_count?'orange':'green'}">${queue.pending_count}건</span>`)}<div class="panel-body">${queue.pending_count?`<div class="notice warning">확인 전 문서는 업무 기록에 반영되지 않습니다. 원본을 보관하지 않으므로 이전에 올린 파일은 다시 업로드해 대조·승인하세요.</div>${table(['파일명','인식 유형','회사','대기 사유','업로드 시각'],queue.pending.map(x=>`<tr><td>${e(x.filename)}</td><td>${e(x.document_kind)}</td><td>${e(x.company||'미확정')}</td><td>${e(x.missing_fields.length?x.missing_fields.join(', '):'원본 대조·승인 대기')}</td><td>${e(x.created_at.slice(0,16).replace('T',' '))}</td></tr>`).join(''))}`:'<p class="muted">검토 대기 문서가 없습니다.</p>'}</div></section>`;
return title('문서 업로드 · 자동 처리','원본 인식 → 자동 검증 → 사용자 확인 → 해당 업무 반영')+`<section class="import-hero"><div class="import-hero-copy"><span class="import-eyebrow">JARVIS AUTOMATION · WORKSPACE</span><h2>파일만 올리고, 결과만 확인하세요.</h2><p>회사·품목·수량·문서 날짜·단가·금액을 자동 추출하고 불일치와 누락을 먼저 알려드립니다.</p><div class="import-workflow"><span>① 업로드</span><span>② 분석·대조</span><span>③ 최종 확인</span><span>④ 안전한 등록</span></div></div><div class="import-hero-side"><span class="badge green">자동 등록 지원</span><b>견적서 · 발주서 · 수주서 · 주문서</b><small>검색 가능한 PDF / 정형 XLSX</small><span class="badge orange">후속 자동화 개발 대상</span><b>납품 · 청구 · 입금 증빙</b><small>현재는 자동 등록하지 않으며 다른 문서로 오인하지 않습니다.</small></div></section><div class="notice">원본과 비교하여 승인해야만 거래 데이터가 생성됩니다. 불일치·모호성은 차단합니다. 상단 견적·발주 자동 등록은 검색 가능한 PDF·정형 XLSX 전용입니다. 사진·스캔 PDF는 아래 증빙 인식 메뉴에서 별도 검토합니다. 임의 양식과 엑셀 수식은 제한됩니다.</div><section class="panel import-upload-panel"><div class="panel-header"><h2>문서 파일 올리기</h2><span class="badge green">주요 시작 기능</span></div><div class="panel-body"><form id="import-file-form"><label class="import-label">파일 선택 (.xlsx, 텍스트 기반 .pdf · 최대 5MB)<input type="file" name="file" id="import-file" accept=".xlsx,.pdf" required></label><p class="muted">필수: 거래처, 문서종류, 문서 날짜(견적일 또는 수주일), 발주 문서의 납기일, 과세 구분, 품목명, 수량, 단가, 품목별 금액, 공급가액, 부가세, 총금액.</p><button class="btn primary" type="submit">파일 분석 및 검증</button></form></div></section><section class="panel import-upload-panel"><div class="panel-header"><h2>일괄 문서 검토 (V6.3)</h2></div><div class="panel-body"><form id="import-batch-form"><label class="import-label">정형 PDF·XLSX 1~8개 선택<input type="file" accept=".xlsx,.pdf" name="files" multiple required></label><p class="muted">파일당 5MB, 한 번에 20MB. 하나라도 유효하지 않으면 전부 등록되지 않습니다. 이 일괄 등록은 사진 OCR·스캔 PDF를 지원하지 않습니다. 아래 증빙 인식을 이용하세요.</p><button type="submit" class="btn primary">모두 분석해 검토함에 저장</button></form></div></section>${multi}${preview}${queueHtml}${evidenceHtmlV64()}<details class="import-stats-details"><summary>수주 통계 자세히 보기 <span class="import-stats-hint">날짜·거래처·품목별 집계</span></summary><section class="panel import-summary"><div class="panel-header"><h2>수주 집계 (취소 발주 제외)</h2></div><div class="panel-body"><form id="import-period-form" class="import-period"><label>시작일 <input type="date" name="start_date"></label><label>종료일 <input type="date" name="end_date"></label><button class="btn ghost" type="submit">기간 조회</button></form>${info}${a.companies.length?table(['거래처','수주 건수','수주 수량(단위 합산)','공급가액','부가세','총액'],a.companies.map(x=>`<tr><td>${e(x.company)}</td><td>${x.order_count}</td><td>${x.ordered_quantity}</td><td>${krw(x.subtotal)}</td><td>${krw(x.vat)}</td><td class="amount">${krw(x.total)}</td></tr>`).join('')):empty('수주 집계')}<h3 class="section-title">단위별 수량</h3><p class="muted">${e(Object.entries(a.quantity_by_unit||{}).map(([unit,n])=>unit+' '+n).join(' / ')||'집계 없음')}</p>${a.mixed_units?'<div class="notice warning">서로 다른 단위를 단순 합산한 수치는 재고 수량으로 사용하지 마세요. 위 단위별 집계를 사용하세요.</div>':''}<h3 class="section-title">날짜별 수주 집계</h3>${(a.by_date||[]).length?table(['수주일','건수','수량(단위 합산)','공급가액','총액'],a.by_date.map(x=>`<tr><td>${e(x.date)}</td><td>${x.order_count}</td><td>${x.ordered_quantity}</td><td>${krw(x.subtotal)}</td><td>${krw(x.total)}</td></tr>`).join('')):empty('날짜별 수주')}<h3 class="section-title">품목·규격별 수주 집계</h3>${(a.by_item||[]).length?table(['품목','품목코드','규격','단위','수량','공급가액'],a.by_item.map(x=>`<tr><td>${e(x.item)}</td><td>${e(x.sku||'—')}</td><td>${e(x.spec||'—')}</td><td>${e(x.unit)}</td><td>${x.ordered_quantity}</td><td>${krw(x.subtotal)}</td></tr>`).join('')):empty('품목별 수주')}${(a.warnings||[]).length?`<div class="notice warning">${a.warnings.length}건의 발주 내용이 원본에서 변경되었습니다. 단위별 수량을 다시 확인해야 합니다.</div>`:''}</div></section></details>`;
}
async function importFileSubmit(form){const file=form.querySelector('input[type=file]').files?.[0];if(!file)throw new Error('파일을 선택하세요');if(file.size>5*1024*1024)throw new Error('최대 5MB 파일만 지원합니다');
state.importPreview=null;state.importLocalFile=null;if(state.importSourceUrl)URL.revokeObjectURL(state.importSourceUrl);state.importSourceUrl=null;const fd=new FormData();fd.append('file',file,file.name);const response=await fetch('/api/imports/preview',{method:'POST',headers:{'X-CSRF-Token':state.csrf,'Accept':'application/json'},body:fd});let data;try{data=await response.json()}catch{throw new Error('문서 분석 응답을 읽을 수 없습니다')}
if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'문서 해석에 실패했습니다');state.importPreview=data;state.importLocalFile=file;toast('문서 분석 완료 · 원본과 대조 후 승인하세요');await navigate('imports');}
async function importBatchSubmit(form){
 const files=Array.from(form.querySelector('input[type=file]').files||[]);
 if(!files.length||files.length>8)throw new Error('1~8개 파일을 선택하세요');
 if(files.some(f=>f.size>5*1024*1024)||files.reduce((sum,f)=>sum+f.size,0)>20*1024*1024)throw new Error('파일당 5MB, 전체 20MB 이하만 지원합니다');
 const body=new FormData();for(const f of files)body.append('files',f,f.name);
 const response=await fetch('/api/imports/batch/preview',{method:'POST',headers:{'X-CSRF-Token':state.csrf,'Accept':'application/json'},body});
 let data;try{data=await response.json()}catch{throw new Error('일괄 분석 응답을 읽을 수 없습니다')}
 if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'일괄 분석에 실패했습니다');
 state.importBatchPreviews=data.previews;state.importBatchFiles={};
 data.previews.forEach((preview,i)=>{state.importBatchFiles[preview.id]=files[i]});
 state.importPreview=data.previews[0];state.importLocalFile=files[0];
 toast(`${data.staged_count}건 검토함 저장 완료 · 각 문서 승인 필요`);await navigate('imports');
}
async function supplementImportedOrder(form){const p=state.importPreview;if(!p)throw new Error('검토할 문서가 없습니다');
 const fd=new FormData(form);const fields={};for(const [key,value] of fd)fields[key]=String(value).trim();
 const result=await api('/imports/'+encodeURIComponent(p.id)+'/supplement','PATCH',{preview_digest:p.digest,fields});
 state.importPreview=result;toast(result.ready_to_confirm?'필수 정보 보완 완료 · 원본 비교 후 승인하세요':'정보가 저장되었습니다. 나머지 누락 항목을 확인하세요');await navigate('imports');
}
async function approveImportedOrder(){
const p=state.importPreview;if(!p)return;
if(p.document.missing_fields?.length)throw new Error('누락된 필수 정보를 먼저 보완해야 합니다');
const approval=$('#import-approval');if(!approval?.checked)throw new Error('원본과 모든 필수값을 대조한 후 확인란을 선택하세요');
const quoteImport=p.document.record_type==='quote';
if(!confirm(quoteImport?'원본 견적을 대조했습니까? 승인하면 거래처와 견적 초안만 등록되며 발주·입금은 처리하지 않습니다.':'모든 정보를 원본과 비교했습니까? 승인하면 거래처, 내부 연결 기록, 발주서가 생성됩니다.'))return;
const payload={preview_digest:p.digest,confirmed_customer:p.document.company,confirmed_total:p.document.money.total,approve:true};
if(quoteImport)payload.confirmed_quote_date=p.document.quote_date;
else payload.confirmed_order_date=p.document.ordered_at;
const result=await api(`/imports/${encodeURIComponent(p.id)}/confirm`,'POST',payload);
state.importPreview=null;state.importLocalFile=null;
if(state.importSourceUrl)URL.revokeObjectURL(state.importSourceUrl);state.importSourceUrl=null;
await navigate('imports');
if(quoteImport){
 toast('견적 초안 등록 완료 · '+result.quote.doc_no);
 modal('견적 초안 등록 완료',`<div class="notice">견적서 원본을 확인한 후 초안으로 등록했습니다. 외부 발송·거래처 승인·발주·입금 처리는 수행하지 않았습니다.</div><div class="details">${[['견적번호',result.quote.doc_no],['거래처',result.quote.customer_name_snapshot],['견적일',result.quote.quote_date],['상태','초안 (승인 아님)'],['합계',krw(result.quote.money.total)]].map(x=>`<div class="detail-row"><span>${e(x[0])}</span><strong>${e(x[1])}</strong></div>`).join('')}</div>`,'원본 파일은 서버에 저장되지 않습니다.',btn('go-imported-quote','견적서 상세 보기',result.quote.id,'primary'));
}else{
 toast('발주 생성 완료 · '+result.order.doc_no);
 modal('발주 생성 완료',`<div class="notice">확인된 문서에서 거래처·발주가 함께 등록되었습니다.</div><div class="details">${[['발주번호',result.order.doc_no],['거래처',result.order.customer_name_snapshot],['수주일',result.order.order_date],['수주 수량',Object.entries(result.order.import_source?.quantity_by_unit||{}).map(([unit,qty])=>unit+' '+qty).join(' / ')||result.order.items.reduce((a,b)=>a+b.quantity,0)+' (단위 미기재)'],['총액',krw(result.order.money.total)]].map(x=>`<div class="detail-row"><span>${e(x[0])}</span><strong>${e(x[1])}</strong></div>`).join('')}</div>`,'실제 거래처의 전자서명이나 계약 승인을 대신하지 않습니다.',btn('go-imported-order','발주서 상세 확인',result.order.id,'primary'));
}
}

document.addEventListener('click',async ev=>{const d=ev.target.closest('[data-demo]');if(d){$('#login-form [name=email]').value=d.dataset.demo;$('#login-form [name=password]').value='Demo!2026secure';return}
 const page=ev.target.closest('[data-page]');if(page){await navigate(page.dataset.page);return}
 const button=ev.target.closest('[data-action]');if(!button)return;
 if(button.dataset.action==='remove-line'){button.closest('[data-line]')?.remove();renderPreview();return}
 try{button.disabled=true;await handleAction(button.dataset.action,button.dataset.id||'')}catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false}});
document.addEventListener('input',ev=>{if(ev.target.id==='jw-company-query'){state.messengerSearch=ev.target.value;clearTimeout(messengerSearchTimer);messengerSearchTimer=setTimeout(()=>messengerSearch(true).catch(err=>toast(err.message,true)),250);return}if(ev.target.id==='list-search'){applyListFilter();return}if(ev.target.closest('#line-container')||ev.target.name==='vat_mode')renderPreview()});document.addEventListener('scroll',ev=>{if(ev.target.id==='jw-company-results'&&ev.target.scrollTop+ev.target.clientHeight>=ev.target.scrollHeight-80&&state.messengerDirectoryMore!==null){messengerSearch(false).catch(err=>toast(err.message,true))}if(ev.target.id==='jw-message-list')messengerMarkReadAtBottom()},true);
document.addEventListener('change',async ev=>{if(['jw-photo-file','jw-regular-file'].includes(ev.target.id)){try{await messengerSendAttachment(ev.target.files?.[0])}catch(err){toast(err.message,true)}finally{ev.target.value=''}return}if(ev.target.id==='status-filter'){applyListFilter();return}if(ev.target.name==='vat_mode')renderPreview()});
document.addEventListener('submit',async ev=>{
 if(ev.target.id==='messenger-send-form'){
   ev.preventDefault();const form=ev.target;const content=new FormData(form).get('content');const button=form.querySelector('[type=submit]');button.disabled=true;
   try{await api('/messenger/threads/'+state.messengerThreadId+'/messages','POST',{content,request_id:requestRef()});const draft=form.querySelector('[name=content]');if(draft&&draft.value===content)draft.value='';await messengerReceiveUpdates();const log=$('#jw-message-list');if(log)log.scrollTop=log.scrollHeight;}catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false}return;
 }
 if(ev.target.id==='messenger-order-form'){
   ev.preventDefault();const form=ev.target;const data=Object.fromEntries(new FormData(form));const button=form.querySelector('[type=submit]');button.disabled=true;
   try{if(!confirm('이 발주서를 상대 기업에 전송합니까? 전송된 거래 증빙은 수정할 수 없습니다.'))return;await api('/messenger/threads/'+form.dataset.thread+'/orders','POST',{...data,request_id:requestRef()});closeModal();toast('발주서 전송 완료 · 상대 기업 수신 확인 대기');await navigate('messenger')}catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false}return;
 }
 if(ev.target.id==='staff-status-form'){
   ev.preventDefault();const form=ev.target,button=form.querySelector('[type=submit]');button.disabled=true;
   try{await api('/security/users/'+encodeURIComponent(form.dataset.target)+'/'+form.dataset.operation,'POST',{admin_password:new FormData(form).get('admin_password')});form.reset();closeModal();toast('직원 계정 상태가 변경되었습니다');await navigate('security')}
   catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false}return;
 }
 if(ev.target.id==='login-form'){ev.preventDefault();const button=ev.target.querySelector('[type=submit]');button.disabled=true;try{const f=new FormData(ev.target),result=await api('/login','POST',{email:f.get('email'),password:f.get('password'),otp:f.get('otp')||null,recovery_code:f.get('recovery_code')||null});state.csrf=result.csrf_token;state.user=result.user;showApp();await navigate('imports')}catch(err){toast(err.message,true)}finally{button.disabled=false}return}
 if(ev.target.id==='mfa-confirm-form'){
  ev.preventDefault();try{const result=await api('/security/mfa/confirm','POST',{otp:new FormData(ev.target).get('otp')});state.csrf='';state.user=null;showLogin();showRecoveryCodes(result.recovery_codes);}catch(err){toast(err.message,true)}return;
 }
 if(ev.target.id==='mfa-rotate-form'){
  ev.preventDefault();const f=new FormData(ev.target);try{const result=await api('/security/mfa/recovery/rotate','POST',{password:f.get('password'),otp:f.get('otp')||null,recovery_code:f.get('recovery_code')||null});state.csrf='';state.user=null;showLogin();showRecoveryCodes(result.recovery_codes)}catch(err){toast(err.message,true)}return;
 }
 if(ev.target.id==='import-supplement-form'){ev.preventDefault();const button=ev.target.querySelector('[type=submit]');button.disabled=true;try{await supplementImportedOrder(ev.target)}catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false}return}
 if(ev.target.id==='import-period-form'){ev.preventDefault();const p=Object.fromEntries(new FormData(ev.target));try{let query=new URLSearchParams();if(p.start_date)query.set('start_date',p.start_date);if(p.end_date)query.set('end_date',p.end_date);state.importAnalytics=await api('/order-analytics'+(query.size?'?'+query:''));const keep=p;$('#main-content').innerHTML=importPage();$('#import-period-form [name=start_date]').value=keep.start_date||'';$('#import-period-form [name=end_date]').value=keep.end_date||''}catch(err){toast(err.message,true)}return}
 if(ev.target.id==='evidence-v64-file'){ev.preventDefault();const b=ev.target.querySelector('[type=submit]');b.disabled=true;try{await evidenceUploadV64(ev.target)}catch(err){toast(err.message,true)}finally{if(b.isConnected)b.disabled=false}return}
 if(ev.target.id==='evidence-v64-confirm'){ev.preventDefault();const b=ev.target.querySelector('[type=submit]');b.disabled=true;try{await evidenceConfirmV64(ev.target)}catch(err){toast(err.message,true)}finally{if(b.isConnected)b.disabled=false}return}
 if(ev.target.id==='import-batch-form'){ev.preventDefault();const btn=ev.target.querySelector('[type=submit]');btn.disabled=true;try{await importBatchSubmit(ev.target)}catch(err){toast(err.message,true)}finally{if(btn.isConnected)btn.disabled=false}return}
 if(ev.target.id==='import-file-form'){ev.preventDefault();const btn=ev.target.querySelector('[type=submit]');btn.disabled=true;try{await importFileSubmit(ev.target)}catch(err){toast(err.message,true)}finally{if(btn.isConnected)btn.disabled=false}return}
 if(ev.target.id==='entity-form'){ev.preventDefault();const button=ev.target.querySelector('[type=submit]');button.disabled=true;try{await submitForm(ev.target)}catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false}}});
$('#logout').addEventListener('click',async()=>{try{await api('/logout','POST',{})}catch{}state.csrf='';state.user=null;showLogin()});
$('#toggle-menu').addEventListener('click',()=>$('#sidebar').classList.toggle('open'));
document.addEventListener('keydown',ev=>{if(ev.key==='Escape')closeModal();if(ev.key==='/'&&!['INPUT','TEXTAREA','SELECT'].includes(document.activeElement?.tagName)&&!$('#modal-root .modal')){const search=$('#list-search');if(search){ev.preventDefault();search.focus()}}});
begin();
