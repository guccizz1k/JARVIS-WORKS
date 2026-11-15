/* Dedicated server review shell, never auto-activates in the protected original. */
(function(g){
'use strict';
const MENUS=[['home','홈','all'],['docs','문서',''],['deals','거래','quotes'],['papers','거래 문서','quotes'],
['money','입금·미수금','invoices'],['partners','거래처','customers'],['messenger','메신저',''],
['automation','자동화',''],['stats','통계',''],['export','내보내기',''],['inbox','승인함',''],
['files','첨부 파일',''],['activity','감사 이력',''],['team','직원',''],['security','보안',''],['settings','설정',''],['account','내 계정','identity']];
const t=(tag,cls,text)=>{const x=document.createElement(tag);if(cls)x.className=cls;if(text!==undefined)x.textContent=String(text);return x};
const clear=e=>e.replaceChildren();
const msg=e=>({'SESSION_EXPIRED':'세션이 종료되었습니다.','TENANT_MISMATCH':'다른 회사의 데이터가 확인되어 조회를 차단했습니다.','NETWORK_ERROR':'서버 연결 실패','FORBIDDEN':'접근 권한 없음','HTTPS_REQUIRED':'HTTPS 연결이 필요합니다.'}[e&&e.code]||'요청을 처리할 수 없습니다.');
function start(){
  const root=document.getElementById('app'), login=document.getElementById('login');document.getElementById('intro')?.remove();
  document.documentElement.dataset.theme='dark';document.body.classList.add('jw-approved-review');clear(root);clear(login);login.hidden=false;
  let bridge;try{bridge=new g.JWOwnerServerBridge()}catch(e){login.append(t('p','jw-review-failure',msg(e)));return}
  let epoch=0,submitting=false;
  function entry(note){
    ++epoch;root.classList.remove('on');clear(root);clear(login);login.hidden=false;
    const c=t('section','jw-review-entry');c.append(t('small','jw-review-kicker','JARVIS WORKS · SECURE REVIEW'),t('h1','jw-review-heading','WORK WITHOUT EDGES.'),t('p','jw-review-muted','실제 서버 인증 · 읽기 전용 연결 검토'));
    const form=t('form','jw-review-form'),em=t('input','jw-review-input'),pw=t('input','jw-review-input'),otp=t('input','jw-review-input'),btn=t('button','jw-review-button','서버 로그인'),alert=t('p','jw-review-muted',note||'등록된 서버 계정으로 로그인하세요.');
    em.type='email';em.required=true;em.autocomplete='username';em.placeholder='이메일';em.setAttribute('aria-label','이메일');
    pw.type='password';pw.required=true;pw.autocomplete='current-password';pw.placeholder='비밀번호';pw.setAttribute('aria-label','비밀번호');
    otp.autocomplete='one-time-code';otp.placeholder='MFA 코드 (선택)';otp.setAttribute('aria-label','MFA 코드');
    btn.type='submit';form.append(em,pw,otp,btn,alert);c.append(form,t('p','jw-review-muted','로컬 회사 등록 · 브라우저 거래 저장 · 서버 미검증 거래 수정 비활성'));login.append(c);
    form.addEventListener('submit',async e=>{e.preventDefault();if(submitting)return;submitting=true;btn.disabled=true;
      try{const who=await bridge.login(em.value,pw.value,otp.value);pw.value='';otp.value='';dashboard(who)}
      catch(err){pw.value='';otp.value='';alert.textContent=msg(err);alert.setAttribute('role','alert')}
      finally{submitting=false;btn.disabled=false}});
  }
  function dashboard(who){
    ++epoch;clear(login);login.hidden=true;clear(root);root.classList.add('on');
    const shell=t('div','jw-review-shell'),nav=t('nav','jw-review-nav'),content=t('main','jw-review-main'),head=t('header','jw-review-top'),view=t('section','jw-review-view');
    nav.setAttribute('aria-label','업무 메뉴');nav.append(t('strong','jw-review-mark','JW ∞'));
    for(const [key,label] of MENUS){const b=t('button','jw-review-navitem',label);b.type='button';b.dataset.page=key;b.onclick=()=>open(key);nav.append(b)}
    const logout=t('button','jw-review-logout','로그아웃');logout.onclick=async()=>{try{await bridge.logout()}catch{}entry('서버에서 로그아웃했습니다.')};
    head.append(t('span','jw-review-kicker','서버 데이터 연결 검토'),t('span','jw-review-user',who.name+' · '+who.org_name),logout);content.append(head,view);shell.append(nav,content);root.append(shell);
    async function open(key){
      let selected=MENUS.find(m=>m[0]===key)||MENUS[0];let token=++epoch;
      nav.querySelectorAll('button').forEach(b=>b.classList.toggle('selected',b.dataset.page===key));
      clear(view);view.append(t('small','jw-review-kicker','JARVIS WORKS'),t('h2','jw-review-title',selected[1]));
      if(key==='account'){view.append(t('p','jw-review-muted',who.name+' · '+who.email+' · '+who.org_name+' · '+who.role));return}
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
