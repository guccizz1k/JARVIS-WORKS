/* JARVIS-WORKS CINEMA server-backed adapter v2.
 * Original CINEMA HTML, CSS, WebGL, layout and assets MUST NOT be changed.
 * Only authenticated server state may be displayed as transaction state.
 * No local-storage business persistence or browser-authoritative approval.
 */
'use strict';
const _jwV2ValidMoney = n => Number.isSafeInteger(Number(n)) && Number(n) >= 0;
const _jwV2ValidQuantity = n => Number.isSafeInteger(Number(n)) && Number(n) > 0 && Number(n) <= 100000;
const _jwV2Date = n => String(n || '').slice(0,10);
const _jwV2AsDate = n => n ? (Date.parse(n) || Date.now()) : Date.now();
const _jwV2Safe = async (task) => {try{return await task()} catch(e){toast(e.message || '서버에서 처리를 거부했습니다.','bad');return null}};
async function _jwV2Commit(path,method,body){
  if(!_jwServerUser || !_jwCsrf) throw new Error('서버 인증이 필요합니다. 다시 로그인하세요.');
  const response=await _jwRequest(path,method,body);
  // Verify that session is still valid BEFORE showing success, then read server source-of-truth.
  const u=await _jwRequest('/api/me');
  if(u.org_id!==_jwServerUser.org_id || u.id!==_jwServerUser.id)throw new Error('인증된 기업 정보가 변경되어 작업 결과를 표시하지 않습니다.');
  const snapshot=await _jwFetchSnapshot();
  _jwServerData=snapshot;
  _jwSeedReadOnly();restoreSession();emit('data');
  if(typeof softRender === 'function')await softRender();
  return response;
}
function _jwV2Quote(q){
  const current=q.status==='accepted'?'approved':q.status;
  return {id:q.id,no:q.doc_no||q.id,kind:'sales',partnerId:q.customer_id,title:q.title,
    items:(q.items||[]).map(i=>({name:i.name,qty:i.quantity,price:i.unit_price})),vat:q.vat_mode==='taxable',
    quote:{no:q.doc_no||q.id,date:_jwV2Date(q.created_at),status:current,serverId:q.id},order:null,deliveries:[],statement:null,
    invoice:null,payments:[],files:[],created:_jwV2AsDate(q.created_at),updated:_jwV2AsDate(q.updated_at),serverBacked:true};
}
_jwFetchSnapshot=async function(){
  const [partners,quotes,orders,invoices,auditRows,dashboard,queue]=await Promise.all([
    _jwRequest('/api/customers'),_jwRequest('/api/quotes'),_jwRequest('/api/orders'),
    _jwRequest('/api/invoices'),_jwRequest('/api/audit'),_jwRequest('/api/dashboard'),_jwRequest('/api/evidence/queue')]);
  if(![partners,quotes,orders,invoices,auditRows].every(Array.isArray) || !dashboard || typeof dashboard!=='object' || !Array.isArray(queue?.items))
    throw new Error('서버 업무 응답 검증에 실패했습니다.');
  const deals=quotes.map(_jwV2Quote),qmap=new Map(deals.map(d=>[d.id,d]));
  for(const o of orders){
    let d=qmap.get(o.quote_id);
    if(!d){
      d={id:o.id,no:o.doc_no||o.id,kind:'purchase',partnerId:o.customer_id,title:o.title,
      items:(o.items||[]).map(i=>({name:i.name,qty:i.quantity,price:i.unit_price})),vat:o.vat_mode==='taxable',
      quote:null,order:null,deliveries:[],statement:null,invoice:null,payments:[],files:[],
      created:_jwV2AsDate(o.created_at),updated:_jwV2AsDate(o.updated_at),serverBacked:true};deals.push(d);
    }
    d.order={no:o.doc_no||o.id,serverId:o.id,date:_jwV2Date(o.order_date||o.created_at),
      due:o.due_date||'',status:o.status,total:o.money?.total||0,reviewState:o.review_state};
    // Deliberately do not fabricate a delivery record: the server order status is not a delivery ledger.
  }
  for(const v of invoices){
    const d=deals.find(d=>d.order?.serverId===v.order_id);
    if(!d)continue;
    d.invoice={no:v.doc_no||v.id,serverId:v.id,date:_jwV2Date(v.created_at),due:v.due_date,
      status:v.status||'issued',total:v.money?.total||0};
    d.payments=(v.payments||[]).filter(p=>!p.reversed_at).map(p=>({id:p.id,date:p.paid_at,amount:p.amount,method:'서버 기록',memo:p.note||''}));
  }
  const safePartners=partners.map(p=>({id:p.id,name:p.name,bizNo:p.business_number||'',contact:p.contact_name||'',
    email:p.email||'',phone:p.phone||'',type:'both',serverBacked:true}));
  const safeAudit=auditRows.map((a,i)=>({i,uid:a.actor_id,user:a.actor_name||'',action:a.action,
    target:a.entity_id||'',detail:a.detail_json||'',at:_jwV2AsDate(a.created_at),serverBacked:true}));
  // The source file is NOT stored, and the OCR engine supplies NO calibrated
  // confidence percentage. The immutable CINEMA drawer expects confidence,
  // line items and arrays from its old local-only parser. Never fabricate
  // those fields or render a bogus confidence percentage for server previews.
  const files=queue.items.map(x=>({id:x.id,no:x.id,name:x.filename,addedAt:_jwV2AsDate(x.created_at),
    // New uploads carry authenticated original byte size; legacy rows have NULL.
    size:Number.isSafeInteger(x.source_size_bytes)&&x.source_size_bytes>0?x.source_size_bytes:0,
    size_known:Number.isSafeInteger(x.source_size_bytes)&&x.source_size_bytes>0,
    originalStored:false,
    status:x.status==='pending'?'review':x.status==='confirmed'?'approved':'rejected',
    analysis:{ok:false,kind:x.document_kind||null,reason:'서버 OCR 분류가 접수되었습니다. 원본은 서버에 저장되지 않으며 현재 CINEMA에는 검증된 신뢰도 수치·원본 대조 화면이 연결되지 않았습니다. 승인과 회계 반영은 이루어지지 않았습니다.'},
    by:_jwServerUser?.id||null,serverBacked:true}));
  return {partners:safePartners,deals,audit:safeAudit,dashboard,files};
};
_jwSeedReadOnly=function(){
  DB=defaultDB();
  // Local CINEMA rule defaults are demonstrations, NOT server automations.
  // Report no active rules until an audited server setting actually exists.
  DB.rules=Object.fromEntries(Object.keys(DB.rules).map(k=>[k,false]));
  DB.company={id:_jwServerUser?.org_id||'',name:_jwServerUser?.org_name||'JARVIS WORKS'};
  DB.users=_jwServerUser?[{id:_jwServerUser.id,email:_jwServerUser.email,name:_jwServerUser.name,
    role:_jwServerUser.role==='admin'?'admin':_jwServerUser.role==='member'?'staff':'viewer',active:true,mfa:{on:false}}]:[];
  // Permissions intentionally conservative: unsynchronised modules cannot claim a server commit.
  DB.roles={admin:['partners.write','deals.write','finance.view','audit.view','docs.write','docs.approve'],
    manager:['partners.write','deals.write','finance.view','docs.write'],staff:['partners.write','deals.write','finance.view','docs.write'],viewer:['finance.view']};
  if(_jwServerData){DB.partners=_jwServerData.partners;DB.deals=_jwServerData.deals;
    DB.audit=_jwServerData.audit;DB.files=_jwServerData.files;}
  const freeze=value=>{if(!value||typeof value!=='object'||Object.isFrozen(value))return;
    Object.values(value).forEach(freeze);Object.freeze(value)};
  for(const field of ['partners','deals','files','audit','users','threads'])freeze(DB[field]);
};
// Browser-maintained audit data cannot be presented as verified server audit.
audit=function(){return null};
// Server OCR runs at upload time; this replaces the browser-only analyzer without changing its upload UI.
registerFile=async function(file){
  if(!_jwServerUser||!_jwCsrf)throw new Error('서버 로그인이 필요합니다.');
  const body=new FormData();body.append('file',file,file.name);
  const response=await fetch('/api/evidence/preview',{method:'POST',headers:{'X-CSRF-Token':_jwCsrf},
    credentials:'same-origin',cache:'no-store',body});
  const data=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'서버 문서 업로드 실패 ('+response.status+')');
  if(!data.id||!data.digest||!data.document)throw new Error('서버에서 확인된 문서 검토 기록이 없습니다.');
  _jwServerData=await _jwFetchSnapshot();_jwSeedReadOnly();restoreSession();emit('data');
  return {id:data.id,no:data.id,name:file.name,analysis:{ok:!!data.document.document_kind,
    kind:data.document.document_kind||'미분류',serverAnalyzed:true},status:'review',serverBacked:true};
};
analyzeFile=async function(record){if(!record?.serverBacked)throw new Error('서버에 등록되지 않은 파일입니다.');return record};
const _jwV2OriginalPartnerForm=_jwOriginalCINEMAPartnerForm;
partnerForm=function(p,after){
  const result=_jwV2OriginalPartnerForm(p,after);
  const m=modalStack[modalStack.length-1];const form=m?.box?.querySelector('form.form');
  if(!form)return result;
  form.addEventListener('submit',e=>{
    e.preventDefault();e.stopImmediatePropagation();
    const v=Object.fromEntries(new FormData(form).entries());
    const body={name:String(v.name||'').trim(),business_number:String(v.bizNo||'').trim(),
      contact_name:String(v.contact||'').trim(),email:String(v.email||'').trim(),phone:String(v.phone||'').trim()};
    if(!body.name){toast('거래처명을 입력해 주세요.','bad');return}
    _jwV2Safe(async()=>{
      const c=await _jwV2Commit(p?'/api/customers/'+encodeURIComponent(p.id):'/api/customers',p?'PUT':'POST',body);
      if(c){m.close();toast('서버에 거래처 정보가 저장됐습니다.','ok');if(after)after(c)}
    });
  },true);
  return result;
};
const _jwV2OriginalDealForm=_jwOriginalCINEMADealForm;
dealForm=function(kind,startAs,preset={},after){
  const m=_jwV2OriginalDealForm(kind,startAs,preset,after);
  if(!m?.box)return m;
  const form=m.box.querySelector('form.form');const submit=m.box.querySelector('.mfoot button.primary');
  if(!form||!submit)return m;
  submit.addEventListener('click',e=>{
    e.preventDefault();e.stopImmediatePropagation();
    if(kind!=='sales'||startAs==='order'){
      toast('직접 수주·발주 등록은 기존 서버가 지원하지 않습니다. 승인된 견적에서 수주를 생성하세요.','bad');return;
    }
    const title=form.querySelector('input[maxlength="80"]')?.value?.trim();
    const customer_id=form.querySelector('select')?.value;
    const vat_mode=form.querySelector('input[type="checkbox"]')?.checked?'taxable':'exempt';
    const items=[...form.querySelectorAll('tbody tr')].map(row=>({name:row.querySelector('input[aria-label="품명"]')?.value?.trim(),
      quantity:Number(row.querySelector('input[aria-label="수량"]')?.value),unit_price:Number(row.querySelector('input[aria-label="단가"]')?.value)}));
    if(!title||!customer_id||items.length<1||items.length>40||items.some(i=>!i.name||!_jwV2ValidQuantity(i.quantity)||!_jwV2ValidMoney(i.unit_price))){
      toast('거래 제목·거래처·품목·정수 수량·단가를 확인해 주세요.','bad');return;
    }
    const payload={customer_id,title,vat_mode,items};
    _jwV2Safe(async()=>{
      const id=preset.edit?.id;
      const d=await _jwV2Commit(id?'/api/quotes/'+encodeURIComponent(id):'/api/quotes',id?'PUT':'POST',payload);
      if(d){m.close();toast('견적서가 서버에 저장됐습니다.','ok');go('#/deals/'+d.id);if(after)after(d)}
    });
  },true);
  return m;
};
quoteSetStatus=function(d,status){
  const accepted=status==='approved'?'accepted':status;
  if(!['sent','accepted','rejected'].includes(accepted))return _jwDeny();
  return _jwV2Safe(async()=>{await _jwV2Commit('/api/quotes/'+encodeURIComponent(d.id)+'/status','POST',{status:accepted});toast('견적 상태를 서버에서 변경했습니다.','ok')});
};
createOrder=function(d){
  if(!d.quote)return _jwDeny();
  return formModal({title:'수주 등록',values:{due_date:dstr(Date.now()+14*864e5)},
    fields:[{k:'due_date',label:'납기일',type:'date',req:true}],submit:'등록',
    onSubmit:async v=>{
      const order=await _jwV2Commit('/api/orders/from-quote','POST',{quote_id:d.id,due_date:v.due_date});
      if(order)toast('수주가 서버에 등록됐습니다.','ok');
    }});
};
createInvoice=function(d){
  if(!d.order?.serverId)return _jwDeny();
  return formModal({title:'청구서 생성',values:{due_date:dstr(Date.now()+30*864e5)},
    fields:[{k:'due_date',label:'입금기한',type:'date',req:true}],submit:'생성',
    onSubmit:async v=>{await _jwV2Commit('/api/invoices/from-order','POST',
      {order_id:d.order.serverId,due_date:v.due_date});toast('청구서가 서버에 생성됐습니다.','ok')}});
};
const _jwV2OriginalPaymentForm=paymentForm;
paymentForm=function(d,after){
  if(!d.invoice?.serverId){toast('서버에 발행된 청구서를 먼저 선택하세요.','bad');return}
  const rem=Number(d.invoice.total)-paidOf(d);
  formModal({title:'입금 기록 · 잔액 '+won(rem),values:{date:today(),amount:rem,method:'계좌이체'},
    fields:[{k:'date',label:'일자',type:'date',req:true},
      {k:'amount',label:'금액(원)',type:'number',req:true,min:1,validate:v=>v<=0?'0보다 커야 합니다.':v>rem?'잔액보다 많습니다.':''},
      {k:'method',label:'방법',type:'select',options:['계좌이체','현금','카드','어음','기타']},
      {k:'memo',label:'메모',wide:true}],submit:'기록',onSubmit:async v=>{
      if(!Number.isSafeInteger(v.amount)||v.amount<1||v.amount>rem)throw new Error('입금 금액이 유효하지 않습니다.');
      const ref=Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>n.toString(16).padStart(2,'0')).join('');
      await _jwV2Commit('/api/invoices/'+encodeURIComponent(d.invoice.serverId)+'/payments','POST',
        {reference:ref,paid_at:v.date,amount:v.amount,note:(v.method+' '+v.memo).trim()});
      toast('입금이 서버에 기록됐습니다.','ok');if(after)after();
    }});
};
// No local-only actions can overwrite a real server action or create a false success notification.
// Server-backed OCR approval: the original interface already exposes review
// actions. Keep its visual elements untouched, but require an actual human to
// check the physical original and confirm typed fields before any server write.
// An unclassified/unsupported consent form may never become a fake receipt.
const _jwV2EvidenceKinds={
  receipt:['sales','purchase','expense'],
  sales_slip:['sales'],purchase_slip:['purchase'],
  trade_statement:['sales','purchase'],inventory_sheet:['inventory_snapshot']
};
fileDecide=async function(f,ok,reason){
  if(!f?.serverBacked||f.status!=='review'){
    toast('서버의 검토 대기 문서만 처리할 수 있습니다.','bad');return false;
  }
  if(!ok){
    toast('문서 반려는 서버 API가 아직 지원하지 않습니다. 반려된 것으로 표시하지 않습니다.','bad');return false;
  }
  try{
    const preview=await _jwRequest('/api/evidence/preview/'+encodeURIComponent(f.id));
    if(preview.id!==f.id||preview.status!=='pending'||!/^[a-f0-9]{64}$/.test(preview.digest||''))
      throw new Error('서버 원본 검토 정보가 불완전합니다.');
    const doc=preview.document||{};
    const types=_jwV2EvidenceKinds[doc.document_kind];
    if(!types||!types.length||['ambiguous','unknown','unsupported'].includes(doc.kind_inference))
      throw new Error('원본 문서 유형을 확인할 수 없어 승인할 수 없습니다.');
    const fields=doc.fields||{};
    const amount=Number.isSafeInteger(fields.gross_amount)?fields.gross_amount:'';
    return formModal({
      title:'원본 대조 · 문서 승인',
      note:'원본 파일은 서버에 보관되지 않습니다. 업로더가 보관 중인 실제 원본과 모든 필드를 직접 대조한 후에만 승인하세요. 승인된 기록은 회계 전표나 실제 입금으로 자동 반영되지 않습니다.',
      values:{record_type:types.includes(doc.proposed_record_type)?doc.proposed_record_type:types[0],
        document_date:fields.document_date||'',counterparty:fields.counterparty||'',
        gross_amount:amount,reference_number:fields.reference_number||'',
        sku:fields.sku||'',quantity:fields.quantity||'',unit:fields.unit||'',original_checked:false},
      fields:[
        {k:'record_type',label:'업무 기록 구분',type:'select',options:types,req:true},
        {k:'counterparty',label:'거래처 · 원본 대조',req:true,max:120},
        {k:'document_date',label:'거래·발행일 · 원본 대조',type:'date',req:true},
        {k:'gross_amount',label:'총금액(원) · 원본 대조',type:'number',min:1,
          validate:(v,out)=>out.record_type==='inventory_snapshot'?(v===''?'':'재고 실사에는 금액을 입력하지 마세요.'):(Number.isSafeInteger(v)&&v>0&&v<=1e9?'':'유효한 총금액을 입력하세요.')},
        {k:'reference_number',label:'원본 문서번호',max:80},
        {k:'sku',label:'품목코드',max:80},{k:'quantity',label:'재고수량',type:'number',min:1,
          validate:(v,out)=>v===''?'':(Number.isSafeInteger(v)&&v>0&&v<=1e7?'':'유효한 재고수량이 필요합니다.')},
        {k:'unit',label:'단위',max:20},
        {k:'original_checked',label:'실제 원본문서의 내용·수치·항목을 모두 확인했습니다',type:'check',req:true,
          validate:v=>v===true?'':'원본 대조 확인이 필요합니다.'}
      ],submit:'서버에 승인',onSubmit:async v=>{
        if(v.original_checked!==true)throw new Error('원본 확인 없는 자동 승인은 허용되지 않습니다.');
        if(v.record_type==='inventory_snapshot'&&(!v.sku||!v.quantity))
          throw new Error('재고 실사 품목코드와 수량을 확인하세요.');
        const payload={
          preview_digest:preview.digest,record_type:v.record_type,document_kind:doc.document_kind,
          counterparty:v.counterparty,document_date:v.document_date,
          gross_amount:v.record_type==='inventory_snapshot'?null:v.gross_amount,
          reference_number:v.reference_number||'',sku:v.sku||'',
          quantity:v.quantity===''?null:v.quantity,unit:v.unit||'',original_checked:true
        };
        const out=await _jwV2Commit('/api/evidence/preview/'+encodeURIComponent(f.id)+'/confirm','POST',payload);
        if(!out||!out.id||out.accounting_posted!==false||out.payment_created!==false)
          throw new Error('서버의 승인·회계 미반영 결과를 확인할 수 없습니다.');
        toast('원본 대조 확인이 완료돼 서버에 증빙 기록을 저장했습니다.','ok');
      }});
  }catch(e){toast(e.message||'서버 증빙 검토를 열 수 없습니다.','bad');return false;}
};
// Original bulk action increments a counter before asynchronous writes finish.
// Block until a properly audited per-document bulk approval endpoint exists.
bulkDecide=function(){toast('일괄 승인은 서버가 지원하지 않습니다. 각 문서 원본을 확인해 승인하세요.','bad');};
bulkReview=function(){toast('문서는 등록 즉시 서버 검토 대기열로 전송됩니다.','info');};
const _jwV2Unsupported=function(){toast('해당 작업은 아직 검증된 서버 API와 연결되지 않았습니다.','bad');};
for(const unsupported of ['addDelivery','createStatement','confirmStatement','invoiceRequest','invoiceIssue',
    'invoiceReject','deleteDeal','deleteFile','removePayment',
    'loadSample','clearSample','resetAll','restoreBackup']) {
  // Use explicit statement rather than allowing a browser-only simulated transaction.
  switch(unsupported){
    case 'addDelivery':addDelivery=_jwV2Unsupported;break;
    case 'createStatement':createStatement=_jwV2Unsupported;break;
    case 'confirmStatement':confirmStatement=_jwV2Unsupported;break;
    case 'invoiceRequest':invoiceRequest=_jwV2Unsupported;break;
    case 'invoiceIssue':invoiceIssue=_jwV2Unsupported;break;
    case 'invoiceReject':invoiceReject=_jwV2Unsupported;break;
    case 'fileReviewRequest':fileReviewRequest=_jwV2Unsupported;break;
    case 'fileDecide':fileDecide=_jwV2Unsupported;break;
    case 'deleteDeal':deleteDeal=_jwV2Unsupported;break;
    case 'deleteFile':deleteFile=_jwV2Unsupported;break;
    case 'removePayment':removePayment=_jwV2Unsupported;break;
    case 'loadSample':loadSample=_jwV2Unsupported;break;
    case 'clearSample':clearSample=_jwV2Unsupported;break;
    case 'resetAll':resetAll=_jwV2Unsupported;break;
    case 'restoreBackup':restoreBackup=_jwV2Unsupported;break;
  }
}

// Capture only unsupported writes in original screen; never alter the delivered DOM/CSS/assets.
if(typeof document!=='undefined' && document.addEventListener){
  document.addEventListener('submit',event=>{
    if(String(location.hash||'').startsWith('#/messenger')){
      event.preventDefault();event.stopImmediatePropagation();
      toast('기업 메신저의 서버 전송 연결을 검증하는 동안 메시지 전송을 차단합니다.','bad');
    }
  },true);
  document.addEventListener('click',event=>{
    const hash=String(location.hash||'');
    // Original CINEMA messenger stores attachments as browser-only messages.
    // The server preview endpoint is NOT a messenger attachment API.
    // Block this direct-click path as well as the existing submit capture.
    if(hash.startsWith('#/messenger')){
      const attachment=event.target.closest('button[aria-label="파일 첨부"]');
      if(attachment){
        event.preventDefault();event.stopImmediatePropagation();
        toast('기업 메신저 파일 전송은 서버 연결 전까지 사용할 수 없습니다.','bad');
        return;
      }
    }
    const unsafe=hash.startsWith('#/team')||hash.startsWith('#/security')||hash.startsWith('#/account')||
      hash.startsWith('#/settings/data')||hash.startsWith('#/automation');
    if(!unsafe)return;
    const el=event.target.closest('button,input[type=checkbox],input[type=submit]');
    if(!el || el.getAttribute('role')==='tab' || el.classList.contains('ibtn'))return;
    event.preventDefault();event.stopImmediatePropagation();
    toast('이 설정은 서버 인증·저장 기능 연결 전까지 변경할 수 없습니다.','bad');
  },true);
}
