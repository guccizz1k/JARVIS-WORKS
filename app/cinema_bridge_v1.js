/* CINEMA server boundary: no change to original UI HTML/CSS/WebGL or assets. */
let _jwServerUser = null;
let _jwCsrf = '';
let _jwServerData = null;

async function _jwRequest(path, method='GET', body=null) {
  const headers = {'Accept':'application/json'};
  if (method !== 'GET') {
    headers['X-CSRF-Token'] = _jwCsrf;
    if (body !== null) headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(path, {method, headers, credentials:'same-origin', cache:'no-store', ...(body !== null ? {body: JSON.stringify(body)} : {})});
  const data = await res.json().catch(()=>({}));
  if (!res.ok) {
    const error = new Error(typeof data.detail === 'string' ? data.detail : `서버 요청 실패 (${res.status})`);
    if (res.status === 401 || res.status === 403) error.needOtp = res.status === 401 && method === 'POST' && path === '/api/login';
    throw error;
  }
  return data;
}
function _jwShapeQuote(q){
  return {id:q.id,no:q.doc_no || q.id,kind:'sales',partnerId:q.customer_id || '',title:q.title || '제목 없음',
    items:Array.isArray(q.items)?q.items.map(i=>({name:i.name || '',qty:Number(i.quantity)||0,price:Number(i.unit_price)||0})):[],
    vat:q.vat_mode !== 'exempt',quote:{no:q.doc_no || q.id,date:String(q.created_at||'').slice(0,10),status:q.status || 'draft'},
    order:null,deliveries:[],statement:null,invoice:null,payments:[],files:[],created:Date.parse(q.created_at)||Date.now(),updated:Date.parse(q.updated_at)||Date.now(),serverBacked:true};
}
async function _jwFetchSnapshot(){
  const [customers,quotes,orders,invoices] = await Promise.all([
    _jwRequest('/api/customers'),_jwRequest('/api/quotes'),_jwRequest('/api/orders'),_jwRequest('/api/invoices')]);
  if (![customers,quotes,orders,invoices].every(Array.isArray)) throw new Error('서버 데이터 형식이 예상과 다릅니다');
  const deals=quotes.map(_jwShapeQuote),byQuote=new Map(deals.map(d=>[d.id,d]));
  for (const o of orders){
    let d=byQuote.get(o.quote_id);
    if(!d){d=_jwShapeQuote({...o,id:o.id,doc_no:o.doc_no||o.id});d.quote=null;deals.push(d)}
    d.order={no:o.doc_no||o.id,date:String(o.order_date||o.created_at||'').slice(0,10),due:o.due_date||'',status:o.status||'received',total:Number(o.money?.total)||0,serverId:o.id};
  }
  for (const i of invoices){
    const d=deals.find(x=>x.order && x.order.serverId===i.order_id);
    if(!d)throw new Error('서버 청구서의 주문 연결을 확인할 수 없습니다');
    if(i.settlement?.approved_adjustments)throw new Error('조정 정산 데이터는 CINEMA에 아직 연결되지 않았습니다');
    d.invoice={no:i.doc_no||i.id,date:String(i.created_at||'').slice(0,10),due:i.due_date||'',status:i.status||'issued',total:Number(i.money?.total)||0,serverId:i.id};
    d.payments=(Array.isArray(i.payments)?i.payments:[]).filter(p=>!p.reversed_at).map(p=>({id:p.id,date:p.paid_at,amount:Number(p.amount),memo:p.note||''}));
  }
  return {partners:customers.map(c=>({id:c.id,name:c.name,bizNo:c.business_number||'',contact:c.contact_name||'',phone:c.phone||'',email:c.email||'',type:'both',serverBacked:true})),deals};
}
function _jwSeedReadOnly(){
  DB=defaultDB();
  DB.company={id:_jwServerUser?.org_id||'',name:_jwServerUser?.org_name||'JARVIS WORKS'};
  DB.users=[{id:_jwServerUser?.id||'',role:_jwServerUser?.role||'viewer'}];
  DB.roles={admin:['finance.view'],manager:['finance.view'],staff:['finance.view'],viewer:[]};
  if(_jwServerData){DB.partners=_jwServerData.partners;DB.deals=_jwServerData.deals;}
  const freeze=(value)=>{if(!value||typeof value!=='object'||Object.isFrozen(value))return value;Object.values(value).forEach(freeze);return Object.freeze(value)};
  freeze(DB.partners);freeze(DB.deals);freeze(DB.files);freeze(DB.audit);
}
load=_jwSeedReadOnly;
save=function(){};
saveNow=function(){};
restoreSession=function(){
  if(!_jwServerUser)return false;
  // Preserve server role for authorization; translate only for immutable CINEMA UI permissions.
  const cinematicRole=_jwServerUser.role==='admin'?'admin':_jwServerUser.role==='member'?'staff':'viewer';
  ME={..._jwServerUser,role:cinematicRole,active:true,mfa:{on:false}};
  SESS={id:'server-session',uid:ME.id,revoked:false,at:Date.now(),last:Date.now()};
  return true;
};
login=async function(email,password,otp){
  const t=String(otp||'').trim();
  const auth=await _jwRequest('/api/login','POST', {email,password,...(t?(t.length===32?{recovery_code:t}:{otp:t}):{})});
  _jwCsrf=auth.csrf_token||'';
  _jwServerUser=await _jwRequest('/api/me');
  _jwServerData=await _jwFetchSnapshot();
  _jwSeedReadOnly();restoreSession();
  return ME;
};
registerCompany=async function(){throw new Error('회사 등록은 기존 서버의 검증된 가입 절차에서만 진행할 수 있습니다.');};
logout=function(){ME=null;SESS=null;};
const _jwOriginalEndSession=endSession;
endSession=async function(reason){
  try{await _jwRequest('/api/logout','POST');}
  catch(e){toast('서버 로그아웃에 실패했습니다: '+e.message,'bad');return;}
  _jwServerUser=null;_jwServerData=null;_jwCsrf='';
  await _jwOriginalEndSession(reason);
};
const _jwDeny=()=>{throw new Error('서버에 연결되지 않은 업무 변경은 보안상 차단됩니다.');};
newDeal=_jwDeny;quoteSetStatus=_jwDeny;createOrder=_jwDeny;addDelivery=_jwDeny;
createStatement=_jwDeny;confirmStatement=_jwDeny;createInvoice=_jwDeny;
invoiceRequest=_jwDeny;invoiceIssue=_jwDeny;invoiceReject=_jwDeny;
addPayment=_jwDeny;removePayment=_jwDeny;deleteDeal=_jwDeny;
registerFile=_jwDeny;analyzeFile=_jwDeny;fileReviewRequest=_jwDeny;
fileDecide=_jwDeny;deleteFile=_jwDeny;loadSample=_jwDeny;clearSample=_jwDeny;
partnerForm=_jwDeny;dealForm=_jwDeny;paymentForm=_jwDeny;
resetAll=_jwDeny;restoreBackup=_jwDeny;

async function cinemaBoot(){
  try{
    const r=await fetch('/api/me',{credentials:'same-origin',cache:'no-store'});
    if(r.ok){
      _jwServerUser=await r.json();
      _jwCsrf=_jwServerUser.csrf_token||'';
      _jwServerData=await _jwFetchSnapshot();
    }
  }catch(e){_jwServerUser=null;_jwServerData=null;_jwCsrf='';}
  await boot();
}
