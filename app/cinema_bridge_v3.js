/* JARVIS-WORKS CINEMA PostgreSQL trade-ledger bridge v3 (review candidate).
 * Loaded AFTER cinema_bridge_v1.js and cinema_bridge_v2.js inside the same scope.
 * The original CINEMA HTML, CSS, WebGL and assets are NOT changed: this file only re-binds the
 * existing business functions and re-uses the existing formModal/toast components.
 *
 * Rules enforced here (the database enforces them again):
 *  - INERT unless GET /api/pg-stage/cinema-trade/partners answers 200 for the signed-in user.
 *  - A success message is shown only AFTER the server committed AND the ledger was re-read.
 *  - No browser-storage business state and no browser-side approvals.
 *  - A double click re-uses the in-flight request; a retry after an unknown outcome re-uses the
 *    same request id, so the server replays instead of duplicating.
 *  - Delivery evidence: the chosen file itself (PDF/PNG/JPEG, <=5 MB) is uploaded; the SERVER stores it and
 *    recomputes the SHA-256. An administrator must open the stored file (audited) before confirming delivery.
 *  - "Server saved" is never shown as "approved": approval states come from server status fields.
 */
const _jwV3Base='/api/pg-stage/cinema-trade';
const _jwV3Pending=new Map();
let _jwV3Active=false;
let _jwV3ProbeAt=0;
const _jwV3Prev={quoteSetStatus,createOrder,createStatement,confirmStatement,createInvoice,invoiceRequest,
  invoiceIssue,invoiceReject,paymentForm,removePayment,deliveryForm,partnerForm,dealForm,_jwFetchSnapshot};
const _jwV3NewId=()=>'cpg-'+Array.from(crypto.getRandomValues(new Uint8Array(16)),n=>n.toString(16).padStart(2,'0')).join('');
const _jwV3Hex=buf=>Array.from(new Uint8Array(buf),n=>n.toString(16).padStart(2,'0')).join('');
const _jwV3Int=n=>{
  // Never replace a missing/invalid/overflowed ledger value with an invented 0.
  if(n===null||n===undefined||typeof n==='boolean'||n===''||
     (typeof n==='string'&&!/^-?(0|[1-9]\d*)$/.test(n))||
     !Number.isSafeInteger(Number(n)))throw new Error('서버 거래 데이터 숫자 검증 실패');
  return Number(n);
};
const _jwV3Time=v=>{
  // Missing/invalid timestamps are data errors, not the current time.
  if(typeof v!=='string'||!v.trim())throw new Error('서버 거래 데이터 일시 검증 실패');
  const parsed=Date.parse(v);
  if(!Number.isFinite(parsed))throw new Error('서버 거래 데이터 일시 검증 실패');
  return parsed;
};
const _jwV3Date=v=>String(v||'').slice(0,10);

async function _jwV3Fetch(path,method='GET',body=null,raw=null){
  const headers={'Accept':'application/json'};
  if(method!=='GET'){headers['X-CSRF-Token']=_jwCsrf;headers['Content-Type']=raw?raw.type:'application/json'}
  let res;
  try{
    res=await fetch(_jwV3Base+path,{method,headers,credentials:'same-origin',cache:'no-store',
      ...(raw?{body:raw.bytes}:body!==null?{body:JSON.stringify(body)}:{})});
  }catch(e){
    const err=new Error('서버에 연결할 수 없어 저장 여부를 확인하지 못했습니다. 같은 작업을 다시 시도해도 중복 저장되지 않습니다.');
    err.definitive=false;throw err;
  }
  const data=await res.json().catch(()=>null);
  if(!res.ok){
    const err=new Error(typeof data?.detail==='string'?data.detail:'서버 요청 실패 ('+res.status+')');
    // 409 (concurrent) and 5xx may be retried with the same request id; everything else is final.
    err.definitive=!(res.status===409||res.status>=500);err.status=res.status;throw err;
  }
  return data;
}

async function _jwV3List(kind){
  const out=[];
  for(let page=0;page<50;page++){
    const rows=await _jwV3Fetch('/'+kind+'?limit=200&offset='+(page*200));
    if(!Array.isArray(rows))throw new Error('서버 거래 원장 응답 검증에 실패했습니다.');
    for(const r of rows)out.push(r&&r.row?r.row:r);
    if(rows.length<200)return out;
  }
  throw new Error('서버 거래 원장이 너무 커서 화면에 표시하지 않습니다.');
}

/* Pure mapping: server ledger rows -> CINEMA deal objects. Exposed for the JS harness tests. */
function _jwV3BuildLedger(L,me){
  const sum=(arr,f)=>arr.reduce((a,x)=>a+f(x),0);
  const partners=L.partners.map(p=>({id:'pg-'+p.id,name:p.name,bizNo:p.business_number||'',contact:p.contact_name||'',
    email:p.email||'',phone:p.phone||'',type:'both',serverBacked:true,pg:{id:p.id,version:p.version}}));
  const qItems=new Map(),oItems=new Map(),dItems=new Map();
  for(const i of L.quoteItems)(qItems.get(i.quote_id)||qItems.set(i.quote_id,[]).get(i.quote_id)).push(i);
  for(const i of L.orderItems)(oItems.get(i.order_id)||oItems.set(i.order_id,[]).get(i.order_id)).push(i);
  for(const i of L.deliveryItems)(dItems.get(i.delivery_id)||dItems.set(i.delivery_id,[]).get(i.delivery_id)).push(i);
  if(!Array.isArray(L.evidence))throw new Error('서버 증빙 목록 검증 실패');
  const evBySha=new Map(L.evidence.map(e=>[e.content_sha256,e]));
  const reversed=new Set(L.reversals.map(r=>r.payment_id));
  const orderByQuote=new Map(L.orders.map(o=>[o.quote_id,o]));
  const quoteStatus={draft:'draft',submitted:'sent',approved:'approved',ordered:'approved',rejected:'rejected',cancelled:'rejected'};
  const invoiceStatus={draft:'draft',reviewed:'pending',confirmed:'issued'};
  const deals=[];
  for(const q of L.quotes){
    const o=orderByQuote.get(q.id)||null;
    const lines=(o?oItems.get(o.id):qItems.get(q.id))||[];
    lines.sort((a,b)=>a.position-b.position);
    const items=lines.map(i=>({name:i.name,qty:_jwV3Int(i.quantity),price:_jwV3Int(i.unit_price),pgItemId:i.id,pgReserved:0,pgConfirmed:0}));
    const idx=new Map(lines.map((i,n)=>[i.id,n]));
    const dels=o?L.deliveries.filter(x=>x.order_id===o.id).sort((a,b)=>a.seq-b.seq):[];
    const confirmed=[],pending=[];
    for(const v of dels){
      const li=(dItems.get(v.id)||[]).filter(x=>idx.has(x.order_item_id));
      if(v.status==='recorded'||v.status==='confirmed')for(const x of li)items[idx.get(x.order_item_id)].pgReserved+=_jwV3Int(x.quantity);
      if(v.status==='confirmed'){
        for(const x of li)items[idx.get(x.order_item_id)].pgConfirmed+=_jwV3Int(x.quantity);
        confirmed.push({id:v.id,no:o.trade_no+'-D'+v.seq,date:_jwV3Date(v.approved_at),
          items:li.map(x=>({i:idx.get(x.order_item_id),qty:_jwV3Int(x.quantity)})),memo:v.evidence_name||'',pgDeliveryId:v.id});
      }else if(v.status==='recorded'){
        const ev=evBySha.get(v.evidence_sha256)||null;
        pending.push({id:v.id,no:o.trade_no+'-D'+v.seq,recordedBy:v.recorded_by,evidenceName:v.evidence_name,
          evidenceSha256:v.evidence_sha256,evidenceId:ev?ev.id:null,evidenceFile:ev?ev.file_name:'',
          evidenceSize:ev?_jwV3Int(ev.size_bytes):0,lines:li.map(x=>({i:idx.get(x.order_item_id),qty:_jwV3Int(x.quantity)}))});
      }
    }
    const stmts=o?L.statements.filter(s=>s.order_id===o.id&&s.status!=='voided').sort((a,b)=>_jwV3Time(a.created_at)-_jwV3Time(b.created_at)):[];
    const invByStmt=new Map(L.invoices.filter(v=>v.status!=='voided').map(v=>[v.statement_id,v]));
    const paidOf=v=>sum(L.payments.filter(p=>p.invoice_id===v.id&&!reversed.has(p.id)),p=>_jwV3Int(p.amount_krw));
    const unfinished=stmts.find(s=>{const v=invByStmt.get(s.id);return s.status!=='confirmed'||!v||v.status!=='confirmed'||paidOf(v)<_jwV3Int(v.total_krw)});
    const coveredDeliveries=new Set(stmts.map(s=>s.delivery_id));
    const uncovered=confirmed.some(c=>!coveredDeliveries.has(c.id));
    const st=unfinished||(uncovered?null:stmts[stmts.length-1])||null;
    const inv=st?invByStmt.get(st.id)||null:null;
    const payments=inv?L.payments.filter(p=>p.invoice_id===inv.id).map(p=>({id:p.id,date:_jwV3Date(p.paid_on),
      amount:_jwV3Int(p.amount_krw),method:'내부 기록',memo:p.reference||'',reversed:reversed.has(p.id)})).filter(p=>!p.reversed):[];
    deals.push({id:'pg-'+q.id,no:q.trade_no,kind:'sales',partnerId:'pg-'+q.partner_id,title:q.title,items,vat:q.vat_mode==='taxable',
      quote:{no:q.trade_no,date:_jwV3Date(q.created_at),status:quoteStatus[q.status]||'draft',serverId:q.id},
      order:o?{no:o.trade_no,serverId:o.id,date:_jwV3Date(o.created_at),due:'',status:o.status,total:0}:null,
      deliveries:confirmed,
      statement:st?{no:o.trade_no+'-S',serverId:st.id,date:_jwV3Date(st.created_at),status:st.status==='confirmed'?'confirmed':'draft',total:_jwV3Int(st.total_krw)}:null,
      invoice:inv?{no:inv.invoice_no,serverId:inv.id,date:_jwV3Date(inv.created_at),due:'',status:invoiceStatus[inv.status]||'draft',
        total:_jwV3Int(inv.total_krw),paid:paidOf(inv)}:null,
      payments,files:[],created:_jwV3Time(q.created_at),updated:_jwV3Time(q.updated_at),serverBacked:true,
      pg:{quoteId:q.id,quoteVersion:q.version,quoteStatus:q.status,orderId:o?o.id:null,pending,
        confirmedDeliveries:confirmed,statements:stmts,uncoveredDelivery:confirmed.find(c=>!coveredDeliveries.has(c.id))||null,
        bankConfirmed:false,paymentBasis:'internal_record_only',deliveryBasis:'human_admin_attested_evidence_hash'}});
  }
  return {partners,deals};
}

async function _jwV3Load(){
  const [partners,quotes,quoteItems,orders,orderItems,deliveries,deliveryItems,statements,invoices,payments,reversals,evidence]=await Promise.all(
    ['partners','quotes','quote-items','orders','order-items','deliveries','delivery-items','statements','invoices','payments','payment-reversals','evidence'].map(_jwV3List));
  return _jwV3BuildLedger({partners,quotes,quoteItems,orders,orderItems,deliveries,deliveryItems,statements,invoices,payments,reversals,evidence},_jwServerUser);
}

_jwFetchSnapshot=async function(){
  const base=await _jwV3Prev._jwFetchSnapshot();
  if(!_jwServerUser){_jwV3Active=false;return base}
  if(!_jwV3Active){
    if(Date.now()-_jwV3ProbeAt<60000)return base;
    _jwV3ProbeAt=Date.now();
    try{const rows=await _jwV3Fetch('/partners?limit=1');_jwV3Active=Array.isArray(rows)}catch(e){_jwV3Active=false}
    if(!_jwV3Active)return base;
  }
  let pg;
  try{pg=await _jwV3Load()}catch(e){_jwV3Active=false;_jwV3ProbeAt=0;toast('PostgreSQL 거래 원장을 불러오지 못해 해당 거래를 표시하지 않습니다: '+e.message,'bad');return base}
  return {...base,partners:[...base.partners,...pg.partners],deals:[...base.deals,...pg.deals]};
};

async function _jwV3Refresh(){
  const me=await _jwRequest('/api/me');
  if(me.org_id!==_jwServerUser.org_id||me.id!==_jwServerUser.id)throw new Error('인증된 기업 정보가 변경되어 작업 결과를 표시하지 않습니다.');
  _jwServerData=await _jwFetchSnapshot();
  _jwSeedReadOnly();restoreSession();emit('data');
  if(typeof softRender==='function')await softRender();
}

/* One server write. Returns the server result only after the ledger was re-read. */
async function _jwV3Commit(op,path,payload,method='POST'){
  if(!_jwServerUser||!_jwCsrf)throw new Error('서버 인증이 필요합니다. 다시 로그인하세요.');
  const key=op+'|'+path+'|'+JSON.stringify(payload);
  const held=_jwV3Pending.get(key);
  if(held&&held.promise)return held.promise;               // duplicate click: same in-flight call
  const rec=held||{rid:_jwV3NewId(),promise:null};
  _jwV3Pending.set(key,rec);
  rec.promise=(async()=>{
    let result;
    try{
      result=await _jwV3Fetch(path,method,{request_id:rec.rid,...payload});
      _jwV3Pending.delete(key);
    }catch(e){
      if(e.definitive)_jwV3Pending.delete(key);else rec.promise=null;
      throw e;
    }
    try{await _jwV3Refresh()}
    catch(e){throw new Error('서버에는 저장되었지만 화면 갱신에 실패했습니다. 새로고침해 서버 상태를 확인하세요. ('+e.message+')')}
    return result;
  })();
  return rec.promise;
}
const _jwV3Run=async(fn,okText)=>{try{const r=await fn();if(okText)toast(okText,'ok');return r}catch(e){toast(e.message||'서버에서 처리를 거부했습니다.','bad');return null}};
const _jwV3IsPg=d=>!!(d&&d.pg);
const _jwV3Admin=()=>_jwServerUser&&_jwServerUser.role==='admin';

/* ------------------------------------------------------------ delivery evidence (server stored) */
const _jwV3EvTypes=['application/pdf','image/png','image/jpeg'];
const _jwV3EvMax=5*1024*1024;
const _jwV3Opening=new Set();
/* Uploads the raw file. The server stores it and recomputes the SHA-256; the locally computed hash is only a
 * retry key and a transport-integrity cross-check, never the value of record. */
async function _jwV3Upload(file){
  if(!_jwServerUser||!_jwCsrf)throw new Error('서버 인증이 필요합니다. 다시 로그인하세요.');
  if(!file||!_jwV3EvTypes.includes(file.type))throw new Error('증빙 파일은 PDF, PNG, JPEG만 가능합니다.');
  if(!Number.isSafeInteger(file.size)||file.size<1||file.size>_jwV3EvMax)throw new Error('증빙 파일은 1바이트 이상 5MB 이하여야 합니다.');
  const name=String(file.name||'').trim().slice(0,180);
  if(!name)throw new Error('증빙 파일 이름이 없습니다.');
  const bytes=await file.arrayBuffer();
  if(bytes.byteLength!==file.size)throw new Error('증빙 파일을 끝까지 읽지 못했습니다.');
  const local=_jwV3Hex(await crypto.subtle.digest('SHA-256',bytes));
  const key='evidence|'+local+'|'+name+'|'+file.type;
  const held=_jwV3Pending.get(key);
  if(held&&held.promise)return held.promise;
  const rec=held||{rid:_jwV3NewId(),promise:null};
  _jwV3Pending.set(key,rec);
  rec.promise=(async()=>{
    let r;
    try{
      r=await _jwV3Fetch('/evidence?request_id='+encodeURIComponent(rec.rid)+'&name='+encodeURIComponent(name),'POST',null,{type:file.type,bytes});
      _jwV3Pending.delete(key);
    }catch(e){
      if(e.definitive)_jwV3Pending.delete(key);else rec.promise=null;
      throw e;
    }
    const ev=r&&r.entity;
    if(!ev||typeof ev.id!=='string'||!ev.id||!/^[0-9a-f]{64}$/.test(String(ev.content_sha256||'')))throw new Error('서버 증빙 응답 검증에 실패했습니다.');
    if(ev.content_sha256!==local)throw new Error('서버가 계산한 증빙 지문이 선택한 파일과 다릅니다. 전송 중 손상 가능성이 있어 사용하지 않습니다.');
    return ev;
  })();
  return rec.promise;
}
/* Audited open of the stored evidence (server writes an audit row that confirmation requires). */
async function _jwV3OpenEvidence(target){
  if(!target||!target.evidenceId)throw new Error('이 납품의 서버 보관 증빙을 찾을 수 없어 열람·확인할 수 없습니다.');
  if(!_jwServerUser||!_jwCsrf)throw new Error('서버 인증이 필요합니다. 다시 로그인하세요.');
  if(_jwV3Opening.has(target.evidenceId))throw new Error('증빙을 여는 중입니다.');
  _jwV3Opening.add(target.evidenceId);
  try{
    let res;
    try{
      res=await fetch(_jwV3Base+'/evidence/'+encodeURIComponent(target.evidenceId)+'/open',{method:'POST',credentials:'same-origin',cache:'no-store',
        headers:{'Accept':'*/*','X-CSRF-Token':_jwCsrf,'Content-Type':'application/json'},body:JSON.stringify({request_id:_jwV3NewId()})});
    }catch(e){throw new Error('서버에 연결할 수 없어 증빙을 열지 못했습니다.')}
    if(!res.ok){const d=await res.json().catch(()=>null);throw new Error(typeof d?.detail==='string'?d.detail:'증빙을 열 수 없습니다 ('+res.status+')')}
    const type=String(res.headers.get('Content-Type')||'').split(';')[0].trim().toLowerCase();
    if(!_jwV3EvTypes.includes(type))throw new Error('서버가 허용되지 않은 형식의 증빙을 보냈습니다.');
    const bytes=await res.arrayBuffer();
    const got=_jwV3Hex(await crypto.subtle.digest('SHA-256',bytes));
    if(got!==target.evidenceSha256||res.headers.get('X-Evidence-SHA256')!==got)throw new Error('서버가 내려준 증빙의 지문이 기록과 일치하지 않아 사용하지 않습니다.');
    download(target.evidenceFile||'evidence',new Blob([bytes],{type}),type);
  }finally{_jwV3Opening.delete(target.evidenceId)}
}

/* ---------------------------------------------------------------- partners */
partnerForm=function(p,after){
  if(p&&!p.pg)return _jwV3Prev.partnerForm(p,after);
  if(!_jwV3Active)return _jwV3Prev.partnerForm(p,after);
  const result=_jwOriginalCINEMAPartnerForm(p,after);
  const m=modalStack[modalStack.length-1];const form=m?.box?.querySelector('form.form');
  if(!form)return result;
  form.addEventListener('submit',e=>{
    e.preventDefault();e.stopImmediatePropagation();
    const v=Object.fromEntries(new FormData(form).entries());
    const body={name:String(v.name||'').trim(),business_number:String(v.bizNo||'').replace(/[^0-9]/g,''),
      contact_name:String(v.contact||'').trim(),email:String(v.email||'').trim(),phone:String(v.phone||'').trim(),
      partner_id:p?p.pg.id:null,expected_version:p?p.pg.version:null};
    if(!body.name){toast('거래처명을 입력해 주세요.','bad');return}
    if(body.business_number&&body.business_number.length!==10){toast('사업자번호는 숫자 10자리여야 합니다.','bad');return}
    _jwV3Run(async()=>{const r=await _jwV3Commit('partner','/partners',body);m.close();if(after)after(r);return r},'서버(PostgreSQL)에 거래처가 저장됐습니다.');
  },true);
  return result;
};

/* ------------------------------------------------------------------ quotes */
dealForm=function(kind,startAs,preset={},after){
  const editing=preset&&preset.edit;
  if(!_jwV3Active||(editing&&!editing.pg))return _jwV3Prev.dealForm(kind,startAs,preset,after);
  const m=_jwOriginalCINEMADealForm(kind,startAs,preset,after);
  if(!m?.box)return m;
  const form=m.box.querySelector('form.form');const submit=m.box.querySelector('.mfoot button.primary');
  if(!form||!submit)return m;
  submit.addEventListener('click',e=>{
    e.preventDefault();e.stopImmediatePropagation();
    if(kind!=='sales'||startAs==='order'){toast('직접 수주·발주 등록은 지원하지 않습니다. 승인된 견적에서 수주를 생성하세요.','bad');return}
    const title=form.querySelector('input[maxlength="80"]')?.value?.trim();
    const partner=form.querySelector('select')?.value||'';
    const vat_mode=form.querySelector('input[type="checkbox"]')?.checked?'taxable':'exempt';
    const items=[...form.querySelectorAll('tbody tr')].map(row=>({name:row.querySelector('input[aria-label="품명"]')?.value?.trim(),
      quantity:Number(row.querySelector('input[aria-label="수량"]')?.value),unit_price:Number(row.querySelector('input[aria-label="단가"]')?.value)}));
    if(!title||!partner||items.length<1||items.length>40||items.some(i=>!i.name||!Number.isSafeInteger(i.quantity)||i.quantity<1||i.quantity>100000||!Number.isSafeInteger(i.unit_price)||i.unit_price<0)){
      toast('거래 제목·거래처·품목·정수 수량·단가를 확인해 주세요.','bad');return}
    if(!partner.startsWith('pg-')){toast('PostgreSQL 거래 원장에는 PostgreSQL에 등록된 거래처만 사용할 수 있습니다. 거래처를 새로 등록해 주세요.','bad');return}
    _jwV3Run(async()=>{
      const r=editing
        ?await _jwV3Commit('quote-update','/quotes/'+encodeURIComponent(editing.pg.quoteId),{expected_version:editing.pg.quoteVersion,title,items},'PUT')
        :await _jwV3Commit('quote-create','/quotes',{partner_id:partner.slice(3),title,vat_mode,items});
      m.close();const id=r&&r.entity&&r.entity.id;if(id){go('#/deals/pg-'+id)}if(after)after(r);return r;
    },'견적서가 서버(PostgreSQL)에 저장됐습니다. 아직 승인되지 않았습니다.');
  },true);
  return m;
};
quoteSetStatus=function(d,status){
  if(!_jwV3IsPg(d))return _jwV3Prev.quoteSetStatus(d,status);
  const to={sent:'submitted',approved:'approved',rejected:'rejected'}[status];
  if(!to)throw new Error('지원하지 않는 견적 상태입니다.');
  return _jwV3Run(()=>_jwV3Commit('quote-'+to,'/quotes/'+encodeURIComponent(d.pg.quoteId)+'/transition',{expected_version:d.pg.quoteVersion,to}),
    to==='approved'?'견적이 관리자에 의해 서버에서 승인됐습니다.':'견적 상태를 서버에서 변경했습니다.');
};
createOrder=function(d){
  if(!_jwV3IsPg(d))return _jwV3Prev.createOrder(d);
  return _jwV3Run(()=>_jwV3Commit('order','/orders',{quote_id:d.pg.quoteId}),'승인된 견적에서 수주가 서버에 생성됐습니다.');
};

/* -------------------------------------------------------------- deliveries */
deliveryForm=function(d){
  if(!_jwV3IsPg(d))return _jwV3Prev.deliveryForm(d);
  const mine=_jwServerUser?.id;
  const open=d.items.map(it=>Math.max(0,it.qty-it.pgReserved));
  const canRecord=open.some(q=>q>0);
  const confirmable=_jwV3Admin()?d.pg.pending.filter(p=>p.recordedBy!==mine):[];
  const blocked=_jwV3Admin()?d.pg.pending.filter(p=>p.recordedBy===mine):[];
  const modes=[];
  if(canRecord)modes.push(['record','납품 기록 (증빙 파일 업로드)']);
  if(confirmable.length){modes.push(['open','증빙 열람 (관리자, 열람 기록이 남습니다)']);modes.push(['confirm','납품 확인 (관리자, 증빙 열람 후)'])}
  if(!modes.length){
    toast(blocked.length?'본인이 기록한 납품은 본인이 확인할 수 없습니다. 다른 관리자가 확인해야 합니다.'
      :d.pg.pending.length?'기록된 납품은 관리자의 증빙 열람·확인을 기다리고 있습니다.':'기록할 수 있는 남은 수량이 없습니다.','bad');
    return null;
  }
  const fields=[];
  if(modes.length>1)fields.push({k:'mode',label:'작업',type:'select',options:modes});
  d.items.forEach((it,i)=>{if(open[i]>0)fields.push({k:'q'+i,label:`${it.name} (기록 가능 ${open[i]} / 주문 ${it.qty}) · 기록 시 입력`,type:'number',min:0,step:1,
    def:modes[0][0]==='record'?open[i]:0,validate:v=>!Number.isSafeInteger(v)||v<0?'0 이상의 정수여야 합니다.':v>open[i]?'남은 수량보다 많습니다.':''})});
  if(confirmable.length)fields.push({k:'pending',label:'열람·확인할 납품 · 열람/확인 시 선택',type:'select',
    options:confirmable.map(p=>[p.id,p.no+' · '+p.evidenceName])});
  fields.push({k:'evidence',label:'증빙 파일 (서명된 인수증·납품서 PDF/PNG/JPEG, 5MB 이하) · 기록 시 필수',type:'file',wide:true,
    hint:'원본 파일이 서버(PostgreSQL)에 저장되고 서버가 SHA-256을 다시 계산합니다. 확인은 관리자가 저장된 증빙을 열어 본 뒤에만 가능합니다.'});
  fields.push({k:'ack',label:'실제 납품·증빙 원본을 직접 확인했습니다 (기록·확인 시)',type:'check'});
  return formModal({title:'납품 등록·확인 (PostgreSQL 원장)',values:{mode:modes[0][0]},fields,submit:'서버에 저장',
    note:'서버 저장은 납품 "완료"가 아닙니다. 기록 후 다른 관리자가 서버에 저장된 증빙을 열어 확인해야 완료로 인정됩니다.',
    onSubmit:async(v,m)=>{
      const mode=v.mode||modes[0][0];
      if(mode==='open'||mode==='confirm'){
        const target=confirmable.find(p=>p.id===v.pending);
        if(!target)throw new Error('열람·확인할 납품을 선택해 주세요.');
        if(mode==='open'){
          await _jwV3OpenEvidence(target);
          toast('증빙을 내려받았고 열람 기록이 서버에 남았습니다. 내용을 확인한 뒤 "납품 확인"을 진행하세요.','ok');
          return;
        }
        if(v.ack!==true)throw new Error('증빙 원본 확인 체크가 필요합니다.');
        await _jwV3Commit('delivery-confirm','/deliveries/'+encodeURIComponent(target.id)+'/confirm',{});
        toast('관리자가 서버 보관 증빙을 열람해 납품을 확인했습니다. (은행·물류 확인은 아닙니다)','ok');
        return;
      }
      if(v.ack!==true)throw new Error('증빙 원본 확인 체크가 필요합니다.');
      const input=m&&m.box?m.box.querySelector('input[type=file]'):null;const file=input&&input.files&&input.files[0];
      if(!file)throw new Error('증빙 파일을 선택해 주세요.');
      const lines=d.items.map((it,i)=>({order_item_id:it.pgItemId,quantity:Number(v['q'+i])||0})).filter(l=>l.quantity>0);
      if(!lines.length)throw new Error('납품 수량을 입력해 주세요.');
      const ev=await _jwV3Upload(file);
      await _jwV3Commit('delivery-record','/orders/'+encodeURIComponent(d.pg.orderId)+'/deliveries',
        {lines,evidence_sha256:ev.content_sha256,evidence_name:String(ev.file_name||file.name).slice(0,180)});
      toast('납품이 서버에 기록됐습니다. 관리자 확인 전에는 완료가 아닙니다.','ok');
    }});
};

/* ------------------------------------------------- statements and invoices */
createStatement=function(d){
  if(!_jwV3IsPg(d))return _jwV3Prev.createStatement(d);
  const target=d.pg.uncoveredDelivery||d.pg.confirmedDeliveries[0];
  if(!target)return _jwV3Run(async()=>{throw new Error('확인된 납품이 없어 거래명세표를 만들 수 없습니다.')});
  return _jwV3Run(()=>_jwV3Commit('statement','/deliveries/'+encodeURIComponent(target.id)+'/statements',{}),'확인된 납품 기준으로 거래명세표 초안이 생성됐습니다.');
};
confirmStatement=function(d){
  if(!_jwV3IsPg(d))return _jwV3Prev.confirmStatement(d);
  return _jwV3Run(()=>_jwV3Commit('statement-confirm','/statements/'+encodeURIComponent(d.statement.serverId)+'/confirm',{}),'거래명세표가 관리자에 의해 확정됐습니다.');
};
createInvoice=function(d){
  if(!_jwV3IsPg(d))return _jwV3Prev.createInvoice(d);
  return _jwV3Run(()=>_jwV3Commit('invoice','/statements/'+encodeURIComponent(d.statement.serverId)+'/invoices',{}),'청구서 초안이 서버에 생성됐습니다. 아직 발행되지 않았습니다.');
};
invoiceRequest=function(d){
  if(!_jwV3IsPg(d))return _jwV3Prev.invoiceRequest(d);
  toast('청구서 검토·발행은 관리자만 할 수 있습니다. 관리자에게 요청하세요. (서버에 요청 기록은 만들어지지 않았습니다)','bad');
};
invoiceIssue=function(d){
  if(!_jwV3IsPg(d))return _jwV3Prev.invoiceIssue(d);
  const id=encodeURIComponent(d.invoice.serverId);
  return _jwV3Run(async()=>{
    if(d.invoice.status==='draft')await _jwV3Commit('invoice-review','/invoices/'+id+'/review',{});
    return _jwV3Commit('invoice-confirm','/invoices/'+id+'/confirm',{});
  },'청구서가 관리자에 의해 서버에서 확정·발행됐습니다. (입금 확인은 별도입니다)');
};
invoiceReject=function(d,reason){
  if(!_jwV3IsPg(d))return _jwV3Prev.invoiceReject(d,reason);
  return _jwV3Run(()=>_jwV3Commit('invoice-void','/invoices/'+encodeURIComponent(d.invoice.serverId)+'/void',{reason:String(reason||'').trim().slice(0,300)||'반려'}),
    '청구서를 무효 처리했습니다. 필요하면 새로 생성하세요.');
};

/* ---------------------------------------------------------------- payments */
paymentForm=function(d,after){
  if(!_jwV3IsPg(d))return _jwV3Prev.paymentForm(d,after);
  if(!d.invoice||d.invoice.status!=='issued'){toast('확정된 청구서가 있어야 입금을 기록할 수 있습니다.','bad');return null}
  const rem=d.invoice.total-d.invoice.paid;
  const reference='pay-'+_jwV3NewId().slice(4,24);
  return formModal({title:'입금 기록(내부 기록) · 잔액 '+won(rem),values:{date:today(),amount:rem},
    fields:[{k:'date',label:'입금일',type:'date',req:true},
      {k:'amount',label:'금액(원)',type:'number',req:true,min:1,step:1,validate:v=>!Number.isSafeInteger(v)||v<=0?'1원 이상의 정수여야 합니다.':v>rem?'잔액보다 많습니다.':''}],
    submit:'기록',note:'내부 입금 기록입니다. 은행 입금 확인이 아니며 회계 반영·정산 확정이 아닙니다.',
    onSubmit:async v=>{
      await _jwV3Commit('payment','/invoices/'+encodeURIComponent(d.invoice.serverId)+'/payments',
        {amount_krw:v.amount,paid_on:v.date,reference});
      toast('입금이 내부 기록으로 서버에 저장됐습니다. (은행 확인 아님)','ok');if(after)after();
    }});
};
removePayment=function(d,id){
  if(!_jwV3IsPg(d))return _jwV3Prev.removePayment(d,id);
  return formModal({title:'입금 기록 정정(반대 기록)',fields:[{k:'reason',label:'정정 사유',req:true,max:300,wide:true}],submit:'정정 기록',
    note:'원래 기록은 삭제되지 않고 감사 이력에 남으며, 반대 기록이 추가됩니다.',
    onSubmit:async v=>{await _jwV3Commit('payment-reverse','/payments/'+encodeURIComponent(id)+'/reverse',{reason:v.reason});
      toast('입금 기록이 정정(반대 기록)됐습니다.','ok')}});
};
