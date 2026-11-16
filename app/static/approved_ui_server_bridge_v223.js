/* Approved UI server-only review adapter. OFF without explicit review UI.
 * Cookie-based same-origin session. Never touches jw3.db, IndexedDB or demo data.
 * Authentication transitions are serialized; stale responses never cross sessions.
 */
(function(g){
'use strict';
class Refused extends Error{constructor(code){super(code);this.code=code;this.name='JWServerRefusal'}}
class Bridge{
  #who=null;#csrf='';#origin;#epoch=0;#authBusy=false;
  constructor(){if(!location.origin||location.protocol!=='https:')throw new Refused('HTTPS_REQUIRED');this.#origin=location.origin}
  get identity(){return this.#who?Object.freeze({...this.#who}):null}
  get signedIn(){return Boolean(this.#who)}
  #clear(){this.#who=null;this.#csrf=''}
  #assertEpoch(epoch){if(epoch!==this.#epoch)throw new Refused('STALE_SESSION')}
  #session(){if(this.#authBusy)throw new Refused('AUTH_BUSY');if(!this.#who)throw new Refused('LOGIN_REQUIRED');return this.#epoch}
  #beginAuth(clear=true){
    if(this.#authBusy)throw new Refused('AUTH_BUSY');
    this.#authBusy=true;++this.#epoch;if(clear)this.#clear();return this.#epoch;
  }
  async #request(path,method='GET',body,csrf=false,format='json'){
    const epoch=this.#epoch;
    if(!/^\/api\/[a-z0-9/-]+$/.test(path))throw new Refused('BAD_PATH');
    if(!['GET','POST'].includes(method))throw new Refused('BAD_METHOD');
    const multipart=typeof FormData!=='undefined'&&body instanceof FormData;
    const headers={'Accept':format==='xlsx'?'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet':'application/json'};
    if(body!==undefined&&!multipart)headers['Content-Type']='application/json';
    if(csrf){if(!this.#csrf)throw new Refused('CSRF_MISSING');headers['X-CSRF-Token']=this.#csrf}
    let response;
    try{response=await fetch(this.#origin+path,{method,credentials:'same-origin',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',headers,...(body===undefined?{}:{body:multipart?body:JSON.stringify(body)})})}
    catch{this.#assertEpoch(epoch);throw new Refused('NETWORK_ERROR')}
    this.#assertEpoch(epoch);
    if(response.status===401){++this.#epoch;this.#clear();throw new Refused('SESSION_EXPIRED')}
    if(response.status===409&&path.startsWith('/api/account/'))throw new Refused('STALE_VERSION');
    if(response.status===403)throw new Refused('FORBIDDEN');
    if(!response.ok)throw new Refused('API_FAILURE');
    if(format==='xlsx'){
      const type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
      if((response.headers.get('content-type')||'').split(';')[0].trim().toLowerCase()!==type)throw new Refused('INVALID_XLSX_TYPE');
      const size=response.headers.get('content-length');
      if(size!==null&&(!/^\d+$/.test(size)||Number(size)>2097152))throw new Refused('RESPONSE_TOO_BIG');
      let buffer;try{buffer=await response.arrayBuffer()}catch{this.#assertEpoch(epoch);throw new Refused('NETWORK_ERROR')}
      this.#assertEpoch(epoch);const bytes=new Uint8Array(buffer);
      if(bytes.byteLength>2097152)throw new Refused('RESPONSE_TOO_BIG');
      if(bytes.length<4||bytes[0]!==80||bytes[1]!==75||bytes[2]!==3||bytes[3]!==4)throw new Refused('INVALID_XLSX_BYTES');
      return bytes;
    }
    if(!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')||''))throw new Refused('NON_JSON');
    if(Number(response.headers.get('content-length')||0)>2097152)throw new Refused('RESPONSE_TOO_BIG');
    let data;try{data=await response.json()}catch{this.#assertEpoch(epoch);throw new Refused('INVALID_JSON')}
    this.#assertEpoch(epoch);return data;
  }
  #accept(who){
    if(!who||typeof who!=='object'||Array.isArray(who))throw new Refused('BAD_IDENTITY');
    for(const key of ['id','org_id','email','name','role','org_name','csrf_token'])
      if(typeof who[key]!=='string'||!who[key])throw new Refused('INCOMPLETE_IDENTITY');
    // Protected app/main.py roles are admin/member, not staff/manager/viewer.
    if(!['admin','member'].includes(who.role)||who.csrf_token.length<30)throw new Refused('BAD_ROLE_OR_CSRF');
    this.#who=Object.freeze(Object.fromEntries(['id','org_id','email','name','role','org_name'].map(k=>[k,who[k]])));
    this.#csrf=who.csrf_token;return this.identity
  }
  async #restore(epoch){
    const who=await this.#request('/api/me');this.#assertEpoch(epoch);return this.#accept(who);
  }
  async restore(){
    const epoch=this.#beginAuth();
    try{return await this.#restore(epoch)}finally{this.#authBusy=false}
  }
  async login(email,password,otp){
    if(!email||!password)throw new Refused('CREDENTIALS_REQUIRED');
    const epoch=this.#beginAuth();
    try{
      const result=await this.#request('/api/login','POST',{email,password,...(otp?{otp}:{})});
      this.#assertEpoch(epoch);
      if(!result||!result.user||!result.user.id||!result.user.org_id)throw new Refused('INVALID_LOGIN');
      const who=await this.#restore(epoch);this.#assertEpoch(epoch);
      if(result.user.id!==who.id||result.user.org_id!==who.org_id)throw new Refused('IDENTITY_MISMATCH');
      return who;
    }catch(error){if(epoch===this.#epoch)this.#clear();throw error}
    finally{this.#authBusy=false}
  }
  async logout(){
    const epoch=this.#beginAuth(false);
    try{
      // A successful login POST can set a cookie even if its /me read failed.
      // Recover server identity/CSRF before claiming that session was revoked.
      if(!this.#who){
        try{await this.#restore(epoch)}catch(error){if(error.code==='SESSION_EXPIRED')return;throw error}
      }
      this.#assertEpoch(epoch);await this.#request('/api/logout','POST',undefined,true);
    }
    finally{this.#clear();this.#authBusy=false}
  }
  async write(path,payload){
    const epoch=this.#session();
    // No arbitrary path, DELETE, bulk mutation, user administration or production migration.
    const direct=new Set(['/api/customers','/api/quotes','/api/orders/from-quote','/api/invoices/from-order','/api/automation/statements/from-order']);
    const special=[
      /^\/api\/quotes\/[a-f0-9]{32}\/status$/,
      /^\/api\/orders\/[a-f0-9]{32}\/status$/,
      /^\/api\/invoices\/[a-f0-9]{32}\/payments$/
    ];
    if(!direct.has(path)&&!special.some(r=>r.test(path)))throw new Refused('WRITE_NOT_ALLOWLISTED');
    if(!payload||typeof payload!=='object'||Array.isArray(payload))
      throw new Refused('INVALID_WRITE_PAYLOAD');
    const data=await this.#request(path,'POST',payload,true);
    this.#assertEpoch(epoch);
    if(!data||typeof data!=='object'||Array.isArray(data)||data.org_id!==this.#who?.org_id)
      throw new Refused('TENANT_MISMATCH');
    return Object.freeze({...data});
  }


  // Immutable trade statement conversion: a server-side snapshot of a fulfilled order.
  // This is not a tax invoice and never modifies the source order or makes payments.
  // Tenant-scoped list of finalized, immutable internal trade statements.
  async statementList(){
    const epoch=this.#session();
    const data=await this.#request('/api/automation/statements');this.#assertEpoch(epoch);
    if(!Array.isArray(data)||data.length>100||!data.every(x=>
      x&&typeof x.id==='string'&&/^[a-f0-9]{32}$/.test(x.id)&&
      x.org_id===this.#who?.org_id&&typeof x.order_id==='string'&&
      /^[a-f0-9]{32}$/.test(x.order_id)&&
      typeof x.doc_no==='string'&&x.doc_no.startsWith('TS-')&&
      typeof x.created_at==='string'&&x.created_at.length<80))
      throw new Refused('INVALID_STATEMENT_LIST');
    return data.map(x=>Object.freeze({id:x.id,org_id:x.org_id,order_id:x.order_id,
      doc_no:x.doc_no,created_at:x.created_at}));
  }
  async statementFromOrder(orderId){
    const epoch=this.#session();
    if(typeof orderId!=='string'||!/^[a-f0-9]{32}$/.test(orderId))throw new Refused('INVALID_ORDER_ID');
    const d=await this.write('/api/automation/statements/from-order',{order_id:orderId});
    this.#assertEpoch(epoch);
    if(typeof d.id!=='string'||!/^[a-f0-9]{32}$/.test(d.id)||
       d.order_id!==orderId||d.document?.source_order_id!==orderId||
       d.document?.legal_status!=='internal_business_record_not_tax_invoice'||
       d.document?.document_type!=='trade_statement'||d.document?.finalized!==true||
       !Number.isSafeInteger(d.document?.money?.total)||d.document.money.total<0)
      throw new Refused('INVALID_STATEMENT_RESPONSE');
    return d;
  }
  async statementDetail(statementId,orderId){
    const epoch=this.#session();
    if(typeof statementId!=='string'||!/^[a-f0-9]{32}$/.test(statementId)||
       typeof orderId!=='string'||!/^[a-f0-9]{32}$/.test(orderId))
      throw new Refused('INVALID_STATEMENT_ID');
    const d=await this.#request('/api/automation/statements/'+statementId);
    this.#assertEpoch(epoch);
    if(!d||d.id!==statementId||d.org_id!==this.#who?.org_id||
       d.order_id!==orderId||d.document?.source_order_id!==orderId||
       d.document?.legal_status!=='internal_business_record_not_tax_invoice'||
       d.document?.finalized!==true)
      throw new Refused('STATEMENT_IDENTITY_MISMATCH');
    return d;
  }
  async orderTransactionTrace(orderId){
    const epoch=this.#session();
    if(typeof orderId!=='string'||!/^[a-f0-9]{32}$/.test(orderId))
      throw new Refused('INVALID_ORDER_ID');
    const d=await this.#request('/api/automation/transactions/'+orderId);
    this.#assertEpoch(epoch);
    if(!d||d.source_order_id!==orderId||d.scope!=='authenticated_tenant_only'||
       !Array.isArray(d.events)||!d.events.every(e=>
         e&&typeof e.type==='string'&&
         ['quote','order','trade_statement','invoice','payment'].includes(e.type)&&
         typeof e.id==='string'&&/^[a-f0-9]{32}$/.test(e.id))||
       !Number.isSafeInteger(d.order_money?.total)||
       !Number.isSafeInteger(d.active_paid))
      throw new Refused('INVALID_TRANSACTION_TRACE');
    return d;
  }


  // Server-clock-only measurement: never use Date.now() to manufacture elapsed time.
  // Running task state resides exclusively in authenticated tenant server storage.
  async activeTiming(){
    const epoch=this.#session();
    const d=await this.#request('/api/automation/timing/active');
    this.#assertEpoch(epoch);
    if(d===null)return null;
    if(!d||typeof d!=='object'||Array.isArray(d)||!/^[a-f0-9]{32}$/.test(d.id||'')||
       d.workflow!=='trade_statement'||!['manual','automated'].includes(d.mode)||
       typeof d.started_at!=='string'||!Number.isFinite(Date.parse(d.started_at)))
      throw new Refused('INVALID_ACTIVE_TIMER');
    return Object.freeze({id:d.id,workflow:d.workflow,mode:d.mode,started_at:d.started_at});
  }
  async startTiming(mode){
    const epoch=this.#session();
    if(mode!=='manual'&&mode!=='automated')throw new Refused('INVALID_TIMER_MODE');
    const d=await this.#request('/api/automation/timing/start','POST',
      {workflow:'trade_statement',mode},true);
    this.#assertEpoch(epoch);
    if(!d||!/^[a-f0-9]{32}$/.test(d.id||'')||
       d.status!=='running'||d.workflow!=='trade_statement'||d.mode!==mode)
      throw new Refused('INVALID_TIMER_START');
    return Object.freeze({id:d.id,workflow:d.workflow,mode:d.mode,status:d.status});
  }
  async finishTiming(runId,statementId=null){
    const epoch=this.#session();
    if(typeof runId!=='string'||!/^[a-f0-9]{32}$/.test(runId))throw new Refused('INVALID_TIMER_ID');
    const active=await this.activeTiming();
    this.#assertEpoch(epoch);
    if(!active||active.id!==runId)throw new Refused('TIMER_NOT_ACTIVE');
    if(active.mode==='automated'&&
       (typeof statementId!=='string'||!/^[a-f0-9]{32}$/.test(statementId)))
      throw new Refused('AUTOMATED_REQUIRES_NEW_STATEMENT');
    if(active.mode==='manual'&&statementId!==null)throw new Refused('MANUAL_CANNOT_LINK_DOCUMENT');
    const body={completed:true,...(active.mode==='automated'?{statement_id:statementId}:{})};
    const d=await this.#request('/api/automation/timing/'+runId+'/finish','POST',body,true);
    this.#assertEpoch(epoch);
    if(!d||d.id!==runId||d.mode!==active.mode||d.workflow!=='trade_statement'||
       d.status!=='completed'||d.measurement!=='server_elapsed_time'||
       !Number.isSafeInteger(d.elapsed_ms)||d.elapsed_ms<0||d.elapsed_ms>1800000||
       d.task_outcome!==(active.mode==='automated'?'linked_document':'self_reported_completion'))
      throw new Refused('INVALID_TIMER_COMPLETION');
    return Object.freeze({id:d.id,mode:d.mode,elapsed_ms:d.elapsed_ms,status:d.status,
      measurement:d.measurement,task_outcome:d.task_outcome});
  }
  async cancelTiming(runId){
    const epoch=this.#session();
    if(typeof runId!=='string'||!/^[a-f0-9]{32}$/.test(runId))throw new Refused('INVALID_TIMER_ID');
    const active=await this.activeTiming();
    this.#assertEpoch(epoch);
    if(!active||active.id!==runId)throw new Refused('TIMER_NOT_ACTIVE');
    const d=await this.#request('/api/automation/timing/'+runId+'/cancel','POST',undefined,true);
    this.#assertEpoch(epoch);
    if(!d||d.id!==runId||d.status!=='cancelled'||d.excluded_from_metrics!==true)
      throw new Refused('INVALID_TIMER_CANCEL');
    return Object.freeze({id:d.id,status:d.status,excluded_from_metrics:true});
  }

  #evidence(d,id=null){
    if(!d||typeof d!=='object'||Array.isArray(d)||!/^[a-f0-9]{32}$/.test(d.id||'')||
       (id!==null&&d.id!==id)||!/^[a-f0-9]{64}$/.test(d.digest||'')||
       !/^[a-f0-9]{64}$/.test(d.source_file_sha256||'')||
       !['pending','confirmed'].includes(d.status)||d.original_file_stored!==false||
       !d.document||typeof d.document!=='object'||Array.isArray(d.document)||
       !d.document.fields||typeof d.document.fields!=='object'||Array.isArray(d.document.fields))
      throw new Refused('INVALID_EVIDENCE_PREVIEW');
    return Object.freeze({...d});
  }
  async uploadEvidence(file){
    const epoch=this.#session();
    if(typeof Blob==='undefined'||!(file instanceof Blob)||typeof file.name!=='string'||
       !/\.(png|jpe?g|webp|pdf|xlsx)$/i.test(file.name)||/[\\/]/.test(file.name)||
       file.size<1||file.size>5242880)throw new Refused('INVALID_EVIDENCE_FILE');
    const form=new FormData();form.append('file',file,file.name);
    const d=await this.#request('/api/evidence/preview','POST',form,true);this.#assertEpoch(epoch);
    const checked=this.#evidence(d);if(checked.status!=='pending'||checked.confirmation_required!==true||checked.source_size_bytes!==file.size)
      throw new Refused('INVALID_EVIDENCE_PREVIEW');return checked;
  }
  async evidenceQueue(){
    const epoch=this.#session(),d=await this.#request('/api/evidence/queue');this.#assertEpoch(epoch);
    if(!d||!Array.isArray(d.items)||d.items.length>100||!d.items.every(r=>r&&/^[a-f0-9]{32}$/.test(r.id||'')&&
       typeof r.filename==='string'&&['pending','confirmed'].includes(r.status)&&typeof r.created_at==='string'))
      throw new Refused('INVALID_EVIDENCE_QUEUE');
    return Object.freeze({items:d.items});
  }
  async evidencePreview(id){
    const epoch=this.#session();if(typeof id!=='string'||!/^[a-f0-9]{32}$/.test(id))throw new Refused('INVALID_EVIDENCE_ID');
    const d=await this.#request('/api/evidence/preview/'+id);this.#assertEpoch(epoch);return this.#evidence(d,id);
  }
  async confirmEvidence(id,payload){
    const epoch=this.#session();
    if(!payload||typeof payload!=='object'||Array.isArray(payload)||payload.original_checked!==true)
      throw new Refused('ORIGINAL_REVIEW_REQUIRED');
    const allowed=['preview_digest','record_type','document_kind','counterparty','document_date','gross_amount','reference_number','sku','quantity','unit','original_checked'];
    if(Object.keys(payload).some(k=>!allowed.includes(k)))throw new Refused('INVALID_EVIDENCE_APPROVAL');
    const d=await this.evidencePreview(id);this.#assertEpoch(epoch);
    if(d.status!=='pending')throw new Refused('EVIDENCE_ALREADY_CONFIRMED');
    if(d.digest!==payload.preview_digest||!d.document.document_kind||d.document.document_kind!==payload.document_kind||
       ['ambiguous','unknown','unsupported'].includes(d.document.kind_inference))throw new Refused('EVIDENCE_CHANGED');
    const result=await this.#request('/api/evidence/preview/'+id+'/confirm','POST',payload,true);this.#assertEpoch(epoch);
    if(!result||!/^[a-f0-9]{32}$/.test(result.id||'')||result.record_type!==payload.record_type||
       !Array.isArray(result.corrected_fields)||!result.corrected_fields.every(k=>typeof k==='string')||
       result.accounting_posted!==false||result.payment_created!==false||result.inventory_stock_changed!==false)
      throw new Refused('INVALID_EVIDENCE_CONFIRMATION');
    return Object.freeze({...result});
  }
  async listEvidenceRecords(){
    const epoch=this.#session(),d=await this.#request('/api/evidence/records');this.#assertEpoch(epoch);
    if(!Array.isArray(d)||d.length>100||!d.every(r=>r&&/^[a-f0-9]{32}$/.test(r.id||'')&&
       ['sales','purchase','expense','inventory_snapshot'].includes(r.kind)&&typeof r.source_kind==='string'&&
       typeof r.counterparty==='string'&&typeof r.document_date==='string'&&
       (r.gross_amount===null||(Number.isSafeInteger(r.gross_amount)&&r.gross_amount>0))&&
       (r.org_id===undefined||r.org_id===this.#who?.org_id)))throw new Refused('INVALID_EVIDENCE_RECORDS');
    return d;
  }

  #draft(d,id=null,kind=null,sourceId=null){
    const kinds={sales_order_draft:'quote',delivery_note_draft:'order',payment_request_draft:'invoice'};
    if(!d||typeof d!=='object'||Array.isArray(d)||!/^[a-f0-9]{32}$/.test(d.id||'')||
       !Object.hasOwn(kinds,d.kind)||d.source_type!==kinds[d.kind]||!/^[a-f0-9]{32}$/.test(d.source_id||'')||
       d.scope!=='authenticated_tenant_only'||typeof d.document_no!=='string'||
       d.document?.source_id!==d.source_id||d.document?.source_type!==d.source_type||
       d.document?.document_status!=='internal_review_draft_only'||
       !Number.isSafeInteger(d.document?.money?.total)||d.document.money.total<0||
       (id!==null&&d.id!==id)||(kind!==null&&d.kind!==kind)||(sourceId!==null&&d.source_id!==sourceId))
      throw new Refused('INVALID_DRAFT_RESPONSE');
    return Object.freeze({...d});
  }
  async draftFromSource(kind,sourceId){
    const epoch=this.#session();
    if(!['sales_order_draft','delivery_note_draft','payment_request_draft'].includes(kind)||
       typeof sourceId!=='string'||!/^[a-f0-9]{32}$/.test(sourceId))throw new Refused('INVALID_DRAFT_SOURCE');
    const d=await this.#request('/api/automation/drafts/from-source','POST',{kind,source_id:sourceId},true);
    this.#assertEpoch(epoch);return this.#draft(d,null,kind,sourceId);
  }
  async draftSummary(){
    const epoch=this.#session(),d=await this.#request('/api/automation/drafts/summary');this.#assertEpoch(epoch);
    const kinds=['sales_order_draft','delivery_note_draft','payment_request_draft'];
    if(!d||d.scope!=='authenticated_tenant_only'||!Number.isSafeInteger(d.total)||d.total<0||
       !d.by_kind||typeof d.by_kind!=='object'||Array.isArray(d.by_kind)||
       !Object.entries(d.by_kind).every(([k,v])=>kinds.includes(k)&&Number.isSafeInteger(v)&&v>=0)||
       Object.values(d.by_kind).reduce((a,b)=>a+b,0)!==d.total||
       !Array.isArray(d.recent)||d.recent.length>5||!d.recent.every(r=>r&&/^[a-f0-9]{32}$/.test(r.id||'')&&
          kinds.includes(r.kind)&&typeof r.document_no==='string'&&typeof r.created_at==='string'))
      throw new Refused('INVALID_DRAFT_SUMMARY');
    return Object.freeze({...d});
  }
  async draftDetail(id){
    const epoch=this.#session();if(typeof id!=='string'||!/^[a-f0-9]{32}$/.test(id))throw new Refused('INVALID_DRAFT_ID');
    const d=await this.#request('/api/automation/drafts/'+id);this.#assertEpoch(epoch);
    const checked=this.#draft(d,id);if(typeof checked.stale!=='boolean')throw new Refused('INVALID_DRAFT_RESPONSE');return checked;
  }
  async draftXlsx(id){
    const epoch=this.#session(),d=await this.draftDetail(id);this.#assertEpoch(epoch);
    if(d.stale)throw new Refused('STALE_DRAFT');
    const bytes=await this.#request('/api/automation/drafts/'+id+'/xlsx','GET',undefined,false,'xlsx');this.#assertEpoch(epoch);
    return Object.freeze({bytes,filename:'draft-'+id+'.xlsx',contentType:'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'});
  }

  // V22.3 owner-review messenger and administrator actions.
  // Every request inherits the existing fail-closed cookie, CSRF and session-epoch policy.
  #v223id(value){return typeof value==='string' && /^[a-f0-9]{32}$/.test(value)}
  async messengerDirectory(){
    const epoch=this.#session(), rows=await this.#request('/api/messenger/directory');this.#assertEpoch(epoch);
    if(!Array.isArray(rows)||rows.length>200||!rows.every(r=>r&&this.#v223id(r.org_id)&&
      r.org_id!==this.#who.org_id&&typeof r.company_name==='string'&&r.company_name.length<=200))
      throw new Refused('INVALID_DIRECTORY');
    return rows.map(r=>Object.freeze({org_id:r.org_id,company_name:r.company_name}));
  }
  #v223thread(t,expectedOrg){
    if(!t||!this.#v223id(t.id)||!this.#v223id(t.other_org_id)||
      t.other_org_id===this.#who?.org_id||
      (expectedOrg&&t.other_org_id!==expectedOrg)||
      typeof t.other_company!=='string'||t.other_company.length>200||
      t.status!=='active'||!Number.isSafeInteger(t.unread_count)||t.unread_count<0)
      throw new Refused('BAD_THREAD');
    return Object.freeze({id:t.id,other_org_id:t.other_org_id,other_company:t.other_company,
      unread_count:t.unread_count,status:t.status});
  }
  async messengerThreads(){
    const epoch=this.#session(), data=await this.#request('/api/messenger/threads');this.#assertEpoch(epoch);
    if(!Array.isArray(data)||data.length>200)throw new Refused('INVALID_THREADS');
    return data.map(x=>this.#v223thread(x));
  }
  async messengerCreateThread(recipientOrgId){
    const epoch=this.#session();
    if(!this.#v223id(recipientOrgId)||recipientOrgId===this.#who.org_id)
      throw new Refused('INVALID_RECIPIENT');
    const data=await this.#request('/api/messenger/threads','POST',{recipient_org_id:recipientOrgId},true);
    this.#assertEpoch(epoch);return this.#v223thread(data,recipientOrgId);
  }
  async messengerMessages(threadId,expectedPeerOrgId){
    const epoch=this.#session();if(!this.#v223id(threadId))throw new Refused('INVALID_THREAD_ID');
    if(expectedPeerOrgId!==undefined && !this.#v223id(expectedPeerOrgId))throw new Refused('INVALID_PEER');
    const data=await this.#request('/api/messenger/threads/'+threadId+'/messages');this.#assertEpoch(epoch);
    if(!Array.isArray(data)||data.length>100||!data.every(m=>
      m&&this.#v223id(m.id)&&m.connection_id===threadId&&
      this.#v223id(m.sender_org)&&typeof m.mine==='boolean'&&
      m.mine===(m.sender_org===this.#who.org_id)&&
      (!expectedPeerOrgId||m.sender_org===this.#who.org_id||m.sender_org===expectedPeerOrgId)&&
      typeof m.body==='string'&&m.body.length<=2000&&
      ['text','order'].includes(m.kind)))throw new Refused('INVALID_MESSAGES');
    return data.map(m=>Object.freeze({id:m.id,body:m.body,mine:m.mine,kind:m.kind,sender_org:m.sender_org}));
  }
  async messengerSend(threadId,text,requestId){
    const epoch=this.#session();
    if(!this.#v223id(threadId)||typeof text!=='string'||!text.trim()||text.length>2000||
      typeof requestId!=='string'||!/^[a-f0-9]{32}$/.test(requestId))
      throw new Refused('INVALID_MESSAGE_INPUT');
    const r=await this.#request('/api/messenger/threads/'+threadId+'/messages','POST',
      {content:text,request_id:requestId},true);this.#assertEpoch(epoch);
    if(!r||!this.#v223id(r.id)||!Number.isSafeInteger(r.version)||r.version<1)
      throw new Refused('INVALID_MESSAGE_RECEIPT');
    return Object.freeze({id:r.id,version:r.version});
  }
  async messengerMarkRead(threadId,messageId){
    const epoch=this.#session();
    if(!this.#v223id(threadId)||!this.#v223id(messageId))throw new Refused('INVALID_READ_ID');
    const r=await this.#request('/api/messenger/threads/'+threadId+'/read','POST',
      {last_message_id:messageId},true);this.#assertEpoch(epoch);
    if(!r||r.status!=='read')throw new Refused('INVALID_READ_RESULT');
    return Object.freeze({status:'read'});
  }
  async securityManageOverview(){
    const epoch=this.#session();if(this.#who.role!=='admin')throw new Refused('ADMIN_ONLY');
    const r=await this.#request('/api/security/overview');this.#assertEpoch(epoch);
    if(!r||!Array.isArray(r.users)||!Array.isArray(r.sessions)||!Array.isArray(r.events)||
      typeof r.db_row_level_security_enabled!=='boolean'||
      !Number.isSafeInteger(r.mfa_enabled_user_count)||r.mfa_enabled_user_count<0||
      !r.users.every(u=>u&&this.#v223id(u.id)&&typeof u.name==='string'&&
        ['admin','member'].includes(u.role)&&(u.disabled_at===null||typeof u.disabled_at==='string'))||
      !r.sessions.every(s=>s&&this.#v223id(s.id)&&typeof s.is_current==='boolean'))
      throw new Refused('INVALID_SECURITY');
    return Object.freeze({users:r.users.map(u=>Object.freeze({id:u.id,name:u.name,
        role:u.role,disabled_at:u.disabled_at})),
      sessions:r.sessions.map(s=>Object.freeze({id:s.id,is_current:s.is_current})),
      events:r.events.map(()=>Object.freeze({})),
      mfa_enabled_user_count:r.mfa_enabled_user_count,
      db_row_level_security_enabled:r.db_row_level_security_enabled});
  }
  async securitySetStaffActive(userId,enable,adminPassword){
    const epoch=this.#session();if(this.#who.role!=='admin')throw new Refused('ADMIN_ONLY');
    if(!this.#v223id(userId)||userId===this.#who.id||typeof enable!=='boolean'||
      typeof adminPassword!=='string'||!adminPassword||adminPassword.length>1000)
      throw new Refused('INVALID_STAFF_ACTION');
    const path='/api/security/users/'+userId+(enable?'/enable':'/disable');
    const r=await this.#request(path,'POST',{admin_password:adminPassword},true);this.#assertEpoch(epoch);
    if(!r||r.ok!==true)throw new Refused('INVALID_STAFF_RESPONSE');
    return Object.freeze({ok:true});
  }
  async securityChangeStaffRole(userId,expectedRole,targetRole,adminPassword){
    const epoch=this.#session();if(this.#who.role!=='admin')throw new Refused('ADMIN_ONLY');
    if(!this.#v223id(userId)||userId===this.#who.id||
      !['admin','member'].includes(expectedRole)||!['admin','member'].includes(targetRole)||
      typeof adminPassword!=='string'||!adminPassword||adminPassword.length>1000)
      throw new Refused('INVALID_STAFF_ACTION');
    const response=await this.#request('/api/account/staff/'+userId+'/role','POST',
      {expected_role:expectedRole,target_role:targetRole,admin_password:adminPassword},true);
    this.#assertEpoch(epoch);
    if(!response||response.ok!==true||response.user_id!==userId||
      response.role!==targetRole||typeof response.sessions_revoked!=='boolean')
      throw new Refused('INVALID_STAFF_RESPONSE');
    return Object.freeze({ok:true,user_id:userId,role:targetRole,
      sessions_revoked:response.sessions_revoked});
  }
  async securityRevokeSession(sessionId){
    const epoch=this.#session();if(this.#who.role!=='admin')throw new Refused('ADMIN_ONLY');
    if(!this.#v223id(sessionId))throw new Refused('INVALID_SESSION_ID');
    const r=await this.#request('/api/security/sessions/'+sessionId+'/revoke','POST',undefined,true);
    this.#assertEpoch(epoch);if(!r||r.ok!==true)throw new Refused('INVALID_REVOKE_RESPONSE');
    return Object.freeze({ok:true});
  }
  // Self-scoped profile and UI preferences only; no generic account administration.
  #ownerProfileResult(r){
    if(!r||r.id!==this.#who?.id||r.org_id!==this.#who?.org_id||
      r.role!==this.#who.role||
      typeof r.email!=='string'||typeof r.name!=='string'||!r.name||
      typeof r.org_name!=='string'||!Number.isSafeInteger(r.version)||r.version<0)
      throw new Refused('INVALID_PROFILE');
    return Object.freeze({id:r.id,org_id:r.org_id,email:r.email,name:r.name,
      role:r.role,org_name:r.org_name,version:r.version});
  }
  async profileRead(){
    const epoch=this.#session();
    const r=await this.#request('/api/account/profile');this.#assertEpoch(epoch);
    return this.#ownerProfileResult(r);
  }
  async profileSave(name,version){
    const epoch=this.#session(),v=typeof name==='string'?name.trim():'';
    if(!v||v.length>80||Array.from(v).some(ch=>ch.charCodeAt(0)<32||ch.charCodeAt(0)===127)||
      !Number.isSafeInteger(version)||version<0)throw new Refused('INVALID_PROFILE_INPUT');
    const r=await this.#request('/api/account/profile','POST',{name:v,version},true);
    this.#assertEpoch(epoch);
    const p=this.#ownerProfileResult(r);
    this.#who=Object.freeze({...this.#who,name:p.name});return p;
  }
  #ownerPreferencesResult(r){
    if(!r||r.user_id!==this.#who?.id||r.org_id!==this.#who?.org_id||
      typeof r.compact_view!=='boolean'||typeof r.messenger_auto_refresh!=='boolean'||
      !Number.isSafeInteger(r.version)||r.version<0)
      throw new Refused('INVALID_PREFERENCES');
    return Object.freeze({user_id:r.user_id,org_id:r.org_id,
      compact_view:r.compact_view,messenger_auto_refresh:r.messenger_auto_refresh,version:r.version});
  }
  async preferencesRead(){
    const epoch=this.#session();const r=await this.#request('/api/account/preferences');
    this.#assertEpoch(epoch);return this.#ownerPreferencesResult(r);
  }
  async preferencesSave(preferences){
    const epoch=this.#session();
    if(!preferences||typeof preferences!=='object'||Array.isArray(preferences)||
      !Number.isSafeInteger(preferences.version)||preferences.version<0||
      typeof preferences.compact_view!=='boolean'||
      typeof preferences.messenger_auto_refresh!=='boolean')
      throw new Refused('INVALID_PREFERENCES_INPUT');
    const body={version:preferences.version,compact_view:preferences.compact_view,
      messenger_auto_refresh:preferences.messenger_auto_refresh};
    const r=await this.#request('/api/account/preferences','POST',body,true);
    this.#assertEpoch(epoch);return this.#ownerPreferencesResult(r);
  }
  async list(name){
    const epoch=this.#session();
    if(!['customers','quotes','orders','invoices'].includes(name))throw new Refused('UNSUPPORTED_API');
    const data=await this.#request('/api/'+name);
    this.#assertEpoch(epoch);
    if(!Array.isArray(data))throw new Refused('INVALID_ROWS');
    if(!data.every(r=>r&&typeof r==='object'&&!Array.isArray(r)&&r.org_id===this.#who?.org_id))throw new Refused('TENANT_MISMATCH');
    return data
  }
  // Typed, allowlisted server reads for additional review-only panels.
  // Never expose arbitrary paths or use browser local records as a fallback.
  async readPanel(name){
    const epoch=this.#session();
    const routes={
      'stats':['/api/dashboard','/api/automation/time-savings'],
      'automation':['/api/automation/time-savings'],
      'activity':['/api/audit'],
      'messenger':['/api/messenger/threads'],
      'docs':['/api/evidence/records'],
      'files':['/api/evidence/records'],
      'inbox':['/api/evidence/queue'],
      'security':['/api/security/overview'],
      'team':['/api/security/overview'],
    };
    const allowed=routes[name];
    if(!allowed)throw new Refused('READ_NOT_ALLOWLISTED');
    if(['security','team'].includes(name)&&this.#who.role!=='admin')
      throw new Refused('ADMIN_ONLY');
    const raw=await Promise.all(allowed.map(path=>this.#request(path)));
    this.#assertEpoch(epoch);
    if(!this.#who)throw new Refused('SESSION_EXPIRED');
    const org=this.#who.org_id;
    const array=(data,label,allowMissingOrg)=>{
      if(!Array.isArray(data))throw new Refused('INVALID_'+label.toUpperCase());
      for(const row of data){
        if(!row||typeof row!=='object'||Array.isArray(row))throw new Refused('INVALID_ROW');
        if(typeof row.org_id==='string'&&row.org_id!==org)throw new Refused('TENANT_MISMATCH');
        if(!allowMissingOrg&&typeof row.org_id!=='string')throw new Refused('TENANT_MISMATCH');
      }
      return data;
    };
    let result;
    switch(name){
      case 'stats':{
        const [d,t]=raw;
        if(!d||typeof d!=='object'||Array.isArray(d) ||
          !['customers','quotes','orders','invoices','outstanding','collected','quote_total'].every(k=>Number.isSafeInteger(d[k])&&d[k]>=0)||
          !Array.isArray(d.issues)||!t||!['NOT_MEASURED','COMPARISON_AVAILABLE'].includes(t.status))
          throw new Refused('INVALID_STATISTICS');
        result={counts:{customers:d.customers,quotes:d.quotes,orders:d.orders,invoices:d.invoices},
          money:{outstanding:d.outstanding,collected:d.collected,quote_total:d.quote_total},
          issues:d.issues.filter(x=>x&&typeof x.title==='string').slice(0,30),
          observed_difference_ms:t.status==='COMPARISON_AVAILABLE'&&Number.isFinite(t.observed_difference_ms)?t.observed_difference_ms:null,
          measured:t.status==='COMPARISON_AVAILABLE',
          samples:t.samples};
        break;
      }
      case 'automation':{
        const t=raw[0];
        if(!t||!['NOT_MEASURED','COMPARISON_AVAILABLE'].includes(t.status)||
          !t.samples||!Number.isSafeInteger(t.samples.manual)||!Number.isSafeInteger(t.samples.automated))
          throw new Refused('INVALID_AUTOMATION');
        result={status:t.status,samples:t.samples,
          observed_difference_ms:t.status==='COMPARISON_AVAILABLE'&&Number.isFinite(t.observed_difference_ms)?t.observed_difference_ms:null,
          disclaimer:typeof t.disclaimer==='string'?t.disclaimer:''};
        break;
      }
      case 'activity':result=array(raw[0],'audit',false).slice(0,30).map(x=>({
        action:x.action,entity_type:x.entity_type,actor_name:x.actor_name,created_at:x.created_at}));break;
      case 'messenger':{
        const threads=array(raw[0],'threads',true);
        if(!threads.every(x=>typeof x.id==='string'&&typeof x.other_company==='string'&&
          Number.isSafeInteger(x.unread_count)&&x.unread_count>=0 &&
          x.other_org_id!==org))throw new Refused('INVALID_THREADS');
        result=threads.slice(0,100).map(x=>({other_company:x.other_company,status:x.status,
          unread_count:x.unread_count}));
        break;
      }
      case 'docs':
      case 'files':result=array(raw[0],'documents',true).slice(0,100).map(x=>({
        kind:x.kind,counterparty:x.counterparty,gross_amount:x.gross_amount,
        document_date:x.document_date}));break;
      case 'inbox':{
        const data=raw[0];
        if(!data||!Array.isArray(data.items))throw new Refused('INVALID_QUEUE');
        result=array(data.items,'queue',true).slice(0,100).map(x=>({
          filename:x.filename,status:x.status,document_kind:x.document_kind,created_at:x.created_at}));break;
      }
      case 'security':
      case 'team':{
        const sec=raw[0];
        if(!sec||!Array.isArray(sec.users)||!Array.isArray(sec.sessions)||!Array.isArray(sec.events)||
          typeof sec.db_row_level_security_enabled!=='boolean')throw new Refused('INVALID_SECURITY_OVERVIEW');
        result={users:sec.users.slice(0,100).map(x=>({name:x.name,role:x.role,disabled_at:x.disabled_at})),
          sessions:sec.sessions.length,security_events:sec.events.length,
          mfa_enabled_user_count:sec.mfa_enabled_user_count,
          db_row_level_security_enabled:sec.db_row_level_security_enabled,
          security_monitoring_automated:sec.security_monitoring_automated};
        break;
      }
      default:throw new Refused('READ_NOT_ALLOWLISTED');
    }
    return Object.freeze(result);
  }

}
g.JWOwnerServerBridge=Bridge;
if(typeof module==='object'&&module.exports)module.exports={Bridge,Refused};
})(typeof window==='object'?window:globalThis);
