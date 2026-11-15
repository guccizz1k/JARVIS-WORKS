/* Approved UI server-only review adapter. OFF without explicit review UI.
 * Cookie-based same-origin session. Never touches jw3.db, IndexedDB or demo data.
 * No write except login/logout; business screens are read-only and fail closed.
 */
(function(g){
'use strict';
class Refused extends Error{constructor(code){super(code);this.code=code;this.name='JWServerRefusal'}}
class Bridge{
  #who=null;#csrf='';#origin;
  constructor(){if(!location.origin||location.protocol!=='https:')throw new Refused('HTTPS_REQUIRED');this.#origin=location.origin}
  get identity(){return this.#who?Object.freeze({...this.#who}):null}
  get signedIn(){return Boolean(this.#who)}
  #clear(){this.#who=null;this.#csrf=''}
  async #request(path,method='GET',body,csrf=false){
    if(!/^\/api\/[a-z0-9/-]+$/.test(path))throw new Refused('BAD_PATH');
    if(!['GET','POST'].includes(method))throw new Refused('BAD_METHOD');
    const headers={'Accept':'application/json'};
    if(body!==undefined)headers['Content-Type']='application/json';
    if(csrf){if(!this.#csrf)throw new Refused('CSRF_MISSING');headers['X-CSRF-Token']=this.#csrf}
    let response;
    try{response=await fetch(this.#origin+path,{method,credentials:'same-origin',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',headers,...(body===undefined?{}:{body:JSON.stringify(body)})})}
    catch{throw new Refused('NETWORK_ERROR')}
    if(response.status===401){this.#clear();throw new Refused('SESSION_EXPIRED')}
    if(response.status===403)throw new Refused('FORBIDDEN');
    if(!response.ok)throw new Refused('API_FAILURE');
    if(!/^application\/json(?:;|$)/i.test(response.headers.get('content-type')||''))throw new Refused('NON_JSON');
    if(Number(response.headers.get('content-length')||0)>2097152)throw new Refused('RESPONSE_TOO_BIG');
    try{return await response.json()}catch{throw new Refused('INVALID_JSON')}
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
  async restore(){this.#clear();return this.#accept(await this.#request('/api/me'))}
  async login(email,password,otp){
    this.#clear();if(!email||!password)throw new Refused('CREDENTIALS_REQUIRED');
    const result=await this.#request('/api/login','POST',{email,password,...(otp?{otp}:{})});
    if(!result||!result.user||!result.user.id||!result.user.org_id)throw new Refused('INVALID_LOGIN');
    const who=await this.restore();
    if(result.user.id!==who.id||result.user.org_id!==who.org_id){this.#clear();throw new Refused('IDENTITY_MISMATCH')}
    return who
  }
  async logout(){try{if(this.#who)await this.#request('/api/logout','POST',undefined,true)}finally{this.#clear()}}
  async write(path,payload){
    if(!this.#who)throw new Refused('LOGIN_REQUIRED');
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
    if(!data||typeof data!=='object'||Array.isArray(data)||data.org_id!==this.#who?.org_id)
      throw new Refused('TENANT_MISMATCH');
    return Object.freeze({...data});
  }


  // Immutable trade statement conversion: a server-side snapshot of a fulfilled order.
  // This is not a tax invoice and never modifies the source order or makes payments.
  async statementFromOrder(orderId){
    if(!this.#who)throw new Refused('LOGIN_REQUIRED');
    if(typeof orderId!=='string'||!/^[a-f0-9]{32}$/.test(orderId))throw new Refused('INVALID_ORDER_ID');
    const d=await this.write('/api/automation/statements/from-order',{order_id:orderId});
    if(typeof d.id!=='string'||!/^[a-f0-9]{32}$/.test(d.id)||
       d.order_id!==orderId||d.document?.source_order_id!==orderId||
       d.document?.legal_status!=='internal_business_record_not_tax_invoice'||
       d.document?.document_type!=='trade_statement'||d.document?.finalized!==true||
       !Number.isSafeInteger(d.document?.money?.total)||d.document.money.total<0)
      throw new Refused('INVALID_STATEMENT_RESPONSE');
    return d;
  }
  async statementDetail(statementId,orderId){
    if(!this.#who)throw new Refused('LOGIN_REQUIRED');
    if(typeof statementId!=='string'||!/^[a-f0-9]{32}$/.test(statementId)||
       typeof orderId!=='string'||!/^[a-f0-9]{32}$/.test(orderId))
      throw new Refused('INVALID_STATEMENT_ID');
    const d=await this.#request('/api/automation/statements/'+statementId);
    if(!d||d.id!==statementId||d.org_id!==this.#who?.org_id||
       d.order_id!==orderId||d.document?.source_order_id!==orderId||
       d.document?.legal_status!=='internal_business_record_not_tax_invoice'||
       d.document?.finalized!==true)
      throw new Refused('STATEMENT_IDENTITY_MISMATCH');
    return d;
  }
  async orderTransactionTrace(orderId){
    if(!this.#who)throw new Refused('LOGIN_REQUIRED');
    if(typeof orderId!=='string'||!/^[a-f0-9]{32}$/.test(orderId))
      throw new Refused('INVALID_ORDER_ID');
    const d=await this.#request('/api/automation/transactions/'+orderId);
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

  async list(name){
    if(!this.#who)throw new Refused('LOGIN_REQUIRED');
    if(!['customers','quotes','orders','invoices'].includes(name))throw new Refused('UNSUPPORTED_API');
    const data=await this.#request('/api/'+name);
    if(!Array.isArray(data))throw new Refused('INVALID_ROWS');
    if(!data.every(r=>r&&typeof r==='object'&&!Array.isArray(r)&&r.org_id===this.#who?.org_id))throw new Refused('TENANT_MISMATCH');
    return data
  }
  // Typed, allowlisted server reads for additional review-only panels.
  // Never expose arbitrary paths or use browser local records as a fallback.
  async readPanel(name){
    if(!this.#who)throw new Refused('LOGIN_REQUIRED');
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
