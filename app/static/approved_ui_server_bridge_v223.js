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
  async list(name){
    if(!this.#who)throw new Refused('LOGIN_REQUIRED');
    if(!['customers','quotes','orders','invoices'].includes(name))throw new Refused('UNSUPPORTED_API');
    const data=await this.#request('/api/'+name);
    if(!Array.isArray(data))throw new Refused('INVALID_ROWS');
    if(!data.every(r=>r&&typeof r==='object'&&!Array.isArray(r)&&r.org_id===this.#who?.org_id))throw new Refused('TENANT_MISMATCH');
    return data
  }
}
g.JWOwnerServerBridge=Bridge;
if(typeof module==='object'&&module.exports)module.exports={Bridge,Refused};
})(typeof window==='object'?window:globalThis);
