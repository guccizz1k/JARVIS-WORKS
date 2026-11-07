"""Opt-in CINEMA V22.3 browser bridge; never changes original CINEMA assets.

Only included by cinema_entry_v1 when the isolated dual-session pilot is
explicitly enabled. Aggregate/report screens stay fail-closed until verified.
"""
from __future__ import annotations

import os

JS = r"""
/* V22.3: UI-to-cutover pilot, loaded after unchanged bridge v1/v2/v3. */
let _jwCutoverActive=false;
let _jwCutoverPgCsrf='';
const _jwCutoverOriginalRequest=_jwRequest;
const _jwCutoverOriginalEnd=endSession;
const _jwCutoverOriginalV3Fetch=_jwV3Fetch;
const _jwCutoverLegacyRead=new Set([
  '/api/customers','/api/quotes','/api/orders','/api/invoices',
  '/api/audit','/api/dashboard','/api/evidence/queue'
]);

async function _jwCutoverHttp(path,method='GET',body=null,csrf=''){
  const headers={'Accept':'application/json'};
  if(method!=='GET'){
    if(csrf)headers['X-CSRF-Token']=csrf;
    if(body!==null)headers['Content-Type']='application/json';
  }
  const r=await fetch(path,{method,headers,credentials:'same-origin',cache:'no-store',
    ...(body!==null?{body:JSON.stringify(body)}:{})});
  const data=await r.json().catch(()=>({}));
  if(!r.ok){
    const e=new Error(typeof data.detail==='string'?data.detail:
      (typeof data.code==='string'?data.code:'서버 인증 요청 실패 ('+r.status+')'));
    e.status=r.status;
    e.needOtp=r.status===401&&method==='POST'&&path==='/api/pg-stage/v85/login';
    throw e;
  }
  return data;
}

_jwRequest=async function(path,method='GET',body=null){
  if(!_jwCutoverActive)return _jwCutoverOriginalRequest(path,method,body);
  // PG ledger is loaded separately via the verified CINEMA v3 backend.
  // Never count PG records twice in the unchanged v2 legacy snapshot.
  if(method==='GET'&&_jwCutoverLegacyRead.has(path)){
    return _jwCutoverOriginalRequest('/api/pg-stage/cutover/legacy/'+path.slice(5),
                                     method,body);
  }
  if(method==='GET')return _jwCutoverOriginalRequest(path,method,body);
  const headers={'Accept':'application/json','X-CSRF-Token':_jwCsrf,
                 'X-JW-PG-CSRF':_jwCutoverPgCsrf};
  if(body!==null)headers['Content-Type']='application/json';
  const r=await fetch(path,{method,credentials:'same-origin',headers,cache:'no-store',
    ...(body!==null?{body:JSON.stringify(body)}:{})});
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(typeof data.detail==='string'?data.detail:
                         typeof data.code==='string'?data.code:'서버 요청 실패 ('+r.status+')');
  return data;
};

_jwV3Fetch=async function(path,method='GET',body=null,raw=null){
  if(!_jwCutoverActive)return _jwCutoverOriginalV3Fetch(path,method,body,raw);
  const headers={'Accept':'application/json'};
  if(method!=='GET'){
    headers['X-CSRF-Token']=_jwCutoverPgCsrf;
    headers['Content-Type']=raw?raw.type:'application/json';
  }
  let r;
  try{
    r=await fetch(_jwV3Base+path,{method,headers,credentials:'same-origin',cache:'no-store',
      ...(raw?{body:raw.bytes}:body!==null?{body:JSON.stringify(body)}:{})});
  }catch(e){
    const failure=new Error('서버에 연결할 수 없습니다. 저장 여부는 서버에서 다시 확인해 주세요.');
    failure.definitive=false;
    throw failure;
  }
  const data=await r.json().catch(()=>null);
  if(!r.ok){
    const failure=new Error(typeof data?.detail==='string'?data.detail:
                            'PostgreSQL 거래 요청 실패 ('+r.status+')');
    failure.status=r.status;
    failure.definitive=!(r.status===409||r.status>=500);
    throw failure;
  }
  return data;
};

function _jwCutoverProtectAggregateViews(){
  // All corporate totals must be source-proven, not silently mixed.
  // The normal transactional/document screens remain available.
  for(const name of ['home','stats','money','export','automation']){
    const previous=ROUTES[name];
    if(typeof previous!=='function'||previous._jwV223Guarded)continue;
    const guarded=function(...args){
      if(!_jwCutoverActive)return previous(...args);
      return h('section',{class:'view'},
        h('div',{class:'ph'},h('div',null,
          h('span',{class:'mono'},'DATA VERIFICATION'),
          h('h1',null,'통합 통계 검증 전'),
          h('p',null,'SQLite와 PostgreSQL의 통합 합계는 아직 실측 검증 전이므로 표시하지 않습니다.'))),
        h('div',{class:'card'},
          h('p',null,'기존 문서와 신규 거래는 출처를 구분하여 이용할 수 있습니다. 금액·효율·자동화 통계는 데이터 연결 전입니다.'),
          h('a',{class:'btn soft',href:'#/deals'},'거래 목록 열기'),
          h('a',{class:'btn ghost',href:'#/docs'},'문서 센터 열기')));
    };
    guarded._jwV223Guarded=true;
    ROUTES[name]=guarded;
  }
}

async function _jwCutoverCancelPartialLogin(){
  try{
    const headers={'X-CSRF-Token':_jwCsrf};
    if(_jwCutoverPgCsrf)headers['X-JW-PG-CSRF']=_jwCutoverPgCsrf;
    const r=await fetch('/api/logout',{method:'POST',credentials:'same-origin',
      cache:'no-store',headers});
    // Partial or failed revocation stays an error; never announce logout.
    return r.ok;
  }catch(e){return false}
}

login=async function(email,password,otp){
  const t=String(otp||'').trim();
  const payload={email,password,...(t?(t.length===32?{recovery_code:t}:{otp:t}):{})};
  _jwCutoverActive=false;
  _jwCutoverPgCsrf='';
  const first=await _jwCutoverOriginalRequest('/api/login','POST',payload);
  if(typeof first.csrf_token!=='string'||!first.csrf_token)
    throw new Error('SQLite 로그인 보안 토큰 검증 실패');
  _jwCsrf=first.csrf_token;
  _jwServerUser=await _jwCutoverOriginalRequest('/api/me');
  let status;
  try{
    const r=await fetch('/api/pg-stage/cutover/status',
      {credentials:'same-origin',cache:'no-store',headers:{'Accept':'application/json'}});
    status=r.status===404?{cutover_available:false,pg_required:false}:
      r.ok?await r.json():null;
  }catch(e){status=null}
  if(!status||typeof status.pg_required!=='boolean')
    throw new Error('기업 전환 상태를 확인할 수 없어 로그인을 중단했습니다.');
  if(status.cutover_available&&status.pg_required){
    try{
      const pg=await _jwCutoverHttp('/api/pg-stage/v85/login','POST',payload);
      if(typeof pg.csrf_token!=='string'||pg.csrf_token.length<16)
        throw new Error('PostgreSQL 보안 토큰 확인 실패');
      _jwCutoverPgCsrf=pg.csrf_token;
      const matched=await _jwCutoverHttp('/api/pg-stage/cutover/verify');
      if(matched.identity_verified!==true)throw new Error('기업·사용자 신원이 일치하지 않습니다.');
      _jwCutoverActive=true;
      _jwV3Active=false;
      _jwV3ProbeAt=0;
      _jwCutoverProtectAggregateViews();
    }catch(e){
      const revoked=await _jwCutoverCancelPartialLogin();
      _jwCutoverPgCsrf='';
      _jwServerUser=null;
      _jwCsrf='';
      if(!revoked)throw new Error('이중 인증 중단 후 세션 폐기를 확인하지 못했습니다. 두 저장소에서 다시 로그아웃해야 합니다.');
      throw e;
    }
  }
  try{
    _jwServerData=await _jwFetchSnapshot();
    _jwSeedReadOnly();
    restoreSession();
    return ME;
  }catch(e){
    await _jwCutoverCancelPartialLogin();
    _jwCutoverActive=false;
    _jwCutoverPgCsrf='';
    _jwServerUser=null;
    _jwServerData=null;
    _jwCsrf='';
    throw e;
  }
};

endSession=async function(reason){
  if(!_jwCutoverActive)return _jwCutoverOriginalEnd(reason);
  try{
    const r=await fetch('/api/logout',{
      method:'POST',credentials:'same-origin',cache:'no-store',
      headers:{'X-CSRF-Token':_jwCsrf,'X-JW-PG-CSRF':_jwCutoverPgCsrf,
               'Accept':'application/json'}});
    const data=await r.json().catch(()=>({}));
    if(r.status===409&&data.code==='partial_logout_legacy_pending'){
      // PG is confirmed revoked. Revoke remaining SQLite independently.
      _jwCutoverActive=false;
      _jwCutoverPgCsrf='';
      return await _jwCutoverOriginalEnd(reason);
    }
    if(!r.ok||data.ok!==true)
      throw new Error(typeof data.code==='string'?data.code:'이중 세션 종료 실패');
    _jwCutoverActive=false;
    _jwCutoverPgCsrf='';
    _jwServerUser=null;
    _jwServerData=null;
    _jwCsrf='';
    _jwV3Active=false;
    await _jwOriginalEndSession(reason);
  }catch(e){
    toast('서버 로그아웃에 실패했습니다: '+e.message,'bad');
  }
};
"""


def optional_bridge() -> str:
    """Enable only in an explicitly opted-in isolated non-production pilot."""
    return JS if (os.environ.get("JW_PG_CINEMA_CUTOVER_FRONT_V223")
                  == "ISOLATED_DEV_DUAL_SESSION_PILOT"
                  and os.environ.get("JW_ENV", "").lower() in {"dev", "development", "test"}
                  and os.environ.get("JW_INSECURE_LOCAL_DEV") != "1") else ""
