(()=>{'use strict';
const $=id=>document.getElementById(id),root='/api/naruv-review/v1';
const ids=/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/,period=/^[0-9]{4}-(0[1-9]|1[0-2])$/;
const buttons=['overview','staff','pay','document'].map($);
let epoch=0,controller=null;
function clear(message='조회 항목을 선택하세요.'){
  epoch++;if(controller)controller.abort();controller=null;
  $('result').replaceChildren();$('status').textContent=message;buttons.forEach(b=>b.disabled=false);
}
function row(label,value){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=label;dd.textContent=String(value);$('result').append(dt,dd)}
function number(v){if(typeof v!=='string'||!/^\d{1,30}$/.test(v))throw Error('INVALID_RESPONSE');return BigInt(v).toLocaleString('ko-KR')+' 원'}
function integer(v){if(!Number.isSafeInteger(v)||v<0)throw Error('INVALID_RESPONSE');return v.toLocaleString('ko-KR')}
function render(kind,d){
  if(!d||typeof d!=='object')throw Error('INVALID_RESPONSE');
  if(kind==='overview'){
    if(d.scope!=='ISOLATED_SYNTHETIC_ONLY')throw Error('INVALID_RESPONSE');
    row('매출 미수금',number(d.receivable_krw));row('매입 미지급금',number(d.payable_krw));row('진행 거래',integer(d.open_trade_count));row('품목',integer(d.item_count));
  }else if(kind==='staff'){
    if(!Array.isArray(d.workers)||d.workers.length>50||d.production_authorized!==false)throw Error('INVALID_RESPONSE');
    for(const w of d.workers){if(!ids.test(w.worker_id)||typeof w.active!=='boolean')throw Error('INVALID_RESPONSE');row(w.worker_id,w.active?'활성':'비활성')}
    row('조회 범위',d.next_after?'최대 50명 · 추가 목록 있음':'현재 페이지 전체');
  }else if(kind==='pay'){
    if(d.status!=='SYNTHETIC_GROSS_DRAFT'||d.statutory_validated!==false||d.payment_authorized!==false)throw Error('INVALID_RESPONSE');
    row('세전 급여 초안',integer(d.gross_krw)+' 원');row('기본 근무 (분)',integer(d.regular_minutes));row('추가 근무 (분)',integer(d.additional_minutes));row('법정 검증','미완료 · 지급 불가');
  }else{
    if(d.posting_authorized!==false||d.requires_human_review!==true||!Array.isArray(d.issues)||d.issues.length>40)throw Error('INVALID_RESPONSE');
    if(!d.issues.every(x=>typeof x==='string'&&/^[A-Z_]+$/.test(x)))throw Error('INVALID_RESPONSE');
    row('확인된 필드',integer(d.field_count));row('검토 상태',d.issues.length?'수동 정정 필요':'원본 검토 필요');row('검토 항목',d.issues.join(', ')||'없음');row('자동 등록','불가');
  }
}
async function json(path,opts,signal){
  const r=await fetch(path,{...opts,signal,credentials:'same-origin',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'});
  if(!r.ok)throw Error('HTTP_'+r.status);
  if(!(r.headers.get('content-type')||'').startsWith('application/json'))throw Error('INVALID_RESPONSE');
  return await r.json();
}
async function load(kind,path,body){
  clear('조회 중…');if(innerWidth<1100||document.hidden||location.protocol!=='https:')return clear('PC HTTPS 환경이 필요합니다.');
  const e=epoch;controller=new AbortController();const signal=controller.signal;buttons.forEach(b=>b.disabled=true);
  const timer=setTimeout(()=>{if(e===epoch)clear('조회 시간이 초과되었습니다. 다시 시도하세요.')},12000);
  try{
    const me=await json('/api/pg-stage/v90/me',{method:'GET'},signal);
    if(e!==epoch)return;
    if(typeof me.csrf_token!=='string'||me.csrf_token.length<16||me.csrf_token.length>512)throw Error('SESSION');
    const headers={'X-JW-PG-CSRF':me.csrf_token};
    if(body!==undefined)headers['Content-Type']='application/json';
    const d=await json(root+path,{method:'POST',headers,...(body===undefined?{}:{body:JSON.stringify(body)})},signal);
    if(e!==epoch)return;
    render(kind,d);$('status').textContent='조회 완료';
  }catch{if(e===epoch)clear('조회 실패 · 두 시스템의 로그인과 권한을 확인하세요.')}
  finally{clearTimeout(timer);if(e===epoch){controller=null;buttons.forEach(b=>b.disabled=false)}}
}
$('overview').onclick=()=>load('overview','/valuation/overview');
$('staff').onclick=()=>load('staff','/hr/workers/list',{limit:50});
$('pay').onclick=()=>{const w=$('worker').value,p=$('period').value;if(!ids.test(w)||!period.test(p))return clear('직원과 급여 기간을 확인하세요.');load('pay','/drafts/payroll/'+encodeURIComponent(w)+'/'+p)};
$('document').onclick=()=>{const d=$('doc').value;if(!ids.test(d))return clear('문서 식별번호를 확인하세요.');load('document','/drafts/documents/'+encodeURIComponent(d))};
$('clear').onclick=()=>clear();window.addEventListener('pagehide',()=>clear());document.addEventListener('visibilitychange',()=>{if(document.hidden)clear()});window.addEventListener('resize',()=>{if(innerWidth<1100)clear()});
})();
