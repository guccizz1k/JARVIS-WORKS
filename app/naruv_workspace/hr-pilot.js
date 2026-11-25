(()=>{'use strict';
const $=id=>document.getElementById(id),root='/api/naruv-review/v1',worker='/hr/workers/pilot-ui',period=worker+'/periods/2026-06';
const buttons=['register','create','attendance','review','confirm','pay','archive'].map($);
let digest=null,epoch=0,busy=false,controller=null;
function reset(message='업무를 선택하세요.'){epoch++;if(controller)controller.abort();controller=null;busy=false;digest=null;$('approve').checked=false;$('result').replaceChildren();$('status').textContent=message;buttons.forEach(b=>b.disabled=false)}
function row(k,v){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=k;dd.textContent=String(v);$('result').append(dt,dd)}
async function json(path,opts,signal){const r=await fetch(path,{...opts,signal,credentials:'same-origin',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer'});if(!r.ok||!(r.headers.get('content-type')||'').startsWith('application/json'))throw Error('REQUEST');return r.json()}
async function run(kind,path,body,write){
 if(busy)return;
 if(innerWidth<1100||document.hidden||location.protocol!=='https:')return reset('PC HTTPS 환경이 필요합니다.');
 if(write&&!$('approve').checked){$('status').textContent='변경 확인을 선택하세요.';return}
 const old=digest;digest=null;$('approve').checked=false;$('result').replaceChildren();busy=true;const e=++epoch;controller=new AbortController();const signal=controller.signal;buttons.forEach(b=>b.disabled=true);$('status').textContent='처리 중…';
 const timeout=setTimeout(()=>{if(e===epoch)reset('응답 미확인 · 동일 작업 재조회 또는 재시도 필요')},15000);
 try{
  const me=await json('/api/pg-stage/v90/me',{method:'GET'},signal);if(e!==epoch)return;
  if(typeof me.csrf_token!=='string'||me.csrf_token.length<16||me.csrf_token.length>512)throw Error('SESSION');
  const headers={'X-JW-PG-CSRF':me.csrf_token};if(write)headers['X-Naruv-Confirm']='yes';
  if(kind==='confirm'){if(!old||!(/^[0-9a-f]{64}$/).test(old))throw Error('REVIEW');body={review_sha256:old}}
  if(body!==undefined)headers['Content-Type']='application/json';
  const d=await json(root+path,{method:'POST',headers,...(body===undefined?{}:{body:JSON.stringify(body)})},signal);if(e!==epoch)return;
  if(!d||typeof d!=='object'||d.payment_authorized!==false)throw Error('RESPONSE');
  if(kind==='review'){if(typeof d.review_sha256!=='string'||!(/^[0-9a-f]{64}$/).test(d.review_sha256))throw Error('REVIEW');digest=d.review_sha256;row('검토 지문',digest)}
  if(kind==='pay'){if(d.statutory_validated!==false||!Number.isSafeInteger(d.gross_krw)||d.gross_krw<0)throw Error('PAY');row('세전 급여 초안',d.gross_krw.toLocaleString('ko-KR')+' 원')}
  row('결과','가상 업무 처리 완료');row('실제 지급','불가');$('status').textContent='처리 완료';
 }catch{if(e===epoch)reset('처리 실패 · 최신 상태를 다시 확인하세요.')}
 finally{clearTimeout(timeout);if(e===epoch){busy=false;controller=null;buttons.forEach(b=>b.disabled=false)}}
}
$('register').onclick=()=>run('register',worker+'/register/pilot-ui-register',undefined,true);
$('create').onclick=()=>run('create',period+'/create/pilot-ui-policy',{revision:'pilot-ui-v1',hourly_krw:12000,additional_bps:15000},true);
$('attendance').onclick=()=>run('attendance',period+'/attendance/pilot-ui-att',{date:'2026-06-01',regular:60,additional:60},true);
$('review').onclick=()=>run('review',period+'/review',undefined,false);
$('confirm').onclick=()=>run('confirm',period+'/confirm/pilot-ui-confirm',undefined,true);
$('pay').onclick=()=>run('pay','/drafts/payroll/pilot-ui/2026-06',undefined,false);
$('archive').onclick=()=>run('archive',worker+'/archive/pilot-ui-archive',undefined,true);
$('clear').onclick=()=>reset();window.addEventListener('pagehide',()=>reset());document.addEventListener('visibilitychange',()=>{if(document.hidden)reset()});window.addEventListener('resize',()=>{if(innerWidth<1100)reset()});
})();
