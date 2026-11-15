'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const ui=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const id='a'.repeat(32),statement='b'.repeat(32),csrf='t'.repeat(36);
const me={id:'user',org_id:'orgA',email:'a@example.invalid',name:'Tester',org_name:'Synthetic',role:'admin',csrf_token:csrf};
const timer={id,workflow:'trade_statement',mode:'manual',started_at:'2026-11-16T00:00:00+00:00'};
function make(resolver){
  const calls=[],ctx={window:{},location:{protocol:'https:',origin:'https://isolated.example.invalid'},fetch:async(url,options)=>{
    calls.push({url,options});const payload=url.endsWith('/api/me')?me:resolver(new URL(url).pathname,options);
    const [data,status]=Array.isArray(payload)&&payload.length===2&&typeof payload[1]==='number'?payload:[payload,200];
    return {ok:status>=200&&status<300,status,headers:{get:k=>k==='content-type'?'application/json':null},json:async()=>data};
  }};
  vm.runInNewContext(source,ctx);return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
test('active timer is restored from server after auth, no browser local evidence',async()=>{
 const {bridge,calls}=make((path)=>path.endsWith('/active')?timer:null);
 await bridge.restore();const d=await bridge.activeTiming();
 assert.equal(d.id,id);assert.equal(d.mode,'manual');assert.equal(calls.at(-1).options.method,'GET');
});
test('null active timer is accepted',async()=>{
 const {bridge}=make(()=>null);await bridge.restore();assert.equal(await bridge.activeTiming(),null);
});
test('timer start writes server workflow/mode with CSRF',async()=>{
 const {bridge,calls}=make(()=>({id,workflow:'trade_statement',mode:'manual',status:'running'}));
 await bridge.restore();const d=await bridge.startTiming('manual');
 assert.equal(d.id,id);assert.equal(calls.at(-1).options.method,'POST');
 assert.equal(calls.at(-1).options.headers['X-CSRF-Token'],csrf);
 assert.deepEqual(JSON.parse(calls.at(-1).options.body),{workflow:'trade_statement',mode:'manual'});
});
test('timer rejects unapproved mode before network',async()=>{
 const {bridge,calls}=make(()=>null);await bridge.restore();
 await assert.rejects(()=>bridge.startTiming('auto_fake'),{code:'INVALID_TIMER_MODE'});
 assert.equal(calls.length,1);
});
test('manual completion validates actual server elapsed and provenance',async()=>{
 const {bridge}=make((p)=>p.endsWith('/active')?timer:
 ({id,mode:'manual',workflow:'trade_statement',elapsed_ms:7231,status:'completed',measurement:'server_elapsed_time',task_outcome:'self_reported_completion'}));
 await bridge.restore();const d=await bridge.finishTiming(id);
 assert.equal(d.elapsed_ms,7231);
});
test('manual cannot misattribute an auto document',async()=>{
 const {bridge,calls}=make(p=>p.endsWith('/active')?timer:null);await bridge.restore();
 await assert.rejects(()=>bridge.finishTiming(id,statement),{code:'MANUAL_CANNOT_LINK_DOCUMENT'});
 assert.equal(calls.length,2);
});
test('auto finish requires a fresh statement id',async()=>{
 const {bridge}=make(p=>p.endsWith('/active')?{...timer,mode:'automated'}:null);
 await bridge.restore();
 await assert.rejects(()=>bridge.finishTiming(id),{code:'AUTOMATED_REQUIRES_NEW_STATEMENT'});
});
test('auto completion validates linked document outcome',async()=>{
 const {bridge,calls}=make(p=>p.endsWith('/active')?{...timer,mode:'automated'}:
 ({id,mode:'automated',workflow:'trade_statement',elapsed_ms:402,status:'completed',measurement:'server_elapsed_time',task_outcome:'linked_document'}));
 await bridge.restore();const result=await bridge.finishTiming(id,statement);
 assert.equal(result.elapsed_ms,402);assert.equal(JSON.parse(calls.at(-1).options.body).statement_id,statement);
});
test('oversized or negative duration refused',async()=>{
 for(const ms of [-1,1800001]){
  const {bridge}=make(p=>p.endsWith('/active')?timer:
   ({id,mode:'manual',workflow:'trade_statement',elapsed_ms:ms,status:'completed',measurement:'server_elapsed_time',task_outcome:'self_reported_completion'}));
  await bridge.restore();await assert.rejects(()=>bridge.finishTiming(id),{code:'INVALID_TIMER_COMPLETION'});
 }
});
test('cancel calls only own active run and excludes metrics',async()=>{
 const {bridge,calls}=make(p=>p.endsWith('/active')?timer:
 ({id,status:'cancelled',excluded_from_metrics:true}));
 await bridge.restore();const d=await bridge.cancelTiming(id);assert.equal(d.excluded_from_metrics,true);
 assert.equal(calls.at(-1).options.headers['X-CSRF-Token'],csrf);
});
test('cancel does not trust fake server exclusion response',async()=>{
 const {bridge}=make(p=>p.endsWith('/active')?timer:({id,status:'cancelled',excluded_from_metrics:false}));
 await bridge.restore();await assert.rejects(()=>bridge.cancelTiming(id),{code:'INVALID_TIMER_CANCEL'});
});
test('forged run id is blocked before request',async()=>{
 const {bridge,calls}=make(()=>null);await bridge.restore();
 await assert.rejects(()=>bridge.cancelTiming('../leak'),{code:'INVALID_TIMER_ID'});assert.equal(calls.length,1);
});
test('no browser-based time calculations or storage fallback',()=>{
 assert.match(ui,/await bridge\.startTiming\(mode\)/);
 assert.match(ui,/await bridge\.activeTiming\(\)/);
 assert.match(ui,/await bridge\.finishTiming\(running.id,created.id\)/);
 assert.match(ui,/await bridge\.cancelTiming\(running.id\)/);
 assert.match(ui,/window\.confirm\('실제 수작업/);
 assert.doesNotMatch(ui,/localStorage|indexedDB|sessionStorage|innerHTML|eval\(/);
 const timerSection=ui.split('// Measurements are created by server timers only.')[1]
    ?.split("            const orders=await bridge.list('orders');")[0];
 assert.ok(timerSection,'timer UI section must exist');
 assert.doesNotMatch(timerSection,/Date\\.now\\(\\)/);
});

test('confirmed manual completion status must be shown after timer rerender',()=>{
 const finishSection=ui.split('const done=await bridge.finishTiming(active.id);')[1]
   ?.split('}catch(e)')[0];
 assert.ok(finishSection,'manual finish UI handler exists');
 const refreshAt=finishSection.indexOf('await renderTimer();');
 const confirmedAt=finishSection.indexOf("timerState.textContent='수작업 서버 측정 완료");
 assert.ok(refreshAt>=0 && confirmedAt>refreshAt,
   'server completion confirmation must survive active timer refresh');
 assert.match(finishSection,/setAttribute\('role','status'\)/);
});

test('rapid start-to-finish transition releases the action lock before exposing finish button',()=>{
 const startHandler=ui.split('await bridge.startTiming(mode);')[1]?.split('}catch(e)')[0];
 assert.ok(startHandler,'timing start click handler not found');
 const unlocked=startHandler.indexOf('measuring=false;');
 const rendered=startHandler.indexOf('await renderTimer()');
 assert.ok(unlocked>=0&&rendered>unlocked,'new finish/cancel button cannot appear while start lock is active');
});
