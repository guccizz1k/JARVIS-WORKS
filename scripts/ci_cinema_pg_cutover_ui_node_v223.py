#!/usr/bin/env python3
"""Run opt-in cutover CINEMA JavaScript behavior against a strict Node VM harness.

No browser or live endpoints are implied: synthetic request/response tests that
also verify status lookup, identity check, per-store CSRF and legacy-only scope.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from app.pg_cinema_cutover_ui_v223 import JS

HARNESS = r"""
'use strict';
const vm=require('node:vm');
const fs=require('node:fs');
const assert=require('node:assert/strict');
const source=fs.readFileSync(process.argv[2],'utf8');
let checks=0;
const pass=(condition,name)=>{checks++;assert.ok(condition,name); console.log('PASS_V223_UI_JS_'+name)};
const json=(value,status=200)=>({ok:status>=200&&status<300,status,json:async()=>value});

async function scenario(active,verifyOk=true){
  const called=[];
  const state={
    ME:null,_jwServerUser:null,_jwServerData:null,_jwCsrf:'',
    _jwV3Active:false,_jwV3ProbeAt:0,_jwV3Base:'/api/pg-stage/cinema-trade',
    toast:()=>{}, ROUTES:{home:()=>({original:'home'}),
      stats:()=>({original:'stats'}),money:()=>({original:'money'}),
      automation:()=>({original:'automation'}),export:()=>({original:'export'})},
    h:(tag,props,...children)=>({tag,props,children}),
    _jwRequest:async(path,method='GET',body=null)=>{
      called.push({path,method,body,original:true});
      if(path==='/api/login')return {csrf_token:'legacy-csrf-token'};
      if(path==='/api/me')return {org_id:'A',id:'actor',role:'admin'};
      if(path==='/api/quotes')return [{id:'sqlite-doc'}];
      if(path==='/api/logout')return {ok:true};
      throw Error('unrecognized original path: '+path);
    },
    _jwV3Fetch:async(path,method='GET',body=null)=>{
      called.push({path:'/api/pg-stage/cinema-trade'+path,method,original:true});
      return [];
    },
    _jwFetchSnapshot:async()=>({quotes:await state._jwRequest('/api/quotes')}),
    _jwSeedReadOnly:()=>{},
    restoreSession:()=>{state.ME={id:'actor'};return true},
    login:async()=>({}),
    logout:()=>{state.ME=null},
    _jwOriginalEndSession:async()=>{state.ME=null;called.push({path:'UI_CLEAR'})},
    endSession:async()=>{state.ME=null;called.push({path:'ORIGINAL_END'})},
    fetch:async(path,options={})=>{
      called.push({path,method:options.method||'GET',headers:options.headers||{},body:options.body||null});
      if(path==='/api/pg-stage/cutover/status')
        return json({cutover_available:true,pg_required:active});
      if(path==='/api/pg-stage/v85/login')return json({csrf_token:'pg-token-secret-12345678'});
      if(path==='/api/pg-stage/cutover/verify')
        return verifyOk?json({identity_verified:true}):json({code:'identity_mismatch'},403);
      if(path==='/api/pg-stage/cutover/legacy/quotes')return json([{id:'sqlite-doc'}]);
      if(path==='/api/quotes')return json({id:'pg-doc'});
      if(path==='/api/pg-stage/cinema-trade/partners')return json({id:'pg-ledger'});
      if(path==='/api/logout')return json({ok:true});
      throw Error('unrecognized fetch '+path);
    },
    console,
  };
  vm.createContext(state);
  vm.runInContext(source,state,{filename:'jw-v223-cutover-ui.js'});
  return {ctx:state,called};
}
(async()=>{
  const {ctx,called}=await scenario(true);
  const user=await ctx.login('ci@example.test','synthetic-password','123456');
  pass(user.id==='actor','DUAL_LOGIN_RETURNS_ACTOR');
  pass(called.some(x=>x.path==='/api/pg-stage/v85/login'&&x.method==='POST'),
       'DUAL_PG_LOGIN_ACTUALLY_SENT');
  pass(called.some(x=>x.path==='/api/pg-stage/cutover/verify'),'DUAL_IDENTITY_VERIFIED');
  pass(vm.runInContext('_jwCutoverActive',ctx)===true,'ACTIVE_ONLY_AFTER_IDENTITY');
  const rows=await ctx._jwRequest('/api/quotes');
  pass(rows.length===1&&rows[0].id==='sqlite-doc'&&
       called.some(x=>x.path==='/api/pg-stage/cutover/legacy/quotes'),
       'LEGACY_LIST_IS_EXPLICIT_AND_NOT_DUPLICATED');
  await ctx._jwRequest('/api/quotes','POST',{title:'PG'});
  const pgWrite=called.filter(x=>x.path==='/api/quotes'&&x.method==='POST').at(-1);
  pass(pgWrite.headers['X-CSRF-Token']==='legacy-csrf-token'&&
       pgWrite.headers['X-JW-PG-CSRF']==='pg-token-secret-12345678',
       'INDEPENDENT_CSRF_TOKENS_NOT_REUSED');
  await ctx._jwV3Fetch('/partners','POST',{request_id:'synthetic'});
  const trade=called.filter(x=>x.path==='/api/pg-stage/cinema-trade/partners'&&x.method==='POST').at(-1);
  pass(trade.headers['X-CSRF-Token']==='pg-token-secret-12345678',
       'NATIVE_TRADE_ONLY_USES_PG_CSRF');
  pass(ctx.ROUTES.stats().tag==='section'&&ctx.ROUTES.home().tag==='section',
       'UNVERIFIED_TOTALS_HIDDEN');
  await ctx.endSession('user');
  const logout=called.find(x=>x.path==='/api/logout'&&x.method==='POST'&&!x.original);
  pass(!!logout&&logout.headers['X-CSRF-Token']==='legacy-csrf-token'&&
       logout.headers['X-JW-PG-CSRF']==='pg-token-secret-12345678',
       'LOGOUT_REVOKES_TWO_STORES_WITH_TWO_TOKENS');
  pass(ctx.ME===null&&vm.runInContext('_jwCutoverActive',ctx)===false,'LOGOUT_CLEARS_BROWSER_STATE');

  const {ctx:disabled,called:disabledCalls}=await scenario(false);
  await disabled.login('ci@example.test','synthetic-password','123456');
  pass(!disabledCalls.some(x=>x.path==='/api/pg-stage/v85/login'),
       'FLAG_OFF_NEVER_CREATES_PG_LOGIN');
  pass(disabled.ROUTES.home().original==='home','FLAG_OFF_PRESERVES_ORIGINAL_HOME');

  const {ctx:bad,called:badCalls}=await scenario(true,false);
  let failure=false;
  try{await bad.login('ci@example.test','synthetic-password','123456')}catch(e){failure=true}
  pass(failure&&!vm.runInContext('_jwCutoverActive',bad),
       'MISMATCH_REJECTS_LOGIN');
  pass(badCalls.some(x=>x.path==='/api/logout'),'MISMATCH_ATTEMPTS_BOTH_REVOKE');

  console.log('PASS_V223_CINEMA_DUAL_UI_NODE checks='+checks+' failures=0 synthetic_only=true');
})().catch(e=>{console.error(e.stack||e);process.exitCode=1});
"""


def run() -> int:
    binary = shutil.which("node")
    if binary is None:
        raise SystemExit("BLOCKED: node runtime absent for mandatory UI logic validation")
    with tempfile.TemporaryDirectory(prefix="jw-v223-ui-node-") as d:
        base = Path(d)
        (base/"ui.js").write_text(JS, encoding="utf-8")
        (base/"harness.js").write_text(HARNESS, encoding="utf-8")
        check = subprocess.run([binary,"--check",str(base/"ui.js")],capture_output=True,text=True)
        if check.returncode:
            print(check.stderr)
            return check.returncode
        run = subprocess.run([binary,str(base/"harness.js"),str(base/"ui.js")],
                             capture_output=True,text=True)
        print(run.stdout,end="")
        if run.stderr:
            print(run.stderr)
        return run.returncode


if __name__=="__main__":
    raise SystemExit(run())
