'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const staffUI=fs.readFileSync('app/static/approved_ui_operational_v223.js','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32);
const me={id:A,org_id:B,email:'admin@example.invalid',name:'Admin',org_name:'Test',
          role:'admin',csrf_token:'z'.repeat(36)};
function make(resolver){
 const calls=[],ctx={window:{},location:{origin:'https://review.example.invalid',protocol:'https:'},
 fetch:async(url,opts)=>{
   const path=new URL(url).pathname;calls.push({path,opts});
   const reply=resolver(path,opts);
   const status=typeof reply?.httpStatus==='number'?reply.httpStatus:200;
   return{status,ok:status>=200&&status<300,headers:{get:k=>k==='content-type'?'application/json':null},
     json:async()=>reply?.payload??reply};
 }};
 vm.runInNewContext(source,ctx);return{bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const deny=(p,code)=>assert.rejects(p,{code});
test('admin role change uses owner-scoped allowlisted POST and CSRF',async()=>{
 const a=make(path=>path==='/api/me'?me:{ok:true,user_id:C,role:'admin',sessions_revoked:true});
 await a.bridge.restore();
 const result=await a.bridge.securityChangeStaffRole(C,'member','admin','test-admin-password');
 assert.equal(result.role,'admin');
 const sent=a.calls.at(-1);
 assert.equal(sent.path,'/api/account/staff/'+C+'/role');
 assert.equal(sent.opts.method,'POST');
 assert.equal(sent.opts.headers['X-CSRF-Token'],me.csrf_token);
 assert.equal(JSON.parse(sent.opts.body).expected_role,'member');
 assert.equal(JSON.parse(sent.opts.body).target_role,'admin');
});
test('member cannot invoke high-impact role change',async()=>{
 const a=make(path=>path==='/api/me'?{...me,role:'member'}:null);
 await a.bridge.restore();
 await deny(a.bridge.securityChangeStaffRole(C,'member','admin','password'),'ADMIN_ONLY');
 assert.equal(a.calls.length,1);
});
test('self role change rejected before reaching server',async()=>{
 const a=make(path=>path==='/api/me'?me:null);
 await a.bridge.restore();
 await deny(a.bridge.securityChangeStaffRole(A,'admin','member','password'),'INVALID_STAFF_ACTION');
 assert.equal(a.calls.length,1);
});
test('invalid role and missing reauthentication rejected',async()=>{
 const a=make(path=>path==='/api/me'?me:null);
 await a.bridge.restore();
 await deny(a.bridge.securityChangeStaffRole(C,'member','owner','password'),'INVALID_STAFF_ACTION');
 await deny(a.bridge.securityChangeStaffRole(C,'member','admin',''),'INVALID_STAFF_ACTION');
 assert.equal(a.calls.length,1);
});
test('server must confirm matching target and requested role',async()=>{
 const a=make(path=>path==='/api/me'?me:{ok:true,user_id:A,role:'admin',sessions_revoked:true});
 await a.bridge.restore();
 await deny(a.bridge.securityChangeStaffRole(C,'member','admin','password'),'INVALID_STAFF_RESPONSE');
});
test('role changes in staff review require explicit consent and readback',()=>{
 assert.ok(staffUI.includes('securityChangeStaffRole(person.id'));
 assert.ok(staffUI.includes("window.confirm('직원 권한 변경"));
 assert.ok(staffUI.includes('await display();status.textContent'));
 assert.doesNotMatch(staffUI,/localStorage|innerHTML|eval\(/);
});
