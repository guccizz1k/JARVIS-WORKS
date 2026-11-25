'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
const bridgeSource=fs.readFileSync('app/static/approved_ui_server_bridge_v223.js','utf8');
const financeSource=fs.readFileSync('app/static/approved_ui_finance_review_v223.js','utf8');
const entry=fs.readFileSync('app/cinema_entry_v1.py','utf8');
const review=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),D='d'.repeat(32);
const ID={id:A,org_id:B,name:'QA',email:'qa@example.invalid',
  role:'admin',org_name:'QA',csrf_token:'z'.repeat(36)};
const payment={id:D,reference:'PAY-QA-2026',amount:1100,paid_at:'2026-11-16',
  note:'',reversed_at:null};
const invoice={id:C,org_id:B,order_id:D,customer_id:A,doc_no:'I-20261116-QA',
  due_date:'2099-12-31',money:{total:3300},paid:0,balance:3300,payments:[]};
const paid={...invoice,paid:1100,balance:2200,payments:[payment]};
const reconciled={has_invoice:true,invoice_money:{total:3300},order_money:{total:3300},
 quote_money:{total:3300},quote_to_order:[],order_to_invoice:[],review_state:'clean'};
function create(handler){
  const calls=[],ctx={window:{},location:{origin:'https://review.example.invalid',protocol:'https:'},
    fetch:async(url,opts)=>{
      const path=new URL(url).pathname;calls.push({path,opts});
      const body=await handler(path,opts,calls.length);
      const status=Number.isInteger(body?.http_status)?body.http_status:200;
      return {status,ok:status>=200&&status<300,
        headers:{get:key=>key==='content-type'?'application/json':null},
        json:async()=>body?.payload===undefined?body:body.payload};
    }};
  vm.runInNewContext(bridgeSource,ctx);
  return {bridge:new ctx.window.JWOwnerServerBridge(),calls};
}
const deny=(p,code)=>assert.rejects(p,{code});
test('finance module is included only in owner review, without browser ledger storage',()=>{
 assert.match(entry,/approved_ui_finance_review_v223\.js/);
 assert.match(review,/JWOwnerFinanceReview\.render/);
 assert.doesNotMatch(financeSource,/innerHTML|localStorage|indexedDB|sessionStorage|eval\(/);
 assert.match(financeSource,/textContent/);
});
test('invoice verification refuses cross-tenant and invalid money',async()=>{
 const x=create(p=>p==='/api/me'?ID:{...invoice,org_id:A});
 await x.bridge.restore();await deny(x.bridge.financeInvoice(C),'INVALID_FINANCIAL_RECEIPT');
 const y=create(p=>p==='/api/me'?ID:{...invoice,balance:-1});
 await y.bridge.restore();await deny(y.bridge.financeInvoice(C),'INVALID_FINANCIAL_RECEIPT');
});
test('reconciliation validates real invoice amount and source totals',async()=>{
 const x=create(p=>p==='/api/me'?ID:reconciled);
 await x.bridge.restore();const r=await x.bridge.financeReconcile(D,invoice);
 assert.equal(r.has_invoice,true);assert.equal(r.invoice_money.total,3300);
 assert.equal(x.calls.at(-1).path,'/api/reconciliation/'+D);
 const y=create(p=>p==='/api/me'?ID:{...reconciled,invoice_money:{total:1}});
 await y.bridge.restore();await deny(y.bridge.financeReconcile(D,invoice),'INVALID_RECONCILIATION');
});
test('partial payment includes CSRF, request reference, and server readback',async()=>{
 const x=create((p)=>p==='/api/me'?ID:
  p==='/api/invoices/'+C+'/payments'?paid:
  p==='/api/invoices/'+C?paid:null);
 await x.bridge.restore();
 const result=await x.bridge.financePay(C,invoice,payment.reference,1100,'2026-11-16');
 assert.equal(result.paid,1100);assert.equal(result.balance,2200);
 const req=x.calls.at(-2);
 assert.equal(req.path,'/api/invoices/'+C+'/payments');
 assert.equal(req.opts.credentials,'same-origin');
 assert.equal(req.opts.headers['X-CSRF-Token'],ID.csrf_token);
 assert.deepEqual(JSON.parse(req.opts.body),{reference:payment.reference,
   amount:1100,paid_at:'2026-11-16',note:''});
 assert.equal(x.calls.at(-1).path,'/api/invoices/'+C);
});
test('overpayment and invalid references are stopped before POST',async()=>{
 const x=create(p=>p==='/api/me'?ID:invoice);
 await x.bridge.restore();
 await deny(x.bridge.financePay(C,invoice,'short',100,'2026-11-16'),'INVALID_PAYMENT_INPUT');
 await deny(x.bridge.financePay(C,invoice,'PAY-OVER-0001',3301,'2026-11-16'),'INVALID_PAYMENT_INPUT');
 await deny(x.bridge.financePay(C,invoice,'PAY/SPACES',100,'2026-11-16'),'INVALID_PAYMENT_INPUT');
 assert.equal(x.calls.length,1);
});
test('idempotent retry reads existing payment, without posting again',async()=>{
 const full={...invoice,paid:3300,balance:0,payments:[{...payment,amount:3300}]};
 const x=create(p=>p==='/api/me'?ID:full);
 await x.bridge.restore();
 const result=await x.bridge.financePay(C,full,payment.reference,3300,'2026-11-16');
 assert.equal(result.paid,3300);assert.equal(x.calls.filter(x=>x.opts.method==='POST').length,0);
});
test('conflicting or reversed payment reference cannot be reused',async()=>{
 const x=create(p=>p==='/api/me'?ID:paid);
 await x.bridge.restore();
 await deny(x.bridge.financePay(C,paid,payment.reference,1200,'2026-11-16'),'PAYMENT_REFERENCE_CONFLICT');
 const reversed={...paid,payments:[{...payment,reversed_at:'2026-11-16T10:00:00+09:00'}]};
 await deny(x.bridge.financePay(C,reversed,payment.reference,1100,'2026-11-16'),'PAYMENT_REFERENCE_CONFLICT');
 assert.equal(x.calls.length,1);
});
test('administrator reversal requires explicit protected endpoint and readback',async()=>{
 const reversed={...invoice,payments:[{...payment,reversed_at:'2026-11-16T11:00:00+09:00'}]};
 const x=create(p=>p==='/api/me'?ID:reversed);
 await x.bridge.restore();
 const result=await x.bridge.financeReverse(C,paid,D);
 assert.equal(result.paid,0);assert.equal(result.balance,3300);
 const req=x.calls.at(-2);
 assert.equal(req.path,'/api/invoices/'+C+'/payments/'+D+'/reverse');
 assert.equal(req.opts.headers['X-CSRF-Token'],ID.csrf_token);
 assert.equal(x.calls.at(-1).path,'/api/invoices/'+C);
});
test('ordinary member cannot submit reversal',async()=>{
 const x=create(p=>p==='/api/me'?{...ID,role:'member'}:paid);
 await x.bridge.restore();
 await deny(x.bridge.financeReverse(C,paid,D),'ADMIN_ONLY');
 assert.equal(x.calls.length,1);
});
test('outdated invoice or missing payment cannot reverse',async()=>{
 const x=create(p=>p==='/api/me'?ID:invoice);
 await x.bridge.restore();
 await deny(x.bridge.financeReverse(C,invoice,D),'INVALID_PAYMENT_REVERSAL');
 await deny(x.bridge.financeReverse(C,{...paid,org_id:A},D),'INVALID_PAYMENT_REVERSAL');
 assert.equal(x.calls.length,1);
});
test('payment response from another tenant cannot show success',async()=>{
 const x=create(p=>p==='/api/me'?ID:{...paid,org_id:A});
 await x.bridge.restore();
 await deny(x.bridge.financePay(C,invoice,payment.reference,1100,'2026-11-16'),'INVALID_FINANCIAL_RECEIPT');
});
test('payment readback mismatch is blocked, never UI success',async()=>{
 const x=create(p=>p==='/api/me'?ID:
  p==='/api/invoices/'+C+'/payments'?paid:
  p==='/api/invoices/'+C?invoice:null);
 await x.bridge.restore();
 await deny(x.bridge.financePay(C,invoice,payment.reference,1100,'2026-11-16'),'PAYMENT_READBACK_MISMATCH');
});
test('delayed finance detail from old user never crosses sessions',async()=>{
 let release;const pending=new Promise(resolve=>release=resolve);let who=ID;
 const x=create(p=>p==='/api/me'?who:pending);
 await x.bridge.restore();
 const old=x.bridge.financeInvoice(C).then(()=>null,e=>e.code);
 who={...ID,id:D,org_id:A};await x.bridge.restore();
 release(invoice);
 assert.equal(await old,'STALE_SESSION');
});
