'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {test}=require('node:test');
const html=fs.readFileSync(__dirname+'/messenger_stage_v90.html','utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const expression=script.match(/const send=async\(\)=>\{[\s\S]*?\n \};/);
assert(expression,'send handler missing');
const fnSrc=expression[0].replace(/^const send=/,'send=');
function deferred(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject};}
function env(readfile,request){
 const els={message:{value:'hello'},send:{disabled:false},fileInput:{value:'new'},fileInfo:{textContent:'attached'}};
 const st={chat:'chat-A-B',nonce:1,orgId:'A',file:{name:'proof.txt',type:'text/plain'},pending:null,socket:{readyState:1},sending:null};
 let next=0;
 const sandbox={st,API:'/api/pg-stage/v90',el:id=>els[id],readfile,request,crypto:{randomUUID:()=> 'request-unique-'+(++next)},WebSocket:{OPEN:1},msg:()=>{},sync:async()=>{throw Error('unexpected sync')}};
 return {st,els,send:vm.runInNewContext('let send; '+fnSrc+'\nsend',sandbox),getCalls:()=>next};
}

test('rapid Enter while file read pending submits one HTTP message',async()=>{
 const gate=deferred();let calls=0;
 const x=env(()=>gate.promise,async()=>{calls++;return {}});
 const a=x.send(),b=x.send(),c=x.send();
 gate.resolve('ZGF0YQ==');await Promise.all([a,b,c]);
 assert.equal(calls,1,'duplicate send reached HTTP');
 assert.equal(x.getCalls(),1,'retry key unexpectedly regenerated');
});

test('edits typed while pending response are preserved',async()=>{
 const gate=deferred(),payload=[];
 const x=env(async()=> 'ZGF0YQ==',async(path,opts)=>{payload.push(JSON.parse(opts.body));return gate.promise});
 const a=x.send();for(let i=0;i<30 && !payload.length;i++)await Promise.resolve();
 assert.equal(payload.length,1);
 x.els.message.value='new draft written while sending';
 gate.resolve({message_id:'ok'});await a;
 assert.equal(x.els.message.value,'new draft written while sending');
});

test('new file selected during old response is not cleared',async()=>{
 const gate=deferred(),payload=[];
 const x=env(async()=> 'ZGF0YQ==',async(path,opts)=>{payload.push(JSON.parse(opts.body));return gate.promise});
 const a=x.send();for(let i=0;i<30 && !payload.length;i++)await Promise.resolve();
 const replacement={name:'fresh.pdf',type:'application/pdf'};
 x.st.file=replacement;x.st.pending=null;x.els.fileInfo.textContent='attached fresh.pdf';x.els.fileInput.value='fresh';
 gate.resolve({message_id:'ok'});await a;
 assert.equal(x.st.file,replacement);
 assert.equal(x.els.fileInfo.textContent,'attached fresh.pdf');
});

test('failure retry reuses request ID and clears only after eventual success',async()=>{
 let calls=0;const keys=[];
 const x=env(async()=> 'ZGF0YQ==',async(path,opts)=>{calls++;keys.push(JSON.parse(opts.body).request_id);if(calls===1)throw Error('network');return {}});
 await x.send(); assert(x.st.pending,'lost idempotent retry');
 await x.send();
 assert.equal(calls,2);assert.deepEqual(keys,[keys[0],keys[0]]);
 assert.equal(x.st.pending,null);
 assert.equal(x.els.message.value,'');
});

test('pending failed send is replayed unchanged even after draft edit',async()=>{
 const sent=[];
 const x=env(async()=> 'ZGF0YQ==',async(path,opts)=>{
  sent.push(JSON.parse(opts.body));
  if(sent.length===1)throw Error('timeout');
  return {message_id:'ok'};
 });
 await x.send();assert.equal(sent.length,1);
 x.els.message.value='draft after timeout';
 await x.send();
 assert.equal(sent.length,2);
 assert.deepEqual(sent[0],sent[1]);
 assert.equal(x.els.message.value,'draft after timeout');
});

test('old send finalizer cannot unlock the new chat sending ticket',async()=>{
 const old=deferred(),next=deferred(),sent=[];
 const x=env(async()=> 'ZGF0YQ==',async(path,opts)=>{
  sent.push(path);
  return sent.length===1?old.promise:next.promise;
 });
 const first=x.send();for(let i=0;i<20&&sent.length<1;i++)await Promise.resolve();
 x.st.chat='chat-A-C';x.st.nonce=2;x.st.sending=null;x.st.pending=null;
 x.st.file=null;x.els.message.value='second chat draft';
 const second=x.send();for(let i=0;i<20&&sent.length<2;i++)await Promise.resolve();
 assert.equal(sent.length,2);
 assert.match(sent[1],/chat-A-C/);
 const ticket=x.st.sending;
 old.resolve({});await first;
 assert.equal(x.st.sending,ticket,'old send cleared active ticket');
 assert.equal(x.els.message.value,'second chat draft');
 next.resolve({});await second;
 assert.equal(x.st.sending,null);
});
