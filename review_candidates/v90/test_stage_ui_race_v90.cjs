'use strict';
// Node contract test: exercise the unchanged browser send/close functions in a VM.
// No browser network access is required or attempted.
const fs=require('node:fs');
const vm=require('node:vm');
const assert=require('node:assert/strict');
const {test}=require('node:test');
const html=fs.readFileSync(__dirname+'/messenger_stage_v90.html','utf8');
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const expression=script.match(/const send=async\(\)=>\{[\s\S]*?\n \};/);
assert(expression,'send handler missing');
const fnSrc=expression[0].replace(/^const send=/,'send=');

function env(readfile,request){
 const els={message:{value:'hello'}, send:{disabled:false},fileInput:{value:'x'},fileInfo:{textContent:'attached'}};
 const st={chat:'chat-A-B',nonce:1,file:{name:'proof.txt',type:'text/plain'},pending:null,socket:{readyState:1}};
 const signals=[];
 const sandbox={st, API:'/api/pg-stage/v90', el:id=>els[id], readfile,request,crypto:{randomUUID:()=>'request-identity-123'},WebSocket:{OPEN:1},msg:x=>signals.push(x),sync:async()=>{throw Error('unnecessary sync')}};
 const send=vm.runInNewContext('let send; '+fnSrc+'\n send',sandbox);
 return {send,st,els,signals};
}
const defer=()=>{let resolve;const promise=new Promise(r=>resolve=r);return {promise,resolve}};

test('changing company during file read cannot send to the new company', async()=>{
 let calls=0;const wait=defer();const x=env(()=>wait.promise,async()=>{calls++});
 const task=x.send();
 x.st.chat='chat-A-C';x.st.nonce=2;
 wait.resolve('cHJvb2Y=');await task;
 assert.equal(calls,0);
});

test('switching chats during HTTP reply cannot wipe next chat message draft',async()=>{
 const response=defer();const sent=[];
 const x=env(async()=> 'cHJvb2Y=',(...params)=>{sent.push(params);return response.promise});
 const task=x.send();
 for(let n=0;n<10 && sent.length===0;n++)await Promise.resolve();
 assert.equal(sent.length,1,JSON.stringify({signals:x.signals,pending:x.st.pending}));
 assert.match(sent[0][0],/chat-A-B/);
 x.st.chat='chat-A-C';x.st.nonce=2;x.st.pending=null;x.els.message.value='C new draft';
 response.resolve({message_id:'ok'});await task;
 assert.equal(x.els.message.value,'C new draft');
 assert.equal(x.st.chat,'chat-A-C');
});

test('policy denial 1008 must not trigger reconnection retry',()=>{
 const line=script.split('\n').find(l=>l.includes('sock.onclose=event=>'));
 assert(line, 'onclose handler missing');
 const sock={},st={nonce:12,attempt:0},labels=[],notices=[];
 let retryCount=0;
 const sandbox={sock,st,local:12,connected:s=>labels.push(s),msg:s=>notices.push(s),setTimeout:()=>retryCount++,join:()=>retryCount++};
 vm.runInNewContext(line,sandbox);
 sock.onclose({code:1008});
 assert.equal(retryCount,0);
 assert.match(labels[0],/접근 차단/);
 sock.onclose({code:1006});
 assert.equal(retryCount,1);
});
