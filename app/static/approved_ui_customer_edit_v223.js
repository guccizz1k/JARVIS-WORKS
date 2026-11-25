/* Owner-approved isolated customer editor: tenant, version snapshot and readback.
   No local storage, arbitrary writes, HTML interpolation or background mutations. */
(function(g){
'use strict';
const FIELDS=[['name','거래처명',120],['business_number','사업자번호',20],
  ['contact_name','담당자',100],['email','이메일',255],['phone','전화번호',30]];
const el=(tag,klass,text)=>{const node=document.createElement(tag);
  if(klass)node.className=klass;if(text!==undefined)node.textContent=String(text);return node};
const errorText=e=>e?.code==='STALE_VERSION'?
  '다른 사용자가 거래처를 변경했습니다. 화면을 다시 열어 최신 자료를 확인하세요.':
  e?.code==='STALE_SESSION'?'계정이 바뀌어 결과를 반영하지 않았습니다.':
  e?.code==='TENANT_MISMATCH'?'다른 기업 데이터가 확인되어 변경을 차단했습니다.':
  '거래처를 수정하지 못했습니다. 서버 데이터를 다시 확인하세요.';
async function render({bridge,view,isCurrent}){
  if(!view||typeof isCurrent!=='function')throw Error('INVALID_CUSTOMER_EDITOR_CONTEXT');
  const user=bridge?.identity;
  if(!user||!bridge.signedIn)throw Error('LOGIN_REQUIRED');
  const alive=()=>isCurrent()&&bridge.signedIn&&bridge.identity?.id===user.id&&
    bridge.identity?.org_id===user.org_id;
  const box=el('section','jw-review-customer-edits');
  box.append(el('h3','jw-review-cardtitle','거래처 정보 수정 · 서버 원본 비교'));
  const note=el('p','jw-review-muted','서버 원본 5개 필드를 변경 직전에 비교합니다.');
  note.setAttribute('role','status');box.append(note);view.append(box);
  try{
    const records=await bridge.list('customers');
    if(!alive())return;
    if(!records.length){note.textContent='수정 가능한 거래처가 없습니다.';return;}
    for(const original of records.slice(0,30)){
      if(original.org_id!==user.org_id||typeof original.id!=='string')throw Error('TENANT_MISMATCH');
      const toggle=el('button','jw-review-action-button',original.name+' · 수정');
      toggle.type='button';box.append(toggle);
      const form=el('form','jw-review-action-form');form.hidden=true;
      const controls={};
      for(const [key,label,max] of FIELDS){
        const wrapper=el('label','jw-review-action-label',label);
        const input=el('input','jw-review-input');
        input.name=key;input.value=original[key]||'';
        input.maxLength=max;input.type=key==='email'?'email':'text';
        input.setAttribute('aria-label',label);input.required=key==='name';
        wrapper.append(input);form.append(wrapper);controls[key]=input;
      }
      const submit=el('button','jw-review-button','변경사항 저장');submit.type='submit';
      const feedback=el('p','jw-review-muted','변경 요청 전');
      feedback.setAttribute('role','status');form.append(submit,feedback);box.append(form);
      toggle.onclick=()=>{if(alive())form.hidden=!form.hidden};
      form.addEventListener('submit',async event=>{
        event.preventDefault();
        if(!alive()||submit.disabled)return;
        submit.disabled=true;feedback.textContent='서버 수정 후 재조회 확인 중';
        try{
          const updated=Object.fromEntries(FIELDS.map(([key])=>[key,controls[key].value.trim()]));
          const saved=await bridge.customerEdit(original.id,original,updated);
          const refreshed=await bridge.list('customers');
          if(!alive())return;
          const check=refreshed.find(x=>x.id===original.id);
          if(!check||check.org_id!==user.org_id||
            FIELDS.some(([key])=>check[key]!==saved[key]))throw Error('READBACK_MISMATCH');
          for(const [key] of FIELDS){original[key]=check[key];controls[key].value=check[key]}
          toggle.textContent=check.name+' · 수정';
          feedback.textContent='서버 저장 및 재조회 완료';
          feedback.setAttribute('role','status');
        }catch(e){
          if(alive()){
            feedback.textContent=errorText(e);
            feedback.setAttribute('role','alert');
          }
        }finally{submit.disabled=false}
      });
    }
  }catch(e){
    if(alive()){note.textContent=errorText(e);note.setAttribute('role','alert')}
  }
}
g.JWOwnerCustomerEdit={render};
if(typeof module==='object'&&module.exports)module.exports={render};
})(typeof window==='object'?window:globalThis);
