/* Isolated owner review: edit only tenant-owned DRAFT quotations.
 * All content is DOM text; no generic writes, browser persistence or automatic mutations.
 */
(function(g){
'use strict';
const el=(tag,cls,value)=>{const n=document.createElement(tag);if(cls)n.className=cls;
  if(value!==undefined)n.textContent=String(value);return n};
const why=e=>e?.code==='STALE_VERSION'?
  '다른 사용자가 견적서를 변경했거나 상태를 확정했습니다. 다시 조회하세요.':
  e?.code==='STALE_SESSION'?'로그인 계정이 변경되어 과거 응답을 무시했습니다.':
  e?.code==='TENANT_MISMATCH'?'기업별 접근 권한 검증에 실패했습니다.':
  '견적서 수정 또는 서버 검증에 실패했습니다. 다시 조회하세요.';
const appendLabel=(root,label,control)=>{
  const w=el('label','jw-review-action-label',label);
  control.setAttribute('aria-label',label);w.append(control);root.append(w);return control;
};
const button=(label,cls='jw-review-action-button')=>{
  const n=el('button',cls,label);n.type='button';return n;
};
async function render({bridge,view,isCurrent}){
  const who=bridge?.identity;
  if(!who||!view||typeof isCurrent!=='function')throw Error('QUOTE_REVIEW_CONTEXT_REQUIRED');
  const alive=()=>isCurrent()&&bridge.signedIn&&bridge.identity?.id===who.id&&
    bridge.identity?.org_id===who.org_id;
  const card=el('section','jw-review-card');
  card.append(el('h3','jw-review-cardtitle','견적 초안 수정 · 서버 원본 검증'));
  const status=el('p','jw-review-muted','서버 초안 조회 중');
  status.setAttribute('role','status');card.append(status);view.append(card);
  try{
    const [quotes,customers]=await Promise.all([bridge.list('quotes'),bridge.list('customers')]);
    if(!alive())return;
    const drafts=quotes.filter(q=>q.status==='draft');
    if(!drafts.length){status.textContent='수정 가능한 초안 견적서가 없습니다.';return;}
    for(const q of drafts.slice(0,30)){
      const edit=button(q.doc_no+' · 초안 수정');
      card.append(edit);
      edit.onclick=async()=>{
        if(!alive()||edit.disabled)return;
        edit.disabled=true;
        const wrap=el('section','jw-review-card');
        wrap.append(el('h4','jw-review-cardtitle',q.doc_no+' · 수정 대상 초안'));
        const feedback=el('p','jw-review-muted','원본을 서버에서 다시 확인 중');
        feedback.setAttribute('role','status');wrap.append(feedback);
        card.append(wrap);
        try{
          let context=await bridge.quoteEditContext(q.id);
          if(!alive())return;
          const quote=context.quote;
          const customer=customers.find(x=>x.id===quote.customer_id);
          if(!customer||customer.org_id!==who.org_id)throw Error('INVALID_CUSTOMER');
          const form=el('form','jw-review-action-form');
          const customerInput=el('select','jw-review-input');
          for(const item of customers){
            if(item.org_id!==who.org_id)throw Error('TENANT_MISMATCH');
            const opt=el('option','',item.name);opt.value=item.id;customerInput.append(opt);
          }
          customerInput.value=quote.customer_id;
          appendLabel(form,'거래처',customerInput);
          const title=el('input','jw-review-input');title.type='text';title.maxLength=150;
          title.required=true;title.value=quote.title;appendLabel(form,'견적 제목',title);
          const vat=el('select','jw-review-input');
          for(const [value,label] of [['taxable','과세'],['exempt','면세']]){
            const opt=el('option','',label);opt.value=value;vat.append(opt);
          }
          vat.value=quote.vat_mode;appendLabel(form,'부가세 유형',vat);
          const rows=el('div','jw-review-quote-items');form.append(rows);
          const fields=[];
          function addLine(item={name:'',quantity:1,unit_price:0}){
            if(fields.length>=100)return;
            const block=el('div','jw-review-row');
            const name=el('input','jw-review-input');name.type='text';name.maxLength=150;
            name.required=true;name.value=item.name;
            appendLabel(block,'품목명',name);
            const qty=el('input','jw-review-input');qty.type='number';qty.min='1';
            qty.max='100000';qty.step='1';qty.required=true;qty.value=String(item.quantity);
            appendLabel(block,'수량',qty);
            const price=el('input','jw-review-input');price.type='number';
            price.min='0';price.max='1000000000';price.step='1';price.required=true;
            price.value=String(item.unit_price);appendLabel(block,'단가(원)',price);
            const remove=button('품목 삭제');
            remove.onclick=()=>{
              if(fields.length<=1){feedback.textContent='품목은 최소 1개가 필요합니다.';return}
              const i=fields.findIndex(x=>x.block===block);
              if(i>=0){fields.splice(i,1);block.remove()}
            };
            block.append(remove);fields.push({block,name,qty,price});rows.append(block);
          }
          quote.items.forEach(addLine);
          const add=button('품목 추가');add.onclick=()=>addLine();form.append(add);
          const submit=el('button','jw-review-button','견적 초안 저장');
          submit.type='submit';form.append(submit);
          form.addEventListener('submit',async event=>{
            event.preventDefault();
            if(!alive()||submit.disabled)return;
            const data={
              customer_id:customerInput.value,title:title.value.trim(),vat_mode:vat.value,
              items:fields.map(x=>({name:x.name.value.trim(),
                quantity:Number(x.qty.value),unit_price:Number(x.price.value)}))
            };
            submit.disabled=true;feedback.textContent='변경사항 저장 및 원본 재조회 중';
            try{
              const result=await bridge.quoteEditSave(q.id,context.fingerprint,data);
              const fresh=await bridge.quoteEditContext(q.id);
              if(!alive())return;
              const same=(a,b)=>a.customer_id===b.customer_id&&a.title===b.title&&
                a.vat_mode===b.vat_mode&&a.items.length===b.items.length&&
                a.items.every((x,i)=>x.name===b.items[i].name&&
                  x.quantity===b.items[i].quantity&&x.unit_price===b.items[i].unit_price);
              if(fresh.fingerprint!==result.fingerprint||
                !same(data,fresh.quote))throw Error('READBACK_MISMATCH');
              context=fresh;
              feedback.textContent='견적 초안을 서버에 저장하고 재조회했습니다. 합계 '+
                fresh.quote.money.total.toLocaleString('ko-KR')+'원';
              feedback.setAttribute('role','status');
            }catch(error){
              if(alive()){feedback.textContent=why(error);feedback.setAttribute('role','alert')}
            }finally{submit.disabled=false}
          });
          wrap.append(form);
          feedback.textContent='초안 원본 검증 완료 · 확정 견적은 수정할 수 없습니다.';
        }catch(error){
          if(alive()){feedback.textContent=why(error);feedback.setAttribute('role','alert')}
        }finally{edit.disabled=false}
      };
    }
    status.textContent='수정 가능한 초안 '+drafts.length+'건 · 저장 직전 문서 스냅샷을 대조합니다.';
  }catch(error){
    if(alive()){status.textContent=why(error);status.setAttribute('role','alert')}
  }
}
g.JWOwnerQuoteEdit={render};
if(typeof module==='object'&&module.exports)module.exports={render};
})(typeof window==='object'?window:globalThis);
