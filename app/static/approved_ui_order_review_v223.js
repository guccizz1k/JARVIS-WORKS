/* Owner-reviewed order change + explicit administrator acknowledgement.
 * Server CAS and original quote differences are authoritative.
 * No browser persistence, HTML injection, automatic approval, or ledger mutation.
 */
(function(g){
'use strict';
const node=(tag,cls,txt)=>{const e=document.createElement(tag);
  if(cls)e.className=cls;if(txt!==undefined)e.textContent=String(txt);return e};
const label=(container,text,control)=>{const x=node('label','jw-review-action-label',text);
  control.setAttribute('aria-label',text);x.append(control);container.append(x);return control};
const btn=(text,css='jw-review-action-button')=>{const x=node('button',css,text);x.type='button';return x};
const why=e=>e?.code==='STALE_VERSION'?
  '다른 창에서 수주나 승인 상태가 변경됐습니다. 최신 원본을 다시 조회하세요.':
  e?.code==='ADMIN_ONLY'?'변경 내역을 확인하려면 관리자 권한이 필요합니다.':
  e?.code==='STALE_SESSION'?'계정이 전환되어 이전 작업의 결과를 폐기했습니다.':
  '수주 검토가 완료되지 않았습니다. 서버 상태를 다시 확인하세요.';
async function render({bridge,view,isCurrent}){
  const who=bridge?.identity;
  if(!who||!bridge.signedIn||!view||typeof isCurrent!=='function')
    throw Error('ORDER_REVIEW_CONTEXT_REQUIRED');
  const valid=()=>isCurrent()&&bridge.signedIn&&bridge.identity?.id===who.id&&
    bridge.identity?.org_id===who.org_id;
  const section=node('section','jw-review-order-panel');
  section.append(node('h3','jw-review-cardtitle','수주 변경·원본 대조·관리자 확인'));
  const status=node('p','jw-review-muted','서버에서 수주를 조회하고 있습니다.');
  status.setAttribute('role','status');section.append(status);view.append(section);
  try{
    const orders=await bridge.list('orders');
    if(!valid())return;
    const active=orders.filter(x=>['received','processing'].includes(x.status));
    if(!active.length){status.textContent='검토 가능한 진행 중 수주가 없습니다.';return;}
    for(const order of active.slice(0,30)){
      if(order.org_id!==who.org_id)throw Error('TENANT_MISMATCH');
      const open=btn(order.doc_no+' · 변경·검토');
      section.append(open);
      open.onclick=async()=>{
        if(!valid()||open.disabled)return;
        open.disabled=true;
        const detail=node('section','jw-review-card');
        const feedback=node('p','jw-review-muted','원본 수주·견적·변경 이력 조회 중');
        feedback.setAttribute('role','status');
        detail.append(node('h4','jw-review-cardtitle',order.doc_no+' · 수주 검토'),feedback);
        section.append(detail);
        try{
          let context=await bridge.orderReviewContext(order.id);
          if(!valid())return;
          const form=node('form','jw-review-action-form');
          const deadline=node('input','jw-review-input');deadline.type='date';
          deadline.required=true;deadline.value=context.order.due_date;
          label(form,'납기일',deadline);
          const reason=node('textarea','jw-review-input');reason.required=true;
          reason.maxLength=500;reason.minLength=5;reason.rows=2;
          label(form,'수주 변경 사유 (5자 이상)',reason);
          const rows=node('div','jw-review-order-items');form.append(rows);
          const inputs=[];
          function addLine(item={source_quote_item_id:null,name:'',quantity:1,unit_price:0}){
            if(inputs.length>=100)return;
            const block=node('div','jw-review-row');
            const source=node('select','jw-review-input');
            const extra=node('option','','견적 외 추가 품목');extra.value='';source.append(extra);
            for(const quoteItem of context.order.quote_items){
              const option=node('option','',quoteItem.name+' · 원본 '+quoteItem.quantity+'개');
              option.value=quoteItem.id;source.append(option);
            }
            source.value=item.source_quote_item_id||'';
            label(block,'원본 견적 품목 연결',source);
            const name=node('input','jw-review-input');name.type='text';
            name.maxLength=150;name.required=true;name.value=item.name;
            label(block,'품목명',name);
            const qty=node('input','jw-review-input');qty.type='number';qty.required=true;
            qty.min='1';qty.max='100000';qty.step='1';qty.value=String(item.quantity);
            label(block,'수량',qty);
            const price=node('input','jw-review-input');price.type='number';price.required=true;
            price.min='0';price.max='1000000000';price.step='1';price.value=String(item.unit_price);
            label(block,'단가(원)',price);
            const remove=btn('품목 삭제');
            remove.onclick=()=>{if(inputs.length<=1){feedback.textContent='품목을 최소 1개 유지해야 합니다.';return}
              const index=inputs.findIndex(x=>x.block===block);
              if(index>=0){inputs.splice(index,1);block.remove()}};
            block.append(remove);
            rows.append(block);inputs.push({block,source,name,qty,price});
          }
          context.order.items.forEach(addLine);
          const add=btn('품목 추가');add.onclick=()=>addLine();form.append(add);
          const save=node('button','jw-review-button','수주 변경 저장');save.type='submit';
          form.append(save);detail.append(form);
          const review=node('section','jw-review-order-differences');detail.append(review);
          const renderReview=()=>{
            review.replaceChildren();
            const current=context.order;
            review.append(node('h4','jw-review-cardtitle',
              '수주 검토 상태: '+current.review_state));
            if(current.differences.length){
              for(const difference of current.differences.slice(0,100)){
                review.append(node('p','jw-review-row',
                  [difference.item,difference.field,'원본 '+String(difference.expected),
                   '변경 '+String(difference.actual)].join(' · ')));
              }
            }else review.append(node('p','jw-review-muted','원본 견적과 차이가 없습니다.'));
            if(current.review_state==='pending'){
              if(who.role!=='admin'){
                review.append(node('p','jw-review-muted','관리자 확인이 완료되어야 납품 완료 처리할 수 있습니다.'));
                return;
              }
              const acknowledge=btn('변경사항 확인·승인');
              acknowledge.onclick=async()=>{
                if(!valid()||acknowledge.disabled)return;
                if(!window.confirm('서버 원본과 수주 변경 항목을 대조한 뒤 승인하시겠습니까?'))return;
                acknowledge.disabled=true;feedback.textContent='변경 내역 서버 재검증 중';
                try{
                  const receipt=await bridge.orderReviewAcknowledge(order.id,context.fingerprint);
                  const latest=await bridge.orderReviewContext(order.id);
                  if(!valid())return;
                  if(latest.fingerprint!==receipt.fingerprint||
                     latest.order.review_state!=='acknowledged')
                    throw Error('ACK_READBACK_MISMATCH');
                  context=latest;renderReview();
                  feedback.textContent='관리자 변경 확인·서버 재조회 완료';
                  feedback.setAttribute('role','status');
                }catch(e){
                  if(valid()){feedback.textContent=why(e);feedback.setAttribute('role','alert')}
                }finally{acknowledge.disabled=false}
              };
              review.append(acknowledge);
            }
          };
          renderReview();
          form.addEventListener('submit',async event=>{
            event.preventDefault();
            if(!valid()||save.disabled)return;
            if(!window.confirm('수주 변경 내역을 저장하면 원본 견적 차이에 따라 관리자 확인이 필요할 수 있습니다. 계속하시겠습니까?'))return;
            save.disabled=true;feedback.textContent='수주 변경사항 서버 원본 비교 중';
            try{
              const payload={due_date:deadline.value,change_reason:reason.value.trim(),
                items:inputs.map(x=>({source_quote_item_id:x.source.value||null,
                  name:x.name.value.trim(),quantity:Number(x.qty.value),
                  unit_price:Number(x.price.value)}))};
              const saved=await bridge.orderReviewSave(order.id,context.fingerprint,payload);
              const readback=await bridge.orderReviewContext(order.id);
              if(!valid())return;
              const matches=readback.fingerprint===saved.fingerprint&&
                readback.order.due_date===payload.due_date&&
                readback.order.items.length===payload.items.length&&
                readback.order.items.every((x,i)=>x.name===payload.items[i].name&&
                  x.quantity===payload.items[i].quantity&&
                  x.unit_price===payload.items[i].unit_price&&
                  x.source_quote_item_id===payload.items[i].source_quote_item_id);
              if(!matches)throw Error('ORDER_READBACK_MISMATCH');
              context=readback;renderReview();
              feedback.textContent='수주 변경 서버 저장·재조회 완료 · 검토 상태 '+
                context.order.review_state;
              feedback.setAttribute('role','status');
            }catch(e){if(valid()){feedback.textContent=why(e);feedback.setAttribute('role','alert')}}
            finally{save.disabled=false}
          });
          feedback.textContent='수주 원본·견적 품목·변경 항목 대조 완료';
        }catch(e){if(valid()){feedback.textContent=why(e);feedback.setAttribute('role','alert')}}
        finally{open.disabled=false}
      };
    }
    status.textContent='진행 중 수주 '+active.length+'건 · 변경 승인 전에는 납품 완료할 수 없습니다.';
  }catch(e){if(valid()){status.textContent=why(e);status.setAttribute('role','alert')}}
}
g.JWOwnerOrderReview={render};
if(typeof module==='object'&&module.exports)module.exports={render};
})(typeof window==='object'?window:globalThis);
