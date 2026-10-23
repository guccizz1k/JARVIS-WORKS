/* V6.5: conservative matching and explicit evidence-source linkage. UI-only helper. */
'use strict';
let jwV65CandidateResults = [];
function evidenceV65Html(){
 const q=state.reconciliationQueueV65||{items:[],unlinked:0,linked_with_issues:0};
 const labels={needs_review:'대조 필요',linked:'연결 완료',linked_with_issues:'불일치 기록됨',unsupported_source_direction:'수동 검토 대상'};
 return `<section class="panel" style="margin-top:16px"><div class="panel-header"><h2>거래 정보 자동 대조 (V6.5)</h2><span class="badge orange">미연결 ${e(q.unlinked)}건 · 불일치 기록 ${e(q.linked_with_issues)}건</span></div><div class="panel-body"><p class="muted">검토를 마친 매출전표·거래명세표를 내부 견적·발주·청구 데이터와 대조합니다. 금액이 같다는 이유만으로 자동 연결하지 않습니다.</p>${(q.items||[]).slice(0,30).map(r=>`<div class="jw-v62-result"><span>${e(r.counterparty)} · ${e(r.reference_number||'번호 없음')} · ${r.gross_amount===null?'금액 없음':krw(r.gross_amount)} · ${e(labels[r.status]||r.status)}</span>${r.status==='needs_review'?`<button class="btn small ghost" type="button" data-v68-lines="${e(r.id)}">품목 검토</button><button class="btn small ghost" type="button" data-v65-check="${e(r.id)}">대조 후보 보기</button>`:r.link_id?`<button class="btn small ghost" type="button" data-v65-detail="${e(r.id)}">대조 기록</button>`:''}<button class="btn small ghost" type="button" data-v68-review="${e(r.id)}">검토 이력</button></div>`).join('')||'<p class="muted">등록된 증빙 기록이 없습니다.</p>'}<p class="muted">매입·경비·재고는 내부 매출 거래에 강제로 연결하지 않습니다. 연결해도 공식 회계·결제·재고 수치는 변경되지 않습니다.</p></div></section>`;
}
function jwV65SelectCandidate(i){
 const x=jwV65CandidateResults[i];if(!x)return;
 const issues=x.issues||[];
 const area=document.querySelector('#jw-v65-selected');if(!area)return;
 area.innerHTML=`<form id="jw-v65-link-form"><p><b>${e(x.source_type)} · ${e(x.source_no)}</b> · ${e(x.customer)} · ${krw(x.expected_amount)}</p><p class="muted">${issues.length?'불일치 항목: '+issues.map(y=>`${e(y.field)} (${e(y.expected)} ≠ ${e(y.actual)})`).join(' · '):'대조 필드 일치 — 하지만 실제 거래 사실은 담당자가 확인해야 합니다.'}</p>${issues.length?'<label>불일치 확인 사유 (12자 이상)<textarea name="reason" required minlength="12" maxlength="400" rows="3" placeholder="원본 문서와 거래 자료를 비교한 결과를 작성하세요"></textarea></label>':''}<label class="import-confirm"><input name="ack" type="checkbox" required> 원본 증빙과 내부 거래 기록, 불일치 항목을 직접 확인했습니다.</label><button class="btn primary" type="submit">검토 후 이 거래와 연결</button></form>`;
 area.querySelector('#jw-v65-link-form').dataset.candidate=String(i);
}
function jwV65CandidateModal(rid,docs){
 jwV65CandidateResults=docs.candidates||[];
 const html=docs.supported?`<div class="notice warning">이 목록은 후보일 뿐입니다. 원본 증빙은 서버에 저장되지 않으므로 담당자가 원본 파일과 확인해야 합니다. 자동 승인·매출 전표 생성은 수행하지 않습니다.</div>${jwV65CandidateResults.slice(0,15).map((x,i)=>`<div class="jw-v62-result"><span>${e(x.source_type)} · ${e(x.source_no)} · ${e(x.customer)} · ${krw(x.expected_amount)} · ${x.issues.length?`불일치 ${x.issues.length}개`:'필드 일치'}</span><button class="btn small ghost" type="button" data-v65-select="${i}">확인</button></div>`).join('')||'<p class="muted">거래처나 참조번호가 일치하는 거래가 없습니다. 금액만 같은 건 연결 후보로 보지 않습니다.</p>'}<div id="jw-v65-selected"></div>`:`<p class="muted">${e(docs.reason||'이 증빙은 현재 자동 대조를 지원하지 않습니다.')}</p>`;
 modal('증빙 · 내부 거래 대조',`<div id="jw-v65-record" data-rid="${e(rid)}">${html}</div>`,'대조 결과는 내부 검토용이며 공식 회계처리가 아닙니다.');
}
document.addEventListener('click',async ev=>{
 const check=ev.target.closest('[data-v65-check]'),detail=ev.target.closest('[data-v65-detail]'),choose=ev.target.closest('[data-v65-select]');
 try{
  if(check){check.disabled=true;const rid=check.dataset.v65Check;const rows=await api('/evidence/records/'+encodeURIComponent(rid)+'/candidates');jwV65CandidateModal(rid,rows);}
  else if(detail){detail.disabled=true;const data=await api('/evidence/records/'+encodeURIComponent(detail.dataset.v65Detail)+'/reconciliation');modal('거래 대조 기록',`<p>연결: ${e(data.source_type)} · ${e(data.current_comparison?.source_no||'')}</p><p>최초 불일치: ${e((data.issues_at_link||[]).map(x=>x.field).join(', ')||'없음')}</p><p>확인 사유: ${e(data.discrepancy_reason||'없음')}</p><p>${data.source_changed?'내부 원본 거래가 연결 당시와 달라졌습니다. 다시 확인하세요.':'내부 원본 거래의 대조값은 연결 당시와 같습니다.'}</p>`,'연결 기록은 수정할 수 없습니다.');}
  else if(choose){jwV65SelectCandidate(Number(choose.dataset.v65Select));}
 }catch(err){toast(err.message,true)}finally{if(check?.isConnected)check.disabled=false;if(detail?.isConnected)detail.disabled=false;}
});
document.addEventListener('submit',async ev=>{
 if(ev.target.id!=='jw-v65-link-form')return;
 ev.preventDefault();const form=ev.target,selected=jwV65CandidateResults[Number(form.dataset.candidate)];
 if(!selected||!form.elements.ack?.checked)return toast('원본 확인 동의가 필요합니다',true);
 const rid=document.querySelector('#jw-v65-record')?.dataset.rid;if(!rid)return;
 const button=form.querySelector('button[type=submit]');button.disabled=true;
 try{
  const r=await api('/evidence/records/'+encodeURIComponent(rid)+'/reconcile-link','POST',{
   source_type:selected.source_type,source_id:selected.source_id,
   comparison_digest:selected.comparison_digest,
   original_and_differences_checked:true,discrepancy_reason:form.elements.reason?.value||''
  });closeModal();await navigate('imports');toast(r.issues.length?'불일치 항목을 남기고 연결했습니다':'대조 기록이 연결됐습니다');
 }catch(err){toast(err.message,true)}finally{if(button.isConnected)button.disabled=false;}
});
