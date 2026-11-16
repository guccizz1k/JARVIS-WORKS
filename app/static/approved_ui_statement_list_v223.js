/* V22.3 owner-approved trade document review: immutable server snapshots only. */
(function(g){
'use strict';
const el=(tag,cls,value)=>{const n=document.createElement(tag);if(cls)n.className=cls;if(value!==undefined)n.textContent=String(value);return n};
const same=(a,b)=>Boolean(a&&b&&a.id===b.id&&a.org_id===b.org_id);
async function render({bridge,view,isCurrent}){
  if(!bridge||!view||typeof isCurrent!=='function')throw Error('INVALID_REVIEW_CONTEXT');
  const user=bridge.identity;
  if(!user||!bridge.signedIn)throw Error('LOGIN_REQUIRED');
  const valid=()=>isCurrent()&&bridge.signedIn&&same(user,bridge.identity);
  const box=el('section','jw-review-card'),heading=el('h3','jw-review-cardtitle','확정 거래명세표 · 서버 원본');
  const status=el('p','jw-review-muted','원본 문서를 서버에서 확인 중');status.setAttribute('role','status');
  const list=el('div','jw-review-statement-list'),detail=el('section','jw-review-card');
  box.append(heading,status,list);view.append(box,detail);
  try{
    const statements=await bridge.statementList();
    if(!valid())return;
    if(!statements.length){status.textContent='확정된 거래명세표가 없습니다. 납품 완료 수주에서 자동화 메뉴로 생성하세요.';return;}
    status.textContent='확정 문서 '+statements.length+'건 · 법적 세금계산서가 아닌 내부 거래 문서입니다.';
    for(const record of statements){
      const btn=el('button','jw-review-action-button',record.doc_no+' · '+record.created_at);
      btn.type='button';
      btn.onclick=async()=>{
        if(!valid()||btn.disabled)return;
        btn.disabled=true;
        detail.replaceChildren(el('p','jw-review-muted','서버 원본 재조회 중'));
        try{
          const verified=await bridge.statementDetail(record.id,record.order_id);
          if(!valid())return;
          if(verified.doc_no!==record.doc_no||
            verified.document?.legal_status!=='internal_business_record_not_tax_invoice'||
            verified.document?.document_type!=='trade_statement'||
            verified.document?.finalized!==true||
            !Number.isSafeInteger(verified.document?.money?.total))
            throw Error('INVALID_IMMUTABLE_STATEMENT');
          const doc=verified.document;
          detail.replaceChildren(el('h3','jw-review-cardtitle',verified.doc_no),
            el('p','jw-review-muted','확정된 내부 거래명세표 · 세금계산서 아님'));
          for(const [title,value] of [['원본 수주번호',doc.source_order_no],
            ['거래처',doc.customer_name],['문서명',doc.title],
            ['금액',String(doc.money.total)+'원']]){
            detail.append(el('div','jw-review-row',title+' · '+(value||'자료 없음')));
          }
          if(!Array.isArray(doc.items)||doc.items.length>100)throw Error('INVALID_IMMUTABLE_ITEMS');
          for(const item of doc.items)detail.append(el('div','jw-review-row',
            String(item.name)+' · '+item.quantity+'개 · '+item.line_total+'원'));
        }catch(e){
          if(valid()){detail.replaceChildren(el('p','jw-review-failure',
            '서버 문서 원본이 일치하지 않아 상세 조회를 차단했습니다.'))}
        }finally{btn.disabled=false}
      };
      list.append(btn);
    }
  }catch(e){
    if(valid()){status.textContent='서버 문서 목록을 검증하지 못했습니다.';status.setAttribute('role','alert')}
  }
}
g.JWOwnerStatements={render};
if(typeof module==='object'&&module.exports)module.exports={render};
})(typeof window==='object'?window:globalThis);
