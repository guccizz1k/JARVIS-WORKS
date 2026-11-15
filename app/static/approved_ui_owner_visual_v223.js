/* Server-only owner-visual review bootstrap: NEVER starts original local store. */
(function(){
'use strict';
document.addEventListener('DOMContentLoaded',()=>{
  const root=document.body;
  if(root?.dataset.jwReviewMode!=='owner-visual')return;
  if(typeof window.JWOwnerServerBridge!=='function'||!window.JWOwnerServerUI||
      typeof window.JWOwnerServerUI.start!=='function'){
    root.replaceChildren(document.createTextNode('보호된 서버 검토 모듈을 불러오지 못했습니다.'));
    return;
  }
  window.JWOwnerServerUI.start();
},{once:true});
})();
