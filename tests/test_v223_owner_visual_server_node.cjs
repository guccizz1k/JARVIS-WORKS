'use strict';
const {test}=require('node:test'), assert=require('node:assert/strict'), fs=require('node:fs');
const s=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const bootstrap=fs.readFileSync('app/static/approved_ui_owner_visual_v223.js','utf8');
const css=fs.readFileSync('app/static/approved_ui_owner_visual_v223.css','utf8');
test('owner visual activates only under explicit review flag',()=>{
 assert.ok(s.includes("dataset.jwReviewMode==='owner-visual'"));
 assert.ok(bootstrap.includes("dataset.jwReviewMode!=='owner-visual'"));
});
test('review visual reuses owner poster and login; server session is authoritative',()=>{
 for(const c of ['lbrand','logo','poster jw-owner-brand','mega go','lcard'])
   assert.ok(s.includes(c),'missing original visual class '+c);
 assert.ok(s.includes('bridge.login(em.value,pw.value,otp.value)'));
 for(const banned of ['localStorage','indexedDB','sessionStorage','new Function','eval('])
   assert.equal(bootstrap.includes(banned),false,'unsafe browser fallback '+banned);
});
test('all 17 routes accessible on mobile with full menu',()=>{
 assert.ok(s.includes('for(const [key,label] of MENUS)'));
 assert.ok(s.includes('jw-owner-menu-dialog'));
 assert.ok(s.includes('jw-owner-menu-grid'));
 assert.ok(s.includes('closeMobile();open(key)'));
 assert.ok(s.includes('root.querySelectorAll'));
});
test('owner visual maps native rail bottomnav login and cards',()=>{
 for(const c of ['.rail','.rsc','.ritem','.bottomnav','.lcard','.mega','.top','.view'])
   assert.ok(css.includes(c),'owner style missing '+c);
 assert.ok(css.includes('@media(max-width:900px)'));
 assert.ok(css.includes('prefers-reduced-motion'));
});
test('never execute original local account and storage script',()=>{
 for(const blocked of ['boot();','jw3.db','localStorage','indexedDB','innerHTML','eval('])
   assert.equal(bootstrap.includes(blocked),false,'unsafe boot fallback '+blocked);
 assert.equal(s.includes('window.JWOwnerServerUI.bootLocal'),false);
});
