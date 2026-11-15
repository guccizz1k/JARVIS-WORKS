'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs');
const s=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const bootstrap=fs.readFileSync('app/static/approved_ui_owner_visual_v223.js','utf8');
const css=fs.readFileSync('app/static/approved_ui_owner_visual_v223.css','utf8');
test('owner visual is disabled outside explicit flag',()=>{
 assert.match(s,/dataset\.jwReviewMode==='owner-visual'/);
 assert.match(bootstrap,/data(set)?\.jwReviewMode/);
});
test('owner visual renders native poster and login card, NOT browser local login',()=>{
 for(const c of ['lbrand','logo','poster jw-owner-brand','mega go','lcard','go'])
   assert.ok(s.includes(c),'missing owner visual class '+c);
 assert.ok(s.includes("bridge.login(em.value,pw.value,otp.value)"));
 assert.doesNotMatch(bootstrap,/localStorage|indexedDB|sessionStorage|new Function|eval\\(/);
});
test('all 17 routes remain available on mobile and desktop',()=>{
 assert.match(s,/for\\(const \\[key,label\\] of MENUS\\)/);
 assert.match(s,/jw-owner-mobile-menu|jw-owner-menu-dialog/);
 assert.match(s,/jw-owner-menu-grid/);
 assert.match(s,/btn\\.onclick=\\(\\)=>\\{closeMobile\\(\\);open\\(key\\)\\}/);
});
test('desktop owner source rail & mobile bottom nav assets styled',()=>{
 for(const key of ['.rail','.rsc','.ritem','.bottomnav','.lcard','.mega','.top','.view'])
   assert.ok(css.includes(key),'owner class not mapped '+key);
 assert.ok(css.includes('@media(max-width:900px)'));
 assert.ok(css.includes('prefers-reduced-motion'));
});
test('no imported original local DB scripts or unsafe HTML insertion',()=>{
 assert.doesNotMatch(bootstrap,/\\bboot\\s*\\(|localStorage|indexedDB|innerHTML|eval\\(/);
 assert.doesNotMatch(s,/window\\.JWOwnerServerUI\\.bootLocal/);
});
