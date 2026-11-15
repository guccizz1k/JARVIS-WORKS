'use strict';
const {test}=require('node:test'), assert=require('node:assert/strict'),fs=require('node:fs');
const src=fs.readFileSync('app/static/approved_ui_owner_gl_v223.js','utf8');
const ui=fs.readFileSync('app/static/approved_ui_server_review_v223.js','utf8');
const bootstrap=fs.readFileSync('app/static/approved_ui_owner_visual_v223.js','utf8');
test('original WebGL engine copied and no local data dependencies',()=>{
 assert.ok(src.includes('const GL=(()=>{'));
 assert.ok(src.includes('uniform mat4 uVP'));
 for(const banned of ['localStorage','sessionStorage','indexedDB','DB.','fetch(','document.cookie'])
   assert.equal(src.includes(banned),false,banned);
});
test('GL is disabled on reduced motion or save-data and safely falls back',()=>{
 assert.ok(src.includes("prefers-reduced-motion: reduce"));
 assert.ok(src.includes("saveData===true"));
 assert.ok(src.includes("if(!canvas||skip())"));
 assert.ok(src.includes("GL.onSlow=()=>"));
 assert.ok(src.includes('GL.init(canvas)'));
});
test('server shell starts original visual engine only when review UI is active',()=>{
 assert.ok(bootstrap.includes('window.JWOwnerVisualGL?.mount()'));
 assert.ok(ui.includes("window.JWOwnerVisualGL?.setMode('login')"));
 assert.ok(ui.includes("window.JWOwnerVisualGL?.setMode('home')"));
 assert.ok(ui.includes("window.JWOwnerVisualGL?.setMode(key==='home'?'home':'away')"));
});
