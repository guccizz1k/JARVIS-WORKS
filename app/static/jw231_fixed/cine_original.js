/* JARVIS NEXUS — cinematic depth layer (v3.1)
   Adds parallax depth, orbit rings, light, bokeh and DOF on top of the existing UI.
   Pure canvas/DOM overlay: no business logic, no network. Safe to remove (delete this <script>). */
(function(){
'use strict';
var CUT=new URL('./assets/sculpt_cut.webp',import.meta.url).href;
var GRAIN=new URL('./assets/grain128.png',import.meta.url).href;
var META={w:2044,h:1104,m:80,r:101};   // cut-out size, transparent margin, tube half-thickness (px)
var doc=document,body=doc.body;
var $=function(s){return doc.querySelector(s)};
var clamp=function(x,a,b){return Math.min(b==null?1:b,Math.max(a==null?0:a,x))};
var lerp=function(a,b,t){return a+(b-a)*t};
var ease=function(t){t=clamp(t);return t<.5?4*t*t*t:1-Math.pow(-2*t+2,3)/2};
var easeOut=function(t){return 1-Math.pow(1-clamp(t),3)};
function rng(seed){var s=seed>>>0;return function(){s=(s*1664525+1013904223)>>>0;return s/4294967296}}

var img=new Image(),imgOK=false;img.onload=function(){imgOK=true;prep()};img.src=CUT;
var DPR=Math.min(window.devicePixelRatio||1,2),LEVEL=0; // LEVEL 0 full, 1 no blur filters, 2 minimal
if(typeof window.JW_CINE_LEVEL==='number')LEVEL=window.JW_CINE_LEVEL;
function mk(id,z){var c=doc.createElement('canvas');c.id=id;c.setAttribute('aria-hidden','true');c.style.cssText='position:fixed;left:0;top:0;width:100vw;height:100vh;z-index:'+z+';pointer-events:none';body.appendChild(c);return c}
var back=mk('jw-back',1),front=mk('jw-front',5);
var bx=back.getContext('2d'),fx=front.getContext('2d');
var bars=doc.createElement('div');bars.id='jw-bars';bars.innerHTML='<i></i><i></i>';body.appendChild(bars);
var sc=doc.createElement('canvas'),scx,rf=doc.createElement('canvas'),rfx; // sculpture working canvases
function prep(){sc.width=META.w;sc.height=META.h;scx=sc.getContext('2d');rf.width=META.w>>1;rf.height=META.h>>1;rfx=rf.getContext('2d')}

/* ---------- state ---------- */
var S={reveal:-1,cx:0,cy:0,w:0,al:0,bl:0,yaw:0,pitch:0,px:0,py:0,tpx:0,tpy:0,login:0,auth:0,p:0,last:0,inited:false};
addEventListener('pointermove',function(e){S.tpx=e.clientX/innerWidth*2-1;S.tpy=e.clientY/innerHeight*2-1},{passive:true});
function resize(){
  var W=innerWidth,H=innerHeight;DPR=Math.min(window.devicePixelRatio||1,LEVEL>=2?1:2);
  [back,front].forEach(function(c){c.width=Math.round(W*DPR);c.height=Math.round(H*DPR)});
}
addEventListener('resize',resize);resize();

/* ---------- seeded scene data ---------- */
var R=rng(20260);
var dust=[];for(var i=0;i<150;i++)dust.push({x:R(),y:R(),z:.15+R()*.85,s:.5+R()*1.5,p:R()*6.28,v:.3+R()*.9});
var bokeh=[];for(i=0;i<11;i++)bokeh.push({x:R(),y:R(),r:34+R()*90,a:.035+R()*.06,z:.5+R()*1.2,c:R()<.62?'150,190,235':'255,205,150',p:R()*6.28,v:.4+R()*.6});
var rings=[{rx:.60,ry:.17,rot:-.13,sp:.21,ph:0,lw:1.2,al:.55,sat:'ORBIT / 001'},{rx:.47,ry:.33,rot:.38,sp:-.15,ph:2.1,lw:1,al:.38,sat:'LIGHT PATH'}];

/* ---------- helpers ---------- */
function targetRect(){
  var el=$('.sculpture-target');var W=innerWidth,H=innerHeight;
  if(!el)return{x:W*.40,y:H*.06,w:W*.57,h:H*.64};
  var r=el.getBoundingClientRect();return{x:r.left,y:r.top+scrollY,w:r.width,h:r.height}
}
function chapterProgress(){var c=$('#chapters');if(!c)return 0;var r=c.getBoundingClientRect();return clamp(-r.top/(r.height||1),0,1)}

/* lemniscate path in cut-out space (same family as the original 3D photon orbit) */
var PA=META.w/2-META.m-META.r*1.0, PB=META.h/2-META.m-META.r*1.05;
function pathPt(a){return{x:META.w/2+PA*Math.sin(a),y:META.h/2-PB*Math.sin(2*a)*.93,front:Math.cos(a)>=0}}

/* ---------- main loop ---------- */
var frameMs=[],lastT=0;
function loop(){
  requestAnimationFrame(loop);
  var t0=performance.now(),t=t0/1000,dt=Math.min(.05,S.last?t-S.last:.016);S.last=t;
  var ld=$('#loader');if(S.reveal<0&&ld&&ld.classList.contains('done'))S.reveal=t;
  var fallback=body.classList.contains('fallback-2d');
  var W=innerWidth,H=innerHeight;
  var k=1-Math.exp(-dt*5.5);
  S.px+=(S.tpx-S.px)*k;S.py+=(S.tpy-S.py)*k;
  var login=body.classList.contains('login-active')?1:0,auth=body.classList.contains('is-auth')?1:0;
  S.login+=(login-S.login)*(1-Math.exp(-dt*3.2));S.auth+=(auth-S.auth)*(1-Math.exp(-dt*2.6));
  var p=clamp(scrollY/H,0,1);S.p=p;
  /* target placement */
  var tr=targetRect(),asp=META.w/META.h;
  var heroW=Math.min(tr.w,tr.h*asp),heroCx=tr.x+tr.w/2,heroCy=tr.y+tr.h/2;
  var cp=chapterProgress();
  var tcx=lerp(heroCx,W*.745,S.auth),tcy=lerp(heroCy+p*H*.16,H*.31+cp*H*.12,S.auth),tw=lerp(heroW*(1-.14*p),W*.40*(1-cp*.25),S.auth);
  var tal=lerp(1-.62*p,.46-cp*.2,S.auth)*(1-S.login*.42);
  if(!S.inited){S.cx=tcx;S.cy=tcy;S.w=tw;S.inited=true}
  var kk=1-Math.exp(-dt*4.2);S.cx+=(tcx-S.cx)*kk;S.cy+=(tcy-S.cy)*kk;S.w+=(tw-S.w)*kk;S.al+=(tal-S.al)*kk;
  S.bl+=((S.login*10+S.auth*2.2+p*2.5)-S.bl)*kk;
  var since=S.reveal<0?-1:t-S.reveal;
  var rv=since<0?0:ease(since/2.8);            // reveal 0..1
  /* letterbox slides away at reveal */
  if(since>=0){var b=ease((since-.2)/1.5);bars.style.setProperty('--b',(1-b).toFixed(4))}else bars.style.setProperty('--b','1');
  /* clear */
  bx.setTransform(1,0,0,1,0,0);bx.clearRect(0,0,back.width,back.height);
  fx.setTransform(1,0,0,1,0,0);fx.clearRect(0,0,front.width,front.height);
  bx.setTransform(DPR,0,0,DPR,0,0);fx.setTransform(DPR,0,0,DPR,0,0);
  var camS=1+.035*clamp(since/14)+Math.sin(t*.23)*.006;       // slow dolly-in
  var cx=S.cx+S.px*-14,cy=S.cy+S.py*-8+Math.sin(t*.6)*7,W2=S.w*camS;
  var al=S.al*rv;
  if(!fallback){ /* real WebGL scene: only atmospheric layers */
    atmos(bx,t,W,H,cx,cy,W2,al*.55,false);
    dustBokeh(fx,t,W,H,rv,since);
  }else if(imgOK){
    atmos(bx,t,W,H,cx,cy,W2,al,true);
    var sh=W2/META.w,Hh=META.h*sh;
    /* rings, back halves */
    drawRings(bx,t,cx,cy,W2,al,false);
    /* sculpture working canvas: metal + travelling sheen + photon flare */
    var a=(t*.074*Math.PI*2)%(Math.PI*2),ph=pathPt(a);
    scx.globalCompositeOperation='copy';scx.drawImage(img,0,0);
    scx.globalCompositeOperation='source-atop';
    // travelling specular sweep (diagonal band)
    var sw=((t*.16)%1.6-.3);var gx=META.w*sw,gy=META.h*.1;
    var g=scx.createLinearGradient(gx-260,gy,gx+260,gy+META.h*.55);
    g.addColorStop(0,'rgba(210,235,255,0)');g.addColorStop(.5,'rgba(225,242,255,.20)');g.addColorStop(1,'rgba(210,235,255,0)');
    scx.fillStyle=g;scx.fillRect(0,0,META.w,META.h);
    // warm glint where the photon touches the metal
    var gl=scx.createRadialGradient(ph.x,ph.y,0,ph.x,ph.y,330);
    var gi=ph.front?.62:.16;
    gl.addColorStop(0,'rgba(255,218,168,'+gi+')');gl.addColorStop(.35,'rgba(255,196,140,'+gi*.35+')');gl.addColorStop(1,'rgba(255,190,130,0)');
    scx.fillStyle=gl;scx.fillRect(0,0,META.w,META.h);
    scx.globalCompositeOperation='source-over';
    /* reflection on the floor */
    if(LEVEL<2)reflect(bx,cx,cy,sh,Hh,al,t);
    /* behind-photon (occluded by metal) */
    drawPhoton(bx,t,cx,cy,sh,a,al,false);
    /* sculpture with tilt */
    var yaw=S.px*.10+Math.sin(t*.31)*.06, pit=S.py*.05;
    bx.save();bx.translate(cx,cy);
    bx.transform(Math.cos(yaw)*.985+.015,Math.sin(yaw)*.035+pit*.0,-Math.sin(yaw)*.045,1-Math.abs(pit)*.04,0,0);
    bx.globalAlpha=al;
    if(S.bl>.3&&LEVEL<1)bx.filter='blur('+S.bl.toFixed(2)+'px)';
    var blurIn=(1-rv)*18; if(blurIn>.3&&LEVEL<1)bx.filter='blur('+(S.bl+blurIn).toFixed(2)+'px)';
    bx.drawImage(sc,-W2/2,-Hh/2,W2,Hh);
    bx.filter='none';
    // rim bloom
    if(LEVEL<1){bx.globalCompositeOperation='lighter';bx.globalAlpha=al*.16;bx.filter='blur('+(14*DPR*.6).toFixed(1)+'px)';bx.drawImage(sc,-W2/2,-Hh/2,W2,Hh);bx.filter='none'}
    bx.restore();bx.globalCompositeOperation='source-over';
    /* front half of rings + satellites, then front photon */
    drawRings(bx,t,cx,cy,W2,al,true);
    drawPhoton(bx,t,cx,cy,sh,a,al,true);
    dustBokeh(fx,t,W,H,rv,since);
  }
  /* adaptive quality */
  var ms=performance.now()-t0;frameMs.push(ms);
  if(frameMs.length>45){var avg=frameMs.reduce(function(a,b){return a+b},0)/frameMs.length;frameMs.length=0;
    if(typeof window.JW_CINE_LEVEL!=='number'){if(avg>11&&LEVEL<2){LEVEL++;resize()}}}
}

/* ---------- layers ---------- */
function atmos(c,t,W,H,cx,cy,w,al,full){
  c.save();c.globalCompositeOperation='lighter';
  // cool volumetric halo behind the object
  var g=c.createRadialGradient(cx,cy,0,cx,cy,w*.75);
  g.addColorStop(0,'rgba(110,160,215,'+(.20*al).toFixed(3)+')');g.addColorStop(.45,'rgba(70,110,170,'+(.08*al).toFixed(3)+')');g.addColorStop(1,'rgba(40,70,120,0)');
  c.fillStyle=g;c.fillRect(0,0,W,H);
  // god-rays fanning from upper left
  var ox=W*.18,oy=-H*.12;
  for(var i=0;i<7;i++){
    var ang=.62+i*.105+Math.sin(t*.12+i)*.012,len=H*1.6,wd=.028+.012*Math.sin(t*.2+i*1.7);
    var a=ang-wd,b=ang+wd;
    var ra=al*(.030+.014*Math.sin(t*.3+i*2.1));
    var gg=c.createLinearGradient(ox,oy,ox+Math.cos(ang)*len,oy+Math.sin(ang)*len);
    gg.addColorStop(0,'rgba(170,205,245,'+ra.toFixed(4)+')');gg.addColorStop(1,'rgba(170,205,245,0)');
    c.fillStyle=gg;c.beginPath();c.moveTo(ox,oy);c.lineTo(ox+Math.cos(a)*len,oy+Math.sin(a)*len);c.lineTo(ox+Math.cos(b)*len,oy+Math.sin(b)*len);c.closePath();c.fill();
  }
  // warm floor bounce
  if(full){var fg=c.createRadialGradient(cx,cy+w*.34,0,cx,cy+w*.34,w*.55);fg.addColorStop(0,'rgba(255,190,130,'+(.05*al).toFixed(3)+')');fg.addColorStop(1,'rgba(255,190,130,0)');c.fillStyle=fg;c.fillRect(0,0,W,H)}
  c.restore();
}
function drawRings(c,t,cx,cy,w,al,frontPass){
  c.save();c.translate(cx,cy);
  rings.forEach(function(rg,ri){
    var rx=rg.rx*w,ry=rg.ry*w*.62,rot=rg.rot+Math.sin(t*.18+ri)*.025;
    c.save();c.rotate(rot);
    var N=160,th0=t*rg.sp+rg.ph;
    for(var i=0;i<N;i++){
      var a1=i/N*6.2832,a2=(i+1)/N*6.2832,mid=(a1+a2)/2,front=Math.sin(mid)>0;
      if(front!==frontPass)continue;
      var x1=Math.cos(a1)*rx,y1=Math.sin(a1)*ry,x2=Math.cos(a2)*rx,y2=Math.sin(a2)*ry;
      var d=((mid-th0)%6.2832+6.2832)%6.2832;           // distance behind the comet head
      var comet=d<2.2?Math.pow(1-d/2.2,2):0;
      var depth=front?1:.45;
      c.globalAlpha=al*(rg.al*.28+comet*.7)*depth;
      c.strokeStyle=comet>.05?'rgb(200,225,255)':'rgb(160,190,225)';c.lineWidth=rg.lw*(front?1.15:.8)*(1+comet*.9);
      c.beginPath();c.moveTo(x1,y1);c.lineTo(x2,y2);c.stroke();
    }
    // tick marks
    if(LEVEL<2){c.globalAlpha=al*.16*(frontPass?1:.5);c.strokeStyle='rgb(190,214,240)';c.lineWidth=1;
      for(var k=0;k<72;k++){var a=k/72*6.2832;if((Math.sin(a)>0)!==frontPass)continue;var l=k%6===0?9:4;var ux=Math.cos(a),uy=Math.sin(a);
        c.beginPath();c.moveTo(ux*rx,uy*ry);c.lineTo(ux*(rx+l*(rx>0?1:1)),uy*(ry+l*.5));c.stroke()}}
    // satellite
    var sa=th0,front=Math.sin(sa)>0;
    if(front===frontPass){var sx=Math.cos(sa)*rx,sy=Math.sin(sa)*ry;
      c.globalAlpha=al*(front?1:.5);
      var gg=c.createRadialGradient(sx,sy,0,sx,sy,22);gg.addColorStop(0,'rgba(235,245,255,.95)');gg.addColorStop(.25,'rgba(170,205,245,.35)');gg.addColorStop(1,'rgba(150,190,240,0)');
      c.fillStyle=gg;c.beginPath();c.arc(sx,sy,22,0,6.2832);c.fill();
      c.fillStyle='rgb(245,250,255)';c.beginPath();c.arc(sx,sy,2.4,0,6.2832);c.fill();
      if(front&&LEVEL<2){c.save();c.rotate(-rot);var lx=Math.cos(rot)*sx-Math.sin(rot)*sy,ly=Math.sin(rot)*sx+Math.cos(rot)*sy;
        c.globalAlpha=al*.7;c.fillStyle='rgb(190,212,236)';c.font='600 11px Inter,"Noto Sans CJK KR",sans-serif';c.textBaseline='middle';
        if('letterSpacing' in c)c.letterSpacing='2.4px';c.fillText(rg.sat,lx+16,ly-12);c.restore()}}
    c.restore();
  });
  c.restore();
}
function reflect(c,cx,cy,sh,Hh,al,t){
  var rw=rf.width,rh=rf.height;
  rfx.save();rfx.setTransform(1,0,0,1,0,0);rfx.clearRect(0,0,rw,rh);
  rfx.translate(0,rh);rfx.scale(1,-1);rfx.drawImage(sc,0,0,rw,rh);rfx.restore();
  rfx.globalCompositeOperation='destination-in';
  var g=rfx.createLinearGradient(0,0,0,rh);g.addColorStop(0,'rgba(0,0,0,.34)');g.addColorStop(.55,'rgba(0,0,0,.07)');g.addColorStop(1,'rgba(0,0,0,0)');
  rfx.fillStyle=g;rfx.fillRect(0,0,rw,rh);rfx.globalCompositeOperation='source-over';
  c.save();c.globalAlpha=al*.9;if(LEVEL<1)c.filter='blur(3px)';
  c.drawImage(rf,cx-META.w*sh/2,cy+Hh/2+Hh*.035,META.w*sh,Hh*.62);c.filter='none';c.restore();
}
function drawPhoton(c,t,cx,cy,sh,a,al,frontPass){
  var ph=pathPt(a);if(ph.front!==frontPass)return;
  function toScreen(p){return{x:cx+(p.x-META.w/2)*sh,y:cy+(p.y-META.h/2)*sh}}
  var P=toScreen(ph);
  c.save();c.globalCompositeOperation='lighter';
  var dim=ph.front?1:.5;
  // trail
  var n=LEVEL<2?46:20;
  for(var i=n;i>=1;i--){var q=toScreen(pathPt(a-i*.016));if(pathPt(a-i*.016).front!==frontPass)continue;var f=Math.pow(1-i/n,2.2);
    c.globalAlpha=al*dim*f*.85;var rr=(1.2+f*5.5)*(innerWidth/1920+.4);
    var g=c.createRadialGradient(q.x,q.y,0,q.x,q.y,rr*2.4);g.addColorStop(0,'rgba(255,205,150,.9)');g.addColorStop(1,'rgba(255,170,110,0)');
    c.fillStyle=g;c.beginPath();c.arc(q.x,q.y,rr*2.4,0,6.2832);c.fill();}
  // halo + core
  c.globalAlpha=al*dim;
  var gh=c.createRadialGradient(P.x,P.y,0,P.x,P.y,70*(innerWidth/1920+.3));
  gh.addColorStop(0,'rgba(255,240,215,1)');gh.addColorStop(.12,'rgba(255,214,160,.7)');gh.addColorStop(.4,'rgba(150,190,240,.18)');gh.addColorStop(1,'rgba(120,170,230,0)');
  c.fillStyle=gh;c.beginPath();c.arc(P.x,P.y,70*(innerWidth/1920+.3),0,6.2832);c.fill();
  // anamorphic streak
  c.save();c.translate(P.x,P.y);c.scale(9,1);
  var gs=c.createRadialGradient(0,0,0,0,0,26);gs.addColorStop(0,'rgba(170,205,255,.34)');gs.addColorStop(1,'rgba(120,170,255,0)');
  c.fillStyle=gs;c.beginPath();c.arc(0,0,26,0,6.2832);c.fill();c.restore();
  c.restore();
}
function dustBokeh(c,t,W,H,rv,since){
  var px=S.px,py=S.py;
  // fine dust (parallax by depth)
  c.save();c.globalCompositeOperation='lighter';
  for(var i=0;i<dust.length;i++){var d=dust[i];
    var x=((d.x*W+t*9*d.z*d.v-px*28*d.z)%(W+40)+W+40)%(W+40)-20,y=((d.y*H-t*6*d.z*d.v-py*16*d.z)%(H+40)+H+40)%(H+40)-20;
    var a=(.10+.30*d.z)*(.55+.45*Math.sin(t*1.2+d.p))*rv;
    c.fillStyle='rgba(205,225,250,'+a.toFixed(3)+')';c.beginPath();c.arc(x,y,d.s*d.z*1.25,0,6.2832);c.fill();}
  // bokeh discs (foreground, large, soft)
  if(LEVEL<2)for(i=0;i<bokeh.length;i++){var b=bokeh[i];
    var bx_=((b.x*W+t*7*b.v*b.z-px*70*b.z)%(W+300)+W+300)%(W+300)-150,by_=((b.y*H-t*4*b.v*b.z-py*40*b.z)%(H+300)+H+300)%(H+300)-150;
    var aa=b.a*rv*(.7+.3*Math.sin(t*.5+b.p));
    var g=c.createRadialGradient(bx_,by_,b.r*.1,bx_,by_,b.r);
    g.addColorStop(0,'rgba('+b.c+','+(aa*.5).toFixed(4)+')');g.addColorStop(.82,'rgba('+b.c+','+(aa*.9).toFixed(4)+')');g.addColorStop(.95,'rgba('+b.c+','+(aa*1.5).toFixed(4)+')');g.addColorStop(1,'rgba('+b.c+',0)');
    c.fillStyle=g;c.beginPath();c.arc(bx_,by_,b.r,0,6.2832);c.fill();}
  c.restore();
}

/* start */
if(doc.readyState==='loading')doc.addEventListener('DOMContentLoaded',function(){requestAnimationFrame(loop)});else requestAnimationFrame(loop);
window.JW_CINE={state:S,setLevel:function(l){LEVEL=l;window.JW_CINE_LEVEL=l;resize()}};
})();
