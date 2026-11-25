/* JARVIS-WORKS V21.2 — user's original SVG-glass infinity + one canvas photon.
 * Review-only visual enhancement; original login, API, tenant metrics and routes stay intact.
 * Source: user-supplied jarvis-works-full.html (sculpture renderer only).
 */
(function(){
 'use strict';
const NS='http://www.w3.org/2000/svg';
const $=(s,r=document)=>r.querySelector(s);
const $$=(s,r=document)=>[...r.querySelectorAll(s)];
const el=(n,a={},p)=>{const e=document.createElementNS(NS,n);for(const k in a)e.setAttribute(k,a[k]);if(p)p.appendChild(e);return e};
const REDUCED=matchMedia('(prefers-reduced-motion: reduce)');

function lemniscate(n,off){
  const P=[];for(let i=0;i<n;i++){const t=i/n*2*Math.PI,s=Math.sin(t),c=Math.cos(t),d=1+s*s;P.push([400+300*c/d,232+375*s*c/d])}
  if(!off)return P;
  return P.map((p,i)=>{const a=P[(i-1+n)%n],b=P[(i+1)%n];let tx=b[0]-a[0],ty=b[1]-a[1];const l=Math.hypot(tx,ty)||1;tx/=l;ty/=l;return[p[0]-ty*off,p[1]+tx*off]});
}
const toD=P=>'M'+P.map(p=>p[0].toFixed(1)+' '+p[1].toFixed(1)).join('L')+'Z';

function createSculpture(host){
  const VB='60 50 680 440';
  const svg=el('svg',{viewBox:VB,class:'scv stat',preserveAspectRatio:'xMidYMid meet','aria-hidden':'true'});
  const defs=el('defs',{},svg);
  const g1=el('linearGradient',{id:'rim'+host.id,gradientUnits:'userSpaceOnUse',x1:100,y1:0,x2:700,y2:0},defs);
  [[0,'#8D99B3'],[.22,'#F2F5FF'],[.5,'#FFFFFF'],[.62,'#F3E7DA'],[.78,'#DDE4F4'],[1,'#8D99B3']].forEach(([o,c])=>el('stop',{offset:o,'stop-color':c},g1));
  const beam=el('linearGradient',{id:'bm'+host.id,x1:0,y1:0,x2:1,y2:0},defs);
  [[0,'rgba(200,214,255,0)'],[.5,'rgba(200,214,255,.13)'],[1,'rgba(200,214,255,0)']].forEach(([o,c])=>el('stop',{offset:o,'stop-color':c},beam));
  const bmg=el('linearGradient',{id:'bmg'+host.id,x1:0,y1:0,x2:0,y2:1},defs);
  [[0,'#000'],[.5,'#fff'],[1,'#000']].forEach(([o,c])=>el('stop',{offset:o,'stop-color':c},bmg));
  const bmk=el('mask',{id:'bmk'+host.id,maskUnits:'userSpaceOnUse',x:0,y:0,width:800,height:480},defs);
  el('rect',{x:0,y:0,width:800,height:480,fill:`url(#bmg${host.id})`},bmk);
  const plate=el('linearGradient',{id:'pl'+host.id,x1:0,y1:0,x2:0,y2:1},defs);
  [[0,'#2A3242'],[.5,'#10151F'],[1,'#080B12']].forEach(([o,c])=>el('stop',{offset:o,'stop-color':c},plate));
  const halo=el('radialGradient',{id:'hl'+host.id},defs);
  [[0,'rgba(255,255,255,.85)'],[.25,'rgba(255,255,255,.35)'],[1,'rgba(255,255,255,0)']].forEach(([o,c])=>el('stop',{offset:o,'stop-color':c},halo));
  const floor=el('radialGradient',{id:'fl'+host.id},defs);
  [[0,'rgba(190,205,245,.20)'],[1,'rgba(190,205,245,0)']].forEach(([o,c])=>el('stop',{offset:o,'stop-color':c},floor));
  [['b3',3],['b8',8],['b16',16]].forEach(([id,s])=>{const f=el('filter',{id:id+host.id,x:'-50%',y:'-50%',width:'200%',height:'200%'},defs);el('feGaussianBlur',{stdDeviation:s},f)});

  /* backdrop light column + pedestal (static) */
  el('rect',{x:250,y:0,width:300,height:410,fill:`url(#bm${host.id})`,mask:`url(#bmk${host.id})`,class:'beam'},svg);
  const ped=el('g',{},svg);
  el('ellipse',{cx:400,cy:440,rx:350,ry:44,fill:`url(#fl${host.id})`},ped);
  el('ellipse',{cx:400,cy:408,rx:322,ry:50,fill:'none',stroke:'rgba(220,230,255,.16)','stroke-width':1},ped);
  el('ellipse',{cx:400,cy:408,rx:336,ry:54,fill:'none',stroke:'rgba(220,230,255,.45)','stroke-width':1.2,'stroke-dasharray':'1.2 7'},ped);
  el('ellipse',{cx:400,cy:404,rx:268,ry:38,fill:`url(#pl${host.id})`,stroke:'rgba(235,241,255,.55)','stroke-width':1.2},ped);
  el('ellipse',{cx:400,cy:399,rx:236,ry:30,fill:'none',stroke:'rgba(235,241,255,.28)','stroke-width':1},ped);
  el('ellipse',{cx:400,cy:396,rx:150,ry:19,fill:'#090D15',stroke:'rgba(235,241,255,.4)','stroke-width':1},ped);
  el('ellipse',{cx:400,cy:394,rx:110,ry:13,fill:'rgba(215,226,255,.16)',filter:`url(#b8${host.id})`},ped);

  /* glass ribbon */
  const C=lemniscate(520),O1=lemniscate(520,30),I1=lemniscate(520,-30),O2=lemniscate(520,17),I2=lemniscate(520,-17);
  const dC=toD(C),rim=`url(#rim${host.id})`;
  ped.setAttribute('id','pd'+host.id);
  /* refraction: the floor and pedestal seen through the glass, flipped, magnified and displaced */
  const rm=el('mask',{id:'rm'+host.id,maskUnits:'userSpaceOnUse',x:0,y:0,width:800,height:520},defs);
  el('path',{d:dC,fill:'none',stroke:'#fff','stroke-width':58,'stroke-linejoin':'round'},rm);
  const rf=el('filter',{id:'rf'+host.id,x:'-10%',y:'-10%',width:'120%',height:'120%'},defs);
  el('feTurbulence',{type:'fractalNoise',baseFrequency:'0.011 0.02',numOctaves:2,seed:4,result:'n'},rf);
  el('feDisplacementMap',{in:'SourceGraphic',in2:'n',scale:28,xChannelSelector:'R',yChannelSelector:'G'},rf);
  const rb=el('g',{},svg);
  el('path',{d:dC,fill:'none',stroke:'rgba(185,202,255,.13)','stroke-width':78,filter:`url(#b16${host.id})`},rb);
  const rg=el('g',{mask:`url(#rm${host.id})`},rb);
  const rg2=el('g',{filter:`url(#rf${host.id})`},rg);
  el('use',{href:'#pd'+host.id,transform:'translate(400 262) scale(1.55 -1.4) translate(-400 -404)',opacity:.95},rg2);
  el('path',{d:dC,fill:'none',stroke:rim,'stroke-width':60,opacity:.2,'stroke-linejoin':'round'},rb);
  [[O1,2.1,.95],[I1,2.1,.95],[O2,1.2,.5],[I2,1.2,.5]].forEach(([P,w,o])=>el('path',{d:toD(P),fill:'none',stroke:rim,'stroke-width':w,opacity:o},rb));
  [[lemniscate(520,33),'rgba(255,226,205,.5)'],[lemniscate(520,-33),'rgba(190,212,255,.5)']].forEach(([P,c])=>el('path',{d:toD(P),fill:'none',stroke:c,'stroke-width':1.4},rb));
  [lemniscate(520,23),lemniscate(520,-23)].forEach(P=>el('path',{d:toD(P),fill:'none',stroke:'#fff','stroke-width':3.4,opacity:.5,'stroke-dasharray':'86 168','stroke-linecap':'round',filter:`url(#b3${host.id})`},rb));
  el('path',{d:dC,fill:'none',stroke:'#fff','stroke-width':5,opacity:.45,'stroke-dasharray':'1 34','stroke-linecap':'round',filter:`url(#b3${host.id})`},rb);
  el('path',{d:dC,fill:'none',stroke:'rgba(255,255,255,.35)','stroke-width':.8},rb);

  /* the single moving light — drawn on a canvas with pre-rendered glow sprites (no per-frame SVG filters) */
  const N=1040;
  const resample=P=>{
    const n=P.length,cum=[0];
    for(let i=0;i<n;i++){const a=P[i],b=P[(i+1)%n];cum.push(cum[i]+Math.hypot(b[0]-a[0],b[1]-a[1]))}
    const T=cum[n],xs=new Float32Array(N),ys=new Float32Array(N);let j=0;
    for(let k=0;k<N;k++){const s=k/N*T;while(cum[j+1]<s)j++;const a=P[j],b=P[(j+1)%n],t=(s-cum[j])/((cum[j+1]-cum[j])||1);xs[k]=a[0]+(b[0]-a[0])*t;ys[k]=a[1]+(b[1]-a[1])*t}
    return{xs,ys,T};
  };
  const cv={c:resample(C),o1:resample(O1),i1:resample(I1),o2:resample(O2),i2:resample(I2)};
  const sprite=(size,stops)=>{const s=document.createElement('canvas');s.width=s.height=size;const x=s.getContext('2d'),g=x.createRadialGradient(size/2,size/2,0,size/2,size/2,size/2);stops.forEach(([o,c])=>g.addColorStop(o,c));x.fillStyle=g;x.fillRect(0,0,size,size);return s};
  const SOFT=sprite(64,[[0,'rgba(255,255,255,1)'],[.35,'rgba(255,255,255,.4)'],[1,'rgba(255,255,255,0)']]);
  const TIGHT=sprite(32,[[0,'rgba(255,255,255,1)'],[.5,'rgba(255,255,255,.45)'],[1,'rgba(255,255,255,0)']]);
  const HALO=sprite(128,[[0,'rgba(255,255,255,.85)'],[.25,'rgba(255,255,255,.35)'],[1,'rgba(255,255,255,0)']]);
  const cnv=document.createElement('canvas');cnv.className='scv-c';cnv.setAttribute('aria-hidden','true');
  const ctx=cnv.getContext('2d');
  const wrap=document.createElement('div');wrap.className='sculpture sc-wrap';wrap.append(svg,cnv);host.appendChild(wrap);
  const PADX=0,PADY=0;let bw=0,bh=0,Q=1,lastF=.13,low=false,SM=1,AM=1,hq=true;
  const fit=()=>{
    const w=wrap.clientWidth,h=wrap.clientHeight;if(!w||!h)return;
    const dpr=Math.min(window.devicePixelRatio||1,3);Q=low||!hq?Math.min(2,Math.max(1,dpr)):Math.min(2.5,Math.max(1.25,dpr*1.25));
    if(w===bw&&h===bh&&cnv.width)return;bw=w;bh=h;
    const cw=Math.round(w*(1+2*PADX)),ch=Math.round(h*(1+2*PADY));
    cnv.style.cssText=`position:absolute;left:${-PADX*100}%;top:${-PADY*100}%;width:${(1+2*PADX)*100}%;height:${(1+2*PADY)*100}%;display:block;pointer-events:none`;
    cnv.width=Math.min(2400,Math.round(cw*Q));cnv.height=Math.min(1600,Math.round(ch*Q));
    draw(lastF);
  };
  /* sub-sample interpolation: positions follow the exact fractional head, so the light never steps in whole samples */
  const px=(c,i)=>{const k=Math.floor(i),t=i-k,a=((k%N)+N)%N,b=(a+1)%N;return c.xs[a]+(c.xs[b]-c.xs[a])*t};
  const py=(c,i)=>{const k=Math.floor(i),t=i-k,a=((k%N)+N)%N,b=(a+1)%N;return c.ys[a]+(c.ys[b]-c.ys[a])*t};
  const trail=(c,head,L,step,size,alpha,pw,spr)=>{
    const n=Math.round(L/c.T*N),st=step*SM,h=size/2;
    for(let d=0;d<n;d+=st){
      const i=head-d,a=Math.min(1,alpha*AM)*Math.pow(1-d/n,pw);
      ctx.globalAlpha=a;ctx.drawImage(spr,px(c,i)-h,py(c,i)-h,size,size);
    }
  };
  function draw(f){
    lastF=f;if(!bw)return;
    const cs=Math.min(bw/680,bh/440),ox=(bw-680*cs)/2+bw*PADX,oy=(bh-440*cs)/2+bh*PADY,k=cnv.width/(bw*(1+2*PADX))*cs;
    ctx.setTransform(1,0,0,1,0,0);ctx.clearRect(0,0,cnv.width,cnv.height);
    const sx=cnv.width/(bw*(1+2*PADX));
    ctx.setTransform(k,0,0,k,(ox-60*cs)*sx,(oy-50*cs)*sx);
    ctx.globalCompositeOperation='lighter';
    const head=f*N;
    trail(cv.c,head,190,8,58,.12,1,SOFT);
    trail(cv.c,head,100,6,44,.16,1,SOFT);
    trail(cv.c,head,320,3,19,.17,1.6,SOFT);
    trail(cv.c,head,90,3,14,.23,1.1,SOFT);
    [cv.o1,cv.i1].forEach(c=>{trail(c,head,240,4,11,.50,1.4,TIGHT);trail(c,head,115,4,10,.68,1,TIGHT)});
    [cv.o2,cv.i2].forEach(c=>trail(c,head,130,4,9,.46,1.2,TIGHT));
    const hx=px(cv.c,head),hy=py(cv.c,head);
    ctx.globalAlpha=1;ctx.drawImage(HALO,hx-52,hy-52,104,104);
    ctx.globalAlpha=.9;ctx.drawImage(TIGHT,hx-12,hy-12,24,24);
    ctx.globalAlpha=1;ctx.fillStyle='#fff';ctx.beginPath();ctx.arc(hx,hy,2.4,0,6.2832);ctx.fill();
    ctx.globalCompositeOperation='source-over';ctx.globalAlpha=1;
  }
  const ro=window.ResizeObserver?new ResizeObserver(fit):null;ro?.observe(wrap);

  const PERIOD=9000;
  const set=f=>{fit();draw(f)};
  let raf=0,last=0,running=false,phase=.13,speed=1,target=1;
  let slow=0;
  const frame=ts=>{const raw=last?ts-last:16,dt=Math.min(64,raw);last=ts;
    if(!low){if(raw>26&&raw<250)slow++;else if(slow>0)slow-=.5;if(slow>36){low=true;SM=2;AM=1.7;bw=0;fit()}}
    speed+=(target-speed)*Math.min(1,dt/180);phase=(phase+dt/PERIOD*speed)%1;draw(phase);raf=requestAnimationFrame(frame)};
  const api={
    start(){if(running)return;fit();if(REDUCED.matches){draw(.13);return}running=true;last=0;raf=requestAnimationFrame(frame)},
    stop(){running=false;cancelAnimationFrame(raf)},
    destroy(){this.stop();ro?.disconnect();wrap.remove()},
    boost(m){target=m},
    isLow:()=>low,
    setHQ(v){if(hq===v)return;hq=v;bw=0;fit()},
    wrap
  };
  requestAnimationFrame(()=>set(.13));
  return api;
}
 const login=document.getElementById('login-view');
 const shell=document.getElementById('app-shell');
 const main=document.getElementById('main-content');
 if(!login||!shell||!main||!window.JW_PREMIUM_V211)return;
 const mounted={login:null,home:null};
 let pending=false;
 function mount(key,host){
   const old=mounted[key];
   if(old&&old.host!==host){old.host.classList.remove('jw212-ready');old.fx.destroy();mounted[key]=null;}
   if(!host)return;
   if(mounted[key]?.host===host)return;
   const layer=document.createElement('div');
   layer.className='jw212-sculpt';
   layer.id='jw212-'+key;
   layer.setAttribute('aria-hidden','true');
   host.appendChild(layer);
   try {
     const fx=createSculpture(layer);
     host.classList.add('jw212-ready');
     mounted[key]={host,fx};
   } catch(err) {
     // Fail open visually only: restore V21.1 decoration without touching auth/business.
     layer.remove();host.classList.remove('jw212-ready');
     mounted[key]=null;
   }
 }
 function sync(){
   const signedIn=!shell.classList.contains('hidden')&&!shell.hidden;
   const tabVisible=!document.hidden;
   const homeVisible=signedIn && !!mounted.home?.host.isConnected &&
     (typeof state==='undefined'||state.page==='dashboard');
   for(const [key,m] of Object.entries(mounted)){
     if(!m)continue;
     const shouldPlay=tabVisible&&!REDUCED.matches&&(key==='login'?!signedIn:homeVisible);
     if(shouldPlay)m.fx.start();else m.fx.stop();
   }
   // The inherited V21.1 animated photon must never run behind the accepted
   // Canvas version. Resume it only if the Canvas renderer has failed.
   for(const legacy of document.querySelectorAll('.jw211-glass-photon')){
     if(typeof legacy.pauseAnimations!=='function')continue;
     const parent=legacy.parentElement;
     const hasCanvas=parent?.classList.contains('jw212-ready');
     const hidden=parent?.closest('#login-view,#app-shell')?.classList.contains('hidden');
     if(hasCanvas||hidden||REDUCED.matches||document.hidden)legacy.pauseAnimations();
     else legacy.unpauseAnimations();
   }
 }
 function update(){
   mount('login',login.querySelector('.jw211-login-infinity'));
   mount('home',main.querySelector('.jw210-infinity-stage'));
   sync();
 }
 function schedule(){if(pending)return;pending=true;requestAnimationFrame(()=>{pending=false;update()})}
 new MutationObserver(schedule).observe(main,{childList:true});
 new MutationObserver(schedule).observe(login,{attributes:true,attributeFilter:['class'],childList:true});
 new MutationObserver(schedule).observe(shell,{attributes:true,attributeFilter:['class','hidden']});
 document.addEventListener('visibilitychange',sync);
 REDUCED.addEventListener?.('change',sync);
 update();
 window.JW_PREMIUM_V212=Object.freeze({version:'21.2',renderer:'source-svg-canvas-photon',source:'user-supplied-html',uiMode:'authenticated-workspace'});
})();
