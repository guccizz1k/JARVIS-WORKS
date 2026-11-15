/* Exact visual-only WebGL2 engine copied from the pinned 229028-byte owner UI.
 * This module contains no local company, login, account, document, DB, or API code.
 * Do not modify the embedded GL constant; provenance tests compare it to the immutable source.
 */
(function(){
'use strict';
const GL=(()=>{
  let cv,gl,W=0,H=0,dpr=1,on=false,vis=true,raf=0,last=0,ready=false,fail=false;
  let rp,pp,gq,rVAO,pVAO,rN=0,pN=0,idxN=0,rIdx;
  const S={x:.34,y:.02,s:1,ry:-.35,rx:.9,rz:0,speed:1,glow:1,fade:1,theme:0,photon:0,flash:0,cam:4.6,hz:1};
  const T=Object.assign({},S); const K={x:3,y:3,s:3.2,ry:2.2,rx:2.2,rz:2.2,speed:2,glow:2.4,fade:2.2,theme:4,cam:2.6};
  const P={px:0,py:0,tpx:0,tpy:0,spin:0}; let tier=2,ft=[],slow=0,quality=1,bad=0,fs=0,onSlow=null;
  const VS=`#version 300 es
  precision highp float; in vec2 aP; uniform mat4 uVP,uM; uniform float uT,uHz; out vec3 vN,vP; out vec2 vUV;
  vec3 f(float u,float v){float a=u*6.2831853;float c=cos(a*1.5),s=sin(a*1.5);float r=1.+v*.2*c;
    vec3 p=vec3(r*cos(a)*1.38,r*sin(a)*.9,v*.2*s*1.1);p.z+=sin(a*2.+uT*.45)*.05;return p;}
  void main(){float e=.002;vec3 p=f(aP.x,aP.y);vec3 du=f(aP.x+e,aP.y)-f(aP.x-e,aP.y),dv=f(aP.x,aP.y+e)-f(aP.x,aP.y-e);
    vec3 n=normalize(cross(du,dv));vec4 w=uM*vec4(p,1.);vP=w.xyz;vN=mat3(uM)*n;vUV=aP;gl_Position=uVP*w;}`;
  const FS=`#version 300 es
  precision highp float; in vec3 vN,vP; in vec2 vUV; uniform vec3 uCam; uniform float uT,uTheme,uPh,uGlow,uFade; out vec4 o;
  vec3 env(vec3 r){float y=r.y*.5+.5;
    vec3 dk=mix(vec3(.015,.018,.022),vec3(.2,.215,.25),y);vec3 lt=mix(vec3(.55,.56,.58),vec3(1.05,1.04,1.0),y);vec3 c=mix(dk,lt,uTheme);
    c+=vec3(1.,.96,.9)*smoothstep(.80,.97,dot(r,normalize(vec3(.5,.85,.45))))*2.4;
    c+=vec3(.55,.72,1.)*smoothstep(.84,.98,dot(r,normalize(vec3(-.85,.25,.5))))*1.5;
    c+=mix(vec3(.83,1.,.23),vec3(.55,.8,.0),uTheme)*smoothstep(.9,.995,dot(r,normalize(vec3(.15,-.65,-.75))))*1.3;
    c+=vec3(.6,.5,1.)*smoothstep(.9,.99,dot(r,normalize(vec3(.9,-.2,-.4))))*1.1;return c;}
  void main(){vec3 N=normalize(vN);if(!gl_FrontFacing)N=-N;vec3 V=normalize(uCam-vP);vec3 R=reflect(-V,N);
    float nv=max(dot(N,V),0.);float fr=pow(1.-nv,3.);
    vec3 col=env(R)*(.5+.95*fr);
    col+=(.5+.5*cos(6.2831*(vec3(0.,.33,.67)+nv*1.15+uT*.02)))*fr*.42;
    float ed=smoothstep(.9,1.,abs(vUV.y));vec3 lime=mix(vec3(.83,1.,.23),vec3(.4,.55,0.),uTheme);
    col+=lime*ed*(.5+.5*sin(vUV.x*6.2831*5.+uT*1.2))*.9*uGlow;
    float fl=smoothstep(.93,1.,sin(vUV.x*6.2831*22.-uT*1.1+vUV.y*1.5))*(1.-ed)*.5;col+=lime*fl*.12*uGlow;
    float d=abs(fract(vUV.x-uPh+.5)-.5);col+=vec3(1.,1.,.85)*exp(-d*d*1500.)*2.6*uGlow+lime*exp(-d*d*180.)*.7*uGlow;
    col=1.-exp(-col*1.15);col=pow(col,vec3(.92));o=vec4(col*uFade,uFade);}`;
  const PVS=`#version 300 es
  precision highp float; in vec4 aS; uniform mat4 uVP,uM; uniform float uT,uSz,uSp; out float vA; out float vH;
  vec3 f(float u,float v){float a=u*6.2831853;float c=cos(a*1.5),s=sin(a*1.5);float r=1.+v*.2*c;
    return vec3(r*cos(a)*1.38,r*sin(a)*.9,v*.2*s*1.1)+vec3(0.,0.,sin(a*2.+uT*.45)*.05);}
  void main(){float u=fract(aS.x+uT*(.012+aS.w*.03)*uSp);float v=aS.y*1.5;float off=aS.z;vec3 p=f(u,v);
    p+=vec3(sin(uT*.7+aS.x*40.),cos(uT*.6+aS.y*30.),sin(uT*.5+aS.z*20.))*.05*(1.+abs(off));p.z+=off*.55;
    vec4 w=uM*vec4(p,1.);gl_Position=uVP*w;float k=1.+aS.w*2.2;gl_PointSize=uSz*k/max(.6,gl_Position.w)*3.2;
    vA=.25+.75*fract(aS.x*91.+aS.w*7.+uT*.2*(.2+aS.w));vH=step(.62,aS.w);}`;
  const PFS=`#version 300 es
  precision highp float; in float vA,vH; uniform float uFade,uTheme; out vec4 o;
  void main(){vec2 c=gl_PointCoord-.5;float d=dot(c,c)*4.;if(d>1.)discard;float a=pow(1.-d,2.2)*vA*uFade;
    vec3 col=mix(vec3(.9,.95,1.),vec3(.83,1.,.23),vH);col=mix(col,vec3(.12,.16,.0),uTheme*.85);o=vec4(col*a,a);}`;
  const QVS=`#version 300 es
  in vec2 aP; out vec2 vU; void main(){vU=aP;gl_Position=vec4(aP,0.,1.);}`;
  const QFS=`#version 300 es
  precision highp float; in vec2 vU; uniform vec2 uC,uR; uniform float uG,uTheme,uFade; out vec4 o;
  void main(){vec2 p=(vU-uC)*vec2(uR.x/uR.y,1.);float d=length(p*vec2(.62,.9));float g=exp(-d*d*1.6)*.075+exp(-d*d*7.)*.035;
    vec3 c=mix(vec3(.55,.62,.4),vec3(.25,.3,.5),smoothstep(.0,1.,d));c=mix(c,vec3(.78,.84,.45),uTheme);float a=g*uG*uFade*(1.-uTheme*.55);o=vec4(c*a,a);}`;
  function sh(t,s){const x=gl.createShader(t);gl.shaderSource(x,s);gl.compileShader(x);if(!gl.getShaderParameter(x,gl.COMPILE_STATUS))throw new Error(gl.getShaderInfoLog(x));return x}
  function pr(v,f){const p=gl.createProgram();gl.attachShader(p,sh(gl.VERTEX_SHADER,v));gl.attachShader(p,sh(gl.FRAGMENT_SHADER,f));gl.bindAttribLocation(p,0,'aP');gl.bindAttribLocation(p,0,'aS');gl.linkProgram(p);if(!gl.getProgramParameter(p,gl.LINK_STATUS))throw new Error(gl.getProgramInfoLog(p));
    p.u={};const n=gl.getProgramParameter(p,gl.ACTIVE_UNIFORMS);for(let i=0;i<n;i++){const q=gl.getActiveUniform(p,i);p.u[q.name]=gl.getUniformLocation(p,q.name)}return p}
  const mul=(a,b)=>{const o=new Float32Array(16);for(let i=0;i<4;i++)for(let j=0;j<4;j++){let s=0;for(let k=0;k<4;k++)s+=a[k*4+j]*b[i*4+k];o[i*4+j]=s}return o};
  function persp(fov,asp,n,f){const t=1/Math.tan(fov/2),m=new Float32Array(16);m[0]=t/asp;m[5]=t;m[10]=(f+n)/(n-f);m[11]=-1;m[14]=2*f*n/(n-f);return m}
  function model(x,y,s,rx,ry,rz){const cx=Math.cos(rx),sx=Math.sin(rx),cy=Math.cos(ry),sy=Math.sin(ry),cz=Math.cos(rz),sz=Math.sin(rz);
    const Rx=new Float32Array([1,0,0,0,0,cx,sx,0,0,-sx,cx,0,0,0,0,1]),Ry=new Float32Array([cy,0,-sy,0,0,1,0,0,sy,0,cy,0,0,0,0,1]),Rz=new Float32Array([cz,sz,0,0,-sz,cz,0,0,0,0,1,0,0,0,0,1]);
    let m=mul(Ry,mul(Rx,Rz));for(let i=0;i<12;i++)if(i%4!==3)m[i]*=s;m[12]=x;m[13]=y;m[14]=0;return m}
  function build(){
    const NU=tier>=2?420:260,NV=tier>=2?12:8;const v=[];for(let i=0;i<=NU;i++)for(let j=0;j<=NV;j++)v.push(i/NU,j/NV*2-1);
    const ix=[];for(let i=0;i<NU;i++)for(let j=0;j<NV;j++){const a=i*(NV+1)+j,b=a+NV+1;ix.push(a,b,a+1,a+1,b,b+1)}
    rVAO=gl.createVertexArray();gl.bindVertexArray(rVAO);let b=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,b);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array(v),gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);gl.vertexAttribPointer(0,2,gl.FLOAT,false,0,0);rIdx=gl.createBuffer();gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER,rIdx);gl.bufferData(gl.ELEMENT_ARRAY_BUFFER,new Uint32Array(ix),gl.STATIC_DRAW);idxN=ix.length;
    pN=tier>=2?5200:tier===1?2600:1200;const q=new Float32Array(pN*4);let s=7;const r=()=>{s=(s*16807)%2147483647;return (s-1)/2147483646};
    for(let i=0;i<pN;i++){q[i*4]=r();q[i*4+1]=r()*2-1;q[i*4+2]=(r()-.5)*(r()<.7?.5:1.6);q[i*4+3]=r()}
    pVAO=gl.createVertexArray();gl.bindVertexArray(pVAO);b=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,b);gl.bufferData(gl.ARRAY_BUFFER,q,gl.STATIC_DRAW);gl.enableVertexAttribArray(0);gl.vertexAttribPointer(0,4,gl.FLOAT,false,0,0);
    gq=gl.createVertexArray();gl.bindVertexArray(gq);b=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,b);gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-1,-1,3,-1,-1,3]),gl.STATIC_DRAW);gl.enableVertexAttribArray(0);gl.vertexAttribPointer(0,2,gl.FLOAT,false,0,0);
  }
  function size(){const w=innerWidth,h=innerHeight;dpr=Math.min(devicePixelRatio||1,quality>=1?1.6:quality>.7?1.15:.85);W=Math.round(w*dpr);H=Math.round(h*dpr);cv.width=W;cv.height=H;cv.style.width=w+'px';cv.style.height=h+'px'}
  function init(canvas){
    cv=canvas;try{
      gl=cv.getContext('webgl2',{antialias:true,alpha:true,premultipliedAlpha:true,powerPreference:'high-performance'});if(!gl)throw 0;
      const cores=navigator.hardwareConcurrency||4;tier=(/Mobi|Android|iPhone/.test(navigator.userAgent)||cores<=4)?1:2;
      rp=pr(VS,FS);pp=pr(PVS,PFS);gl.bindAttribLocation=gl.bindAttribLocation;const qp=pr(QVS,QFS);gl.useProgram(qp);gq=null;gl._qp=qp;build();size();ready=true;
    }catch(e){fail=true;cv.style.display='none';document.documentElement.classList.add('no-gl');console.warn('WebGL unavailable → CSS fallback',e);return false}
    addEventListener('resize',()=>{size()});
    addEventListener('pointermove',e=>{P.tpx=e.clientX/innerWidth*2-1;P.tpy=e.clientY/innerHeight*2-1},{passive:true});
    document.addEventListener('visibilitychange',()=>{vis=!document.hidden;if(vis)kick()});
    return true}
  function draw(t,dt){
    gl.viewport(0,0,W,H);gl.clearColor(0,0,0,0);gl.clear(gl.COLOR_BUFFER_BIT|gl.DEPTH_BUFFER_BIT);
    const asp=W/H,cam=S.cam;const VP=mul(persp(.62,asp,.1,40),new Float32Array([1,0,0,0,0,1,0,0,0,0,1,0,0,0,-cam,1]));
    const rot=(P.spin+t*.07*S.speed);const M=model(S.x*asp*.9,S.y,S.s,S.rx+P.py*.16,S.ry+P.px*.3+Math.sin(t*.22)*.18+rot*.0,S.rz+Math.sin(t*.17)*.04);
    // glow quad
    const cx=(S.x*.9/(Math.tan(.31)*cam)*1.0);gl.disable(gl.DEPTH_TEST);gl.enable(gl.BLEND);gl.blendFunc(gl.ONE,gl.ONE_MINUS_SRC_ALPHA);
    const qp=gl._qp;gl.useProgram(qp);gl.bindVertexArray(gq);gl.uniform2f(qp.u.uC,S.x*.9/(Math.tan(.31)*cam)*1/1,S.y/(Math.tan(.31)*cam));gl.uniform2f(qp.u.uR,W,H);gl.uniform1f(qp.u.uG,S.glow*(1+S.flash*3));gl.uniform1f(qp.u.uTheme,S.theme);gl.uniform1f(qp.u.uFade,S.fade);gl.drawArrays(gl.TRIANGLES,0,3);
    gl.enable(gl.DEPTH_TEST);gl.depthFunc(gl.LEQUAL);gl.disable(gl.CULL_FACE);gl.blendFunc(gl.ONE,gl.ONE_MINUS_SRC_ALPHA);
    gl.useProgram(rp);gl.bindVertexArray(rVAO);gl.uniformMatrix4fv(rp.u.uVP,false,VP);gl.uniformMatrix4fv(rp.u.uM,false,M);gl.uniform3f(rp.u.uCam,0,0,cam);
    gl.uniform1f(rp.u.uT,t);gl.uniform1f(rp.u.uTheme,S.theme);gl.uniform1f(rp.u.uPh,(t*.085*S.speed)%1);gl.uniform1f(rp.u.uGlow,S.glow*(1+S.flash*1.5));gl.uniform1f(rp.u.uFade,S.fade);
    gl.drawElements(gl.TRIANGLES,idxN,gl.UNSIGNED_INT,0);
    const M2=model(S.x*asp*.9,S.y,S.s*.64,S.rx*1.0+.55+P.py*.1,S.ry*-1+.5+P.px*.2+Math.cos(t*.2)*.2,S.rz+1.05+t*.05);
    gl.uniformMatrix4fv(rp.u.uM,false,M2);gl.uniform1f(rp.u.uPh,(1-(t*.06*S.speed)%1));gl.uniform1f(rp.u.uFade,S.fade*.85);gl.drawElements(gl.TRIANGLES,idxN,gl.UNSIGNED_INT,0);
    gl.depthMask(false);gl.blendFunc(gl.ONE,gl.ONE);gl.useProgram(pp);gl.bindVertexArray(pVAO);gl.uniformMatrix4fv(pp.u.uVP,false,VP);gl.uniformMatrix4fv(pp.u.uM,false,M);gl.uniform1f(pp.u.uT,t);gl.uniform1f(pp.u.uSz,dpr*2.2);gl.uniform1f(pp.u.uSp,S.speed);gl.uniform1f(pp.u.uFade,S.fade*S.glow);gl.uniform1f(pp.u.uTheme,S.theme);
    gl.drawArrays(gl.POINTS,0,pN);gl.depthMask(true);gl.disable(gl.BLEND)}
  function frame(now){
    raf=0;if(!on||!vis)return;raf=requestAnimationFrame(frame);
    const dt=Math.min(.05,(now-last)/1000||.016);last=now;const t=now/1000;
    for(const k in K){const e=1-Math.exp(-dt*K[k]);S[k]+=(T[k]-S[k])*e}
    S.flash+=(0-S.flash)*(1-Math.exp(-dt*2.2));P.px+=(P.tpx-P.px)*(1-Math.exp(-dt*3));P.py+=(P.tpy-P.py)*(1-Math.exp(-dt*3));
    const t0=performance.now();draw(t,dt);
    // adaptive quality: average of last 90 CPU-side frame intervals
    ft.push(dt);fs+=dt;if(ft.length>45||fs>1.2){const a=ft.reduce((x,y)=>x+y)/ft.length;ft=[];fs=0;
      if(a>.026&&quality>.5){quality=quality>1?1:quality>.7?.7:.5;size();slow++}
      else if(a>.034&&quality<=.5){if(++bad>=2&&onSlow){bad=0;onSlow(a)}}else bad=Math.max(0,bad-1)}
  }
  function kick(){if(on&&vis&&!raf&&ready){last=performance.now();raf=requestAnimationFrame(frame)}}
  return{init,pose(o,snap){Object.assign(T,o);if(snap)for(const k in o)S[k]=o[k]},snapTo(o){Object.assign(T,o);Object.assign(S,o)},flash(v=1){S.flash=v},
    start(){on=true;kick()},stop(){on=false;if(raf){cancelAnimationFrame(raf);raf=0}},set onSlow(f){onSlow=f},resetSlow(){bad=0;quality=1;ft=[];size()},get ok(){return ready&&!fail},get state(){return S},get quality(){return quality},get tier(){return tier}}
})();
let mounted=false,capable=false;
const skip=()=>window.matchMedia('(prefers-reduced-motion: reduce)').matches||
  (navigator.connection&&navigator.connection.saveData===true);
function setMode(mode){
  if(!mounted||!capable)return;
  const canvas=document.getElementById('gl');
  const vig=document.querySelector('.vig');
  if(mode==='away'){
    GL.stop();canvas?.classList.remove('on');vig?.classList.remove('on');
    return;
  }
  GL.pose(mode==='home'?
    {x:.64,y:.05,s:.84,rx:.8,ry:-.38,fade:1,glow:1,speed:1}:
    {x:-.34,y:.04,s:1.12,rx:.85,ry:-.42,fade:1,glow:1,speed:1},true);
  canvas?.classList.add('on');vig?.classList.add('on');GL.start();
}
window.JWOwnerVisualGL=Object.freeze({
  mount(){
    if(mounted)return capable;
    mounted=true;
    const canvas=document.getElementById('gl');
    if(!canvas||skip()){canvas?.setAttribute('hidden','');return false}
    capable=GL.init(canvas)===true;
    if(capable){
      GL.onSlow=()=>{GL.stop();canvas.classList.remove('on');canvas.setAttribute('hidden','')};
      setMode(document.getElementById('login')?.hidden?'home':'login');
    }else canvas.setAttribute('hidden','');
    return capable;
  },
  setMode,stop(){if(mounted&&capable)GL.stop();}
});
})();
