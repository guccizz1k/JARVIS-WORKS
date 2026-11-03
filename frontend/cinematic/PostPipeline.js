/**
 * Stage 1 · PostPipeline
 * Same-origin, one WebGLRenderer / one EffectComposer.
 * Pipeline: Render -> Bokeh DOF -> Bloom -> film/vignette/aberration/flare
 * -> OutputPass. All post FX are cosmetic and can be degraded independently.
 */
import * as THREE from 'three';
import { EffectComposer } from 'three/addons/postprocessing/EffectComposer.js';
import { RenderPass } from 'three/addons/postprocessing/RenderPass.js';
import { BokehPass } from 'three/addons/postprocessing/BokehPass.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { ShaderPass } from 'three/addons/postprocessing/ShaderPass.js';
import { OutputPass } from 'three/addons/postprocessing/OutputPass.js';

const POST_SHADER = {
  uniforms: {
    tDiffuse: { value: null },
    uTime: { value: 0 },
    uResolution: { value: new THREE.Vector2(1, 1) },
    uGrain: { value: 0.04 },
    uVignette: { value: 0.31 },
    uAberration: { value: 0 },
    uFlare: { value: 0 },
    uFlash: { value: 0 }
  },
  vertexShader: [
    'varying vec2 vUv;',
    'void main() {',
    '  vUv = uv;',
    '  gl_Position = projectionMatrix * modelViewMatrix * vec4(position,1.);',
    '}'
  ].join('\n'),
  fragmentShader: [
    'uniform sampler2D tDiffuse;',
    'uniform float uTime, uGrain, uVignette, uAberration, uFlare, uFlash;',
    'uniform vec2 uResolution;',
    'varying vec2 vUv;',
    'float hash(vec2 p) {',
    '  return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453123);',
    '}',
    'void main() {',
    '  vec4 base = texture2D(tDiffuse,vUv);',
    '  vec2 shifted=(vUv-vec2(.5)) * uAberration * .008;',
    '  vec3 rgb=vec3(texture2D(tDiffuse,vUv+shifted).r,',
    '                base.g,',
    '                texture2D(tDiffuse,vUv-shifted).b);',
    '  float radial=distance(vUv,vec2(.5));',
    '  float vignette=1.-uVignette*smoothstep(.15,.72,radial);',
    '  float grain=(hash(floor(vUv*uResolution*vec2(.9,.92)+uTime*14.))- .5)',
    '               * uGrain;',
    '  float horizontal=exp(-pow((vUv.y-.5)*28.,2.));',
    '  float central=exp(-pow((vUv.x-.5)*2.4,2.));',
    '  float streak=horizontal*central*uFlare;',
    '  vec3 color=rgb*vignette+vec3(grain)+vec3(.81,.91,1.)*streak;',
    '  color=mix(color,vec3(1.),clamp(uFlash,0.,1.));',
    '  float luminous=dot(max(color,vec3(0.)),vec3(.21,.72,.07));',
    '  float alpha=clamp(max(base.a,luminous*.6+streak*.3+uFlash),0.,1.);',
    '  gl_FragColor=vec4(max(color,vec3(0.)),alpha);',
    '}'
  ].join('\n')
};

const clamp = (x, a, b) => Math.max(a, Math.min(b, x));

export class PostPipeline {
  constructor(scene, camera, canvas, { mobile = false } = {}) {
    this.scene = scene;
    this.camera = camera;
    this.mobile = mobile;
    this.tier = 0;
    this.reduced = false;

    const renderer = new THREE.WebGLRenderer({
      canvas, alpha: true, antialias: false, powerPreference: 'high-performance',
      stencil: false, preserveDrawingBuffer: false
    });
    renderer.setClearColor(0x000000, 0);
    renderer.setPixelRatio(1);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.2;
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    this.renderer = renderer;
    // Headless/VM SwiftShader is genuine WebGL, but Bokeh+transmission can
    // freeze screenshots and block the UI. Force adaptive safe quality.
    const gl = renderer.getContext();
    const debug = gl.getExtension('WEBGL_debug_renderer_info');
    const gpuName = debug
      ? String(gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) || '')
      : String(gl.getParameter(gl.RENDERER) || '');
    this.isSoftware = /swiftshader|llvmpipe|softpipe|software/i.test(gpuName);

    this.composer = new EffectComposer(renderer);
    this.renderPass = new RenderPass(scene, camera);
    this.renderPass.clearAlpha = 0;
    this.bokeh = new BokehPass(scene, camera, {
      focus: 9.2, aperture: 0.000085, maxblur: 0.0042,
      width: 1, height: 1
    });
    this.bloom = new UnrealBloomPass(new THREE.Vector2(1, 1), 0.28, 0.32, 0.83);
    this.post = new ShaderPass(POST_SHADER);
    this.output = new OutputPass();

    this.composer.addPass(this.renderPass);
    this.composer.addPass(this.bokeh);
    this.composer.addPass(this.bloom);
    this.composer.addPass(this.post);
    this.composer.addPass(this.output);

    this.width = 1;
    this.height = 1;
    this.resize();
    this.setQuality(this.isSoftware ? 2 : 0);
  }

  setReducedMotion(value) {
    this.reduced = !!value;
    this.setQuality(this.tier);
  }

  setQuality(tier) {
    this.tier = clamp(Math.round(tier), 0, 3);
    this.bokeh.enabled = !this.mobile && !this.reduced && this.tier === 0;
    this.bloom.enabled = this.tier < 3;
    this.post.enabled = this.tier < 3;
    const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
    const pixelRatio = this.tier === 0 ? dpr : this.tier === 1 ? Math.min(1, dpr) : 0.78;
    this.composer.setPixelRatio(pixelRatio);
    this.composer.setSize(this.width, this.height);
    this.post.uniforms.uResolution.value.set(this.width * pixelRatio,
                                             this.height * pixelRatio);
    if (this.bloom) this.bloom.strength = this.tier >= 2 ? 0.10 : 0.28;
    this.post.uniforms.uGrain.value = this.tier >= 2 ? 0.018 : 0.04;
    this.post.uniforms.uVignette.value = 0.31;
    this.post.uniforms.uAberration.value = 0;
  }

  resize() {
    this.width = Math.max(1, window.innerWidth);
    this.height = Math.max(1, window.innerHeight);
    this.renderer.setSize(this.width, this.height, false);
    this.camera.aspect = this.width / this.height;
    this.camera.updateProjectionMatrix();
    this.composer.setSize(this.width, this.height);
    if (this.post) this.post.uniforms.uResolution.value.set(this.width, this.height);
  }

  frame(time, state, zoom, { flash = 0, flare = 0, aberration = 0,
                             focus = 9.2, bloom = 0.28 } = {}) {
    this.post.uniforms.uTime.value = time;
    this.post.uniforms.uFlash.value = flash;
    this.post.uniforms.uFlare.value = flare;
    this.post.uniforms.uAberration.value =
      this.mobile || this.reduced || this.tier !== 0 ? 0 : aberration;
    this.bokeh.uniforms.focus.value = focus;
    this.bokeh.uniforms.maxblur.value =
      this.reduced || this.tier !== 0 ? 0 : state === 'transition' ? 0.008 : 0.0042;
    this.bloom.strength = clamp(bloom, 0.08, this.tier >= 2 ? 0.18 : 1.8);
    this.composer.render();
  }

  dispose() {
    for (const pass of this.composer.passes) pass.dispose?.();
    this.composer.dispose();
    this.renderer.dispose();
  }
}
