/**
 * JARVIS-WORKS V23.0 Stage 1.
 * UI integration only: the original delegated login POST, CSRF, MFA, session,
 * error handling, API, business routing and database are NEVER overwritten.
 * Login success is observed from the authenticated shell after the original
 * backend responds successfully.
 */
import * as THREE from 'three';
import { InfinityMark } from './InfinityMark.js';
import { PostPipeline } from './PostPipeline.js';

(() => {
  'use strict';
  const login = document.getElementById('login-view');
  const shell = document.getElementById('app-shell');
  const main = document.getElementById('main-content');
  if (!login || !shell || !main) return;

  const reducedQuery = window.matchMedia('(prefers-reduced-motion: reduce)');
  const mobile = window.innerWidth < 1100;
  const state = {
    mode: 'login', pendingAuthentication: false, transitionStart: 0,
    raf: 0, lastFrame: 0, slowFrames: 0, fastFrames: 0,
    tier: 0, pointerX: 0, pointerY: 0, actualPointerX: 0, actualPointerY: 0
  };
  const clamp = (n, a, b) => Math.min(b, Math.max(a, n));
  const easeInOut = t => t < .5 ? 8 * t * t * t * t
    : 1 - Math.pow(-2 * t + 2, 4) / 2;
  const easeOut = t => 1 - Math.pow(1 - t, 3);

  const root = document.createElement('div');
  root.id = 'jw300-cinema-root';
  root.className = 'jw300-cinema-root';
  root.setAttribute('aria-hidden', 'true');
  const canvas = document.createElement('canvas');
  canvas.id = 'jw300-global-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  root.append(canvas);

  const transition = document.createElement('div');
  transition.id = 'jw300-auth-transition';
  transition.className = 'jw300-auth-transition';
  transition.setAttribute('aria-hidden', 'true');
  const streak = document.createElement('div');
  streak.className = 'jw300-auth-streak';
  const status = document.createElement('div');
  status.className = 'jw300-auth-message';
  status.setAttribute('role', 'status');
  status.innerHTML = '<span aria-hidden="true" class="jw300-auth-check">✓</span>' +
    '<span>로그인 완료<small>JARVIS-WORKS 워크스페이스를 엽니다</small></span>';
  transition.append(streak, status);
  document.body.append(root, transition);

  let renderer;
  let mark;
  let scene;
  let camera;
  let phaseLength = 2600;
  let frozenLoginRect = null;
  let destroyed = false;

  try {
    // Exactly one global WebGL canvas shared between login and all app pages.
    scene = new THREE.Scene();
    camera = new THREE.PerspectiveCamera(38, innerWidth / innerHeight, 0.1, 90);
    camera.position.set(0, 0, 9.2);
    scene.add(new THREE.AmbientLight('#687991', 1.0));

    const key = new THREE.DirectionalLight('#f5f9ff', 4.5);
    key.position.set(-3, 5, 5);
    const rim = new THREE.DirectionalLight('#b4d4ff', 3.5);
    rim.position.set(3, -1, -4);
    scene.add(key, rim);

    const ground = new THREE.Mesh(
      new THREE.CircleGeometry(2.65, 96),
      new THREE.MeshPhysicalMaterial({
        color: '#a5b7c9', metalness: 0.65, roughness: 0.22,
        transparent: true, opacity: 0.075, depthWrite: false, side: THREE.DoubleSide
      })
    );
    ground.rotation.x = -Math.PI / 2;
    ground.position.y = -1.48;
    scene.add(ground);
    mark = new InfinityMark(scene);
    renderer = new PostPipeline(scene, camera, canvas, { mobile });
    renderer.setReducedMotion(reducedQuery.matches);
    if (renderer.isSoftware) {
      // Same physically modelled ribbon; disable costly per-fragment
      // refraction only on software GPUs (CI, VMs or GPU fallback).
      mark.ribbon.material.transmission = 0;
      mark.ribbon.material.roughness = 0.21;
      mark.ribbon.material.needsUpdate = true;
    }
    state.tier = renderer.tier;
    document.documentElement.classList.add('jw300-three-ready');
    // Tell the previous decorative Canvas renderer to suspend its own RAF.
    document.dispatchEvent(new Event('visibilitychange'));
  } catch (error) {
    // Presentation fail-open: original V21.2 SVG+Canvas remains functional.
    console.warn('JARVIS-WORKS: 3D decorative layer unavailable; original infinity retained.');
    root.remove();
    transition.remove();
    try { mark?.dispose(); renderer?.dispose(); } catch {}
    window.JW_CINEMATIC_STAGE1 = Object.freeze({
      version: '23.0', renderer: 'original-svg-canvas-fallback',
      state: () => 'fallback', ready: false
    });
    return;
  }

  const isAuthenticated = () => !shell.classList.contains('hidden') &&
    login.classList.contains('hidden');
  const targetMode = () => {
    if (!isAuthenticated()) return 'login';
    return main.querySelector('.jw210-home') ? 'main' : 'mini';
  };

  function stageRect(mode) {
    const selector = mode === 'login'
      ? '.jw211-login-infinity'
      : mode === 'main'
        ? '.jw210-infinity-stage'
        : '.jw210-brand';
    const element = document.querySelector(selector);
    const rect = element?.getBoundingClientRect();
    if (rect && rect.width > 0 && rect.height > 0) return rect;
    if (mode === 'transition' && frozenLoginRect) return frozenLoginRect;
    return { left: innerWidth * .5 - 180, top: innerHeight * .3,
             width: 360, height: 220 };
  }

  function moveSculpture(time, zoom, ratio) {
    const mode = state.mode;
    const current = mode === 'transition'
      ? (ratio < .65 ? 'transition' : 'main') : mode;
    const measured = current === 'transition'
      ? frozenLoginRect || stageRect('login') : stageRect(current);
    const cx = measured.left + measured.width * .5;
    const cy = measured.top + measured.height * .5;
    const pxPerWorld = innerHeight /
      (2 * Math.tan(THREE.MathUtils.degToRad(camera.fov / 2)) * (9.2 / zoom));
    const objectWidth = 6.2;
    const desired = current === 'mini'
      ? Math.min(measured.width * 0.9, 46)
      : Math.min(measured.width * .96, current === 'login' ? 690 : 770);
    const baseScale = clamp(desired / (objectWidth * pxPerWorld) * zoom,
      current === 'mini' ? .035 : .55,
      current === 'mini' ? .17 : 1.45);
    const worldX = (cx - innerWidth * .5) / pxPerWorld;
    const worldY = -(cy - innerHeight * .5) / pxPerWorld;
    const cursorX = state.actualPointerX;
    const cursorY = state.actualPointerY;
    mark.group.position.set(
      worldX + (mode === 'main' ? cursorX * .07 : 0),
      worldY + (mode === 'main' ? cursorY * .04 : 0),
      0
    );
    mark.group.scale.setScalar(baseScale);
    mark.group.rotation.y = mode === 'mini' ? 0 :
      Math.sin(time * Math.PI / 10) * THREE.MathUtils.degToRad(1.6) +
      (mode === 'main' ? cursorX * .035 : 0);
    mark.group.rotation.x = mode === 'mini' ? 0 :
      Math.cos(time * Math.PI / 10) * THREE.MathUtils.degToRad(.7);
    mark.group.visible = true;
  }

  function activateTransition(now) {
    if (state.mode === 'transition') return;
    state.mode = 'transition';
    state.pendingAuthentication = false;
    state.transitionStart = now;
    phaseLength = reducedQuery.matches ? 400 : 2600;
    root.dataset.state = 'transition';
    document.body.classList.add('jw300-transitioning');
    transition.classList.add('jw300-auth-visible');
    transition.setAttribute('aria-hidden', 'false');
    mark.setReveal(1);
    status.setAttribute('aria-live', 'polite');
  }

  function closeTransition() {
    state.mode = targetMode();
    document.body.classList.remove('jw300-transitioning');
    transition.classList.remove('jw300-auth-visible');
    transition.setAttribute('aria-hidden', 'true');
    status.removeAttribute('aria-live');
    mark.setReveal(1);
    root.dataset.state = state.mode;
  }

  const probe = () => {
    if (destroyed) return;
    if (!isAuthenticated()) {
      state.mode = 'login';
      state.pendingAuthentication = false;
      closeTransition();
      root.dataset.state = 'login';
      return;
    }
    if (state.pendingAuthentication && state.mode === 'login') {
      activateTransition(performance.now());
      return;
    }
    if (state.mode !== 'transition') {
      state.mode = targetMode();
      root.dataset.state = state.mode;
    }
  };

  // This is a VISUAL listener only. The original delegated authentication remains
  // the sole authority; no password, MFA value or cookie is intercepted.
  document.addEventListener('submit', event => {
    if (event.target?.id !== 'login-form') return;
    state.pendingAuthentication = true;
    const rect = stageRect('login');
    frozenLoginRect = { left: rect.left, top: rect.top,
                        width: rect.width, height: rect.height };
  }, true);

  // The app updates these DOM nodes after success/error; react to the result.
  const observer = new MutationObserver(probe);
  observer.observe(login, { attributes: true, attributeFilter: ['class'] });
  observer.observe(shell, { attributes: true, attributeFilter: ['class'] });
  observer.observe(main, { childList: true, subtree: false });
  document.addEventListener('pointermove', event => {
    state.pointerX = clamp((event.clientX / innerWidth - .5) * 2, -1, 1);
    state.pointerY = clamp((event.clientY / innerHeight - .5) * 2, -1, 1);
  }, { passive: true });
  window.addEventListener('resize', () => renderer.resize(), { passive: true });
  reducedQuery.addEventListener?.('change', () => {
    renderer.setReducedMotion(reducedQuery.matches);
    if (state.mode === 'transition') {
      // Accessibility preference changes must not leave an overlay blocking UI.
      closeTransition();
    }
    requestAnimationFrame(frame);
  });
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && !state.raf) state.raf = requestAnimationFrame(frame);
  });

  function frame(now) {
    state.raf = 0;
    if (destroyed || document.hidden) return;
    const dt = state.lastFrame ? Math.min((now - state.lastFrame) / 1000, .10) : .016;
    state.lastFrame = now;
    const time = now / 1000;
    const reduced = reducedQuery.matches;
    state.actualPointerX += (state.pointerX - state.actualPointerX) * .07;
    state.actualPointerY += (state.pointerY - state.actualPointerY) * .07;

    let zoom = 1;
    let flash = 0;
    let flare = 0;
    let aberration = 0;
    let bloom = .28;
    let focus = 9.2;
    let t = 1;
    if (state.mode === 'transition') {
      t = clamp((now - state.transitionStart) / phaseLength, 0, 1);
      if (reduced) {
        flash = flare = aberration = 0;
      } else {
        if (t < 1 / 2.6) {
          const x = easeInOut(t * 2.6);
          zoom = 1 + 2.2 * x;
          bloom = .28 + 1.45 * x;
          focus = 9.2 - 3.5 * x;
          if (x > .82) mark.setReveal(1);
        } else if (t < 1.2 / 2.6) {
          zoom = 3.2;
          flash = Math.sin(Math.PI * (t * 2.6 - 1) / .2) * .68;
          flare = Math.sin(Math.PI * (t * 2.6 - 1) / .2) * .9;
          aberration = .24;
          bloom = 1.7;
          focus = 5.6;
          mark.setReveal(0);
        } else {
          const x = clamp((t * 2.6 - 1.2) / 1.2, 0, 1);
          zoom = 3.2 - 2.2 * easeOut(x);
          bloom = 1.7 - 1.42 * easeOut(x);
          focus = 5.6 + 3.6 * easeOut(x);
          mark.setReveal(easeOut(x));
        }
      }
      if (t >= 1) closeTransition();
    }
    camera.position.z = 9.2 / zoom;
    const tremor = !reduced && state.mode === 'transition' && t < .43
      ? Math.sin(time * 64) * .009 : 0;
    camera.position.x = tremor;
    camera.position.y = tremor * .42;
    camera.lookAt(0, 0, 0);
    moveSculpture(time, zoom, t);
    mark.tick(dt, time, state.mode, reduced);
    renderer.frame(time, state.mode, zoom, { flash, flare, aberration, bloom, focus });

    // Adaptive 45 FPS budget. Reduce DOF first, then bloom/resolution,
    // then post entirely. Never degrade forms, data or accessibility.
    const fps = dt > .002 ? 1 / dt : 60;
    if (!reduced && state.mode !== 'transition') {
      if (fps < 45) { state.slowFrames++; state.fastFrames = 0; }
      else if (fps > 54) { state.fastFrames++; state.slowFrames = 0; }
      if (state.slowFrames > 12 && state.tier < 3) {
        state.tier++; state.slowFrames = 0;
        renderer.setQuality(state.tier);
      }
      if (state.fastFrames > 480 && state.tier > (renderer.isSoftware ? 2 : 0)) {
        state.tier--; state.fastFrames = 0;
        renderer.setQuality(state.tier);
      }
    }
    if (!reduced || state.mode === 'transition') {
      state.raf = requestAnimationFrame(frame);
    }
  }

  function destroy() {
    destroyed = true;
    cancelAnimationFrame(state.raf);
    observer.disconnect();
    mark.dispose();
    renderer.dispose();
    root.remove();
    transition.remove();
    document.documentElement.classList.remove('jw300-three-ready');
  }

  probe();
  state.raf = requestAnimationFrame(frame);
  window.JW_CINEMATIC_STAGE1 = Object.freeze({
    version: '23.0', ready: true, renderer: 'threejs-global-webgl',
    states: Object.freeze(['login', 'transition', 'main', 'mini']),
    state: () => state.mode,
    singleCanvas: () => document.querySelectorAll('#jw300-global-canvas').length === 1,
    qualityTier: () => state.tier,
    bloomEnabled: () => renderer.bloom.enabled,
    focusEnabled: () => renderer.bokeh.enabled,
    reducedMotion: () => reducedQuery.matches,
    destroy
  });
})();
