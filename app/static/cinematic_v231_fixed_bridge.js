/* Bridges the user's V3 FIXED NEXUS visual system into the actual JARVIS-WORKS pages.
 * Authentication, OTP, real navigation, APIs, business data, and approvals are untouched.
 */
(() => {
  'use strict';
  const login = document.getElementById('login-view');
  const shell = document.getElementById('app-shell');
  const main = document.getElementById('main-content');
  if (!login || !shell || !main) return;
  document.documentElement.classList.add('jw231-active');
  // Retire prior visual-only WebGL scene; none of its business logic is involved.
  const old = window.JW_CINEMATIC_STAGE1;
  if (old && typeof old.destroy === 'function') old.destroy();
  // The V3 fixed artwork's anchor is the original login infinity frame and the
  // original real dashboard stage. No fake login or simulated business data.
  const headline = login.querySelector('.jw211-login-headline');
  if (headline) {
    const tag = headline.querySelector('span');
    const title = headline.querySelector('h2');
    if (tag) tag.textContent = 'ENTER THE NEXUS · JARVIS-WORKS';
    if (title) title.textContent = '새로운 차원으로 접속합니다.';
  }
  const intro = login.querySelector('.login-card > p');
  if (intro) intro.textContent = '기업 계정으로 안전하게 로그인합니다. MFA와 모든 승인 절차는 기존 방식으로 작동합니다.';
  // Suppress the predecessor's duplicate visual assets while the fixed render is active.
  // The original elements remain in DOM so the existing UI contract remains intact.
  window.JW231_FIXED = Object.freeze({
    version: '23.1',
    source: 'JARVIS_NEXUS_V3_FIXED_code.zip',
    mode: 'visual-only',
    realAuthentication: () => login.querySelector('form#login-form') !== null,
    realNavigation: () => document.getElementById('nav') !== null,
    state: () => !shell.classList.contains('hidden') && login.classList.contains('hidden') ? 'authenticated' : 'login',
    active: () => document.documentElement.classList.contains('jw231-active')
  });
})();
