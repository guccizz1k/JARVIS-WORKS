# JARVIS-WORKS cinematic UX design contract · V22.2 · 2026-11-03

## User-supplied reference
- Source: user-uploaded 31.4-second, 512 × 1108 mobile screen recording of a COSMOS-style website.
- Observed: almost-black editorial backdrop; floating photographic/decorative panels; generous typographic space; layered scrolling transitions, understated luminous gradients, minimal pill controls, and staged content reveals.
- The reference is an **art-direction source**, not a source of copied images, copy, logos, fonts, or a promise of pixel-level equality.

## Required permanent visual rules for subsequent versions
1. **Brand palette:** abyss `#07090D`, graphite `#111722`, silver `#C9D6E6`, ice `#ADC7E2`, frost `#EAF0F7`, muted `#A6B2C2`. Minimize saturated colors. Keep prior premium dark-glass mood.
2. **One infinity light:** keep the original V21.2 SVG + Canvas transparent crystal infinity and its single bright continuously moving photon. Do not overlay a second competing photon or switch to a static video.
3. **Immersive 3D scroll:** communicate depth through composited layers, perspective, controlled camera-like motion, and independent editorial scenes. Pointer parallax is optional and never blocks scroll or buttons.
4. **Working route transitions:** preserve V21.1 verified source-aperture navigation. Decorative route sweeps must never delay, intercept or emulate actual navigation.
5. **Language:** all new visible business copy in Korean. Avoid English filler labels. Product name JARVIS-WORKS remains a proper name.
6. **Typography:** prefer locally available Pretendard / Noto Sans KR / Apple SD Gothic Neo / Malgun Gothic; maintain balanced sizing; body text at least 16–17px in cinematic scenes and large semantic headings.
7. **Functional protection:** no changes to backend API, session, MFA, tenant RLS, money calculations, user approvals, import/quote/order/invoice/messenger logic. No speculative performance numbers. All CTA buttons route through the already verified business navigation.
8. **Responsive scope:** product remains desktop-only as established in V21.4; no partially working financial interface on unsupported mobile screens. Verify 1280/1366/1440/1920px and browser heights.
9. **Accessibility:** reduced-motion disables continuous scene ornament and parallax; do not hide functional content without JS; keyboard focus and semantic headings required.
10. **Performance/security:** no video autoplay, third-party CDN, external fonts, reference screenshots, analytics beacons, or memory-heavy extra render loops. Pause existing canvas when hidden; scroll updates only by animation-frame coalescing.
11. **Protection:** never merge main or deploy to production without explicit approval; hosted testing only within approved free isolated stage. Keep GitHub review branch / Draft PR until final approval.
12. **Verification:** complete 5 Gates with actual browser screenshot evidence, no FAIL/ERROR/SKIP, and secure user session & core business route regression. Baseline tests must remain green. A screen looking good alone is not PASS.

## External creative tools
Higgsfield offers brand creation after the user connects the provider. Brand tokens are stored in `docs/design/V222_CINEMATIC_BRAND_TOKENS_20261103.json`. Seedance 2.0 is not directly connected in this tool environment. The user requested runtime cursor and scroll responses, so the site uses deterministic, self-contained SVG/Canvas/CSS/JS rather than a pre-rendered movie.

## Reference review methodology
Sampled representative frames at 0.6, 2.5, 5, 8, 11, 14, 17, 20, 23, 26, 29 and 31 seconds. Do not assume the original video contains the requested infinity asset; the infinity requirement comes from the user's instructions and existing project architecture.
