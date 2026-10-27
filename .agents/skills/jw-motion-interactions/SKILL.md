---
name: jw-motion-interactions
description: Build motion-sensitive accessible interactions in the isolated Vanilla JavaScript Motion 14.6.0 lab, with real browser validation prior to adoption.
---

# jw-motion-interactions — J TEAM review-only production skill

Use `design-lab/src/motion.js` with pinned `motion@14.6.0`. Default opacity 1 and transform safe; never hide content pending JS. Honor `prefers-reduced-motion` and keep animations transform/opacity, short duration (<300ms). Build and verify actual runtime on browser via `design-lab/e2e_browser.py`, keyboard functionality and reduced-motion emulation. This library is not loaded by current `app/static`; staging or product use needs independent user approval and regression proof. Motion+ premium features are not authorized.

J1–J6 review safeguards: report PASS only with exact SHA proof; otherwise BLOCKED. No main merge, deployment, paid resource, secret transmission or untrusted upstream code execution. Guard original HTML/CSS/Vanilla JS and all existing enterprise features.
