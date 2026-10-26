---
name: jw-ui-ux-accessibility
description: Review the JARVIS-WORKS B2B desktop HTML CSS vanilla JavaScript UI for accessibility keyboard usability consistent layout workflow clarity and browser regressions.
---

# JARVIS-WORKS UI/UX accessibility reviewer

J1–J6 subordinate review-only skill; never merge to main or declare launch PASS. Missing browsers and UX evidence are BLOCKED or NOT RUN.

1. Confirm source SHA and inspect actual app/static/index.html, style.css, app.js, automation and messenger assets. This is FastAPI plus vanilla JS; do not assume React or add Next/Vercel.
2. Walk enterprise tasks: company selection, search and scrolling, chat plus menu/file sends, document uploads, OCR preview and human approval, quote/order/payment status, errors and recovery.
3. Inspect semantic headings, form labels, keyboard tab order, visible focus, accessible names, status announcements, contrast, zoom, responsive overflow, client-side validation, tabular currency and Korean wording.
4. Check motion and loading: prefers-reduced-motion, smooth but nonblocking transitions, no disappearing warnings, no blocking animations, no false progress. Preserve user-confirmed alignment and left/right whitespace.
5. Reuse existing isolated Playwright CLI and browser regression scripts; measure at PC viewport widths and Chrome/Edge, check keyboard-only plus screen-reader semantics, screenshots+DOM together. Prefer optional axe-core only after explicit dependency/license approval.
6. Apply only task-specific ideas from pinned Vercel web-design-guidelines and Microsoft Playwright, never pull latest remote prompt or execute upstream installer. Record file:line, reproducible before/after and browser PASS/FAIL/NOT RUN.
7. Preserve J1–J6 5-Gate, company RLS, financial approvals and rollback; product release remains BLOCKED without real authenticated browser evidence.
