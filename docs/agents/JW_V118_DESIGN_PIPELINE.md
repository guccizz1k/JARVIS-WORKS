# JARVIS-WORKS — Eight-stage product design pipeline under J1–J6

The eight stages extend the **existing single five-role team**, not create eight extra agents.

1. Site Strategist — deputy: prioritize the primary user action, currently upload a document and review extracted data.
2. Reference Hunter — deputy: inspect three licensed/public SaaS references, record transferable patterns, reject imitation.
3. Design System — deputy_manager: 6 semantic colors, 6 type levels, 8 spacing steps, component tokens, minimum WCAG contrast 4.5:1 for normal text.
4. Hero Builder — deputy_manager: three headline/subheadline/CTA alternatives; 1440px and 390px first-fold evidence.
5. Section Writer — deputy_manager: accurate product copy; no invented reviews, adoption, savings or accuracy.
6. Motion Detailer — manager: <=5 purposeful animations, <=600ms, prefers-reduced-motion, no lost keyboard focus.
7. Performance Checker — director: independent browser screenshots, real workflow E2E, Lighthouse, accessibility and regression proof on same SHA.
8. Launch Manager — jarvis_lead: final review checklist only; no production deployment, main merge, paid API or data migration.

All eight stages retain J1–J6 requirements, 5-gate evidence policy, RLS and tenant isolation. This design pipeline is not proof that five independent AI models ran or that UI changes have passed browser tests.

Local structural tests: `python -m unittest tests.test_jw_design_eight_stage_gate -v`.
Evidence audit: `python scripts/jw_design_eight_stage_gate.py --evidence path/to/evidence.json`.
