---
name: jw-design-intelligence
description: Generate WCAG-audited enterprise design tokens and consistent layouts for vanilla HTML CSS J TEAM screens without replacing J1-J6 quality gates.
---

# jw-design-intelligence — J TEAM review-only production skill

Use UI UX Pro Max's official Codex-compatible design methodology as a read-only reference. Curated locally, not the upstream CLI installed. Begin with task/audience/contrast hierarchy then run `python scripts/jw_jteam_design_factory.py --check` and inspect `agents/team/jarvis_v1/pro_design_system.json` and `design-lab/design.css`. For real product changes, compare system fonts, 44px minimum touch target, responsive grids, 4.5:1 small text, 3:1 focus visibility, accessible keyboard flows and screenshot proofs. NEVER swap the app to React automatically.

J1–J6 review safeguards: report PASS only with exact SHA proof; otherwise BLOCKED. No main merge, deployment, paid resource, secret transmission or untrusted upstream code execution. Guard original HTML/CSS/Vanilla JS and all existing enterprise features.
