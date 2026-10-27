# J TEAM V13.5 — Professional design-system production kit

Date: 2026-10-27. Branch candidate only; no main merge or production changes.

## Source verification
- UI UX Pro Max Skill (MIT): https://github.com/nextlevelbuilder/ui-ux-pro-max-skill — current CLI supports Codex `uipro init --ai codex` but **we do not install, clone, or execute external installer**. Local Codex-compatible SKILL.md is a curated set of design principles with its own deterministic token engine, not the full third-party CLI package.
- Motion (MIT): https://motion.dev/docs/quick-start and https://www.npmjs.com/package/motion — pinned `motion@14.6.0` in `design-lab/package.json`; standard ESM build via esbuild, isolated from `app/static`.
- 21st MCP (remote; terms/individual component license apply): https://21st.dev/mcp and https://github.com/21st-dev/magic-mcp — replaces previous Magic MCP. The API key and remote server setup need separate user connection. NO KEY is written and no paid calls are triggered.

## Real locally implemented outputs
1. `scripts/jw_jteam_design_factory.py`: fixed contract + WCAG 2.x relative luminance/contrast and generated scoped design CSS; fail closed on unauthorized palettes or unreviewed policy changes.
2. `design-lab/design.css`: enterprise teal palette matching existing JARVIS-WORKS app styles, system typography, responsive cards, minimum 44px action, focus-visible, accessibility reduced-motion. Real app CSS is unchanged.
3. `design-lab/src/motion.js` with bundled runtime from pinned Motion: 240 ms opacity/transform animation; reduced-motion skips animation, status interaction still works.
4. `intake_21st_component`: strict structured source domain fields, escaped semantic HTML previews only, React proposals must undergo human conversion and license review. No JSX eval, remote code or third-party access.
5. Three new governed skills; original five J TEAM roles, all 15 previous skill entries and J1–J6 preserved.

## Final acceptance gates
Gate 1: Python syntax, skill registry, npm pinned versions/bundle.
Gate 2: design-color math, CSS determinism, component XSS/injection tests, Motion browser interaction.
Gate 3: original skill/team contracts and full Python suite.
Gate 4: Playwright desktop + mobile viewport 375/768/1440, reduced-motion, overflow, focus indicator, accessible live region and screenshots.
Gate 5: no third-party secret/remote service/data movement, no paid model/build, maintain private repo and draft branch; actual external 21st MCP and full upstream Pro Max CLI remain NOT RUN. No production release/main merge.

Validation: `python scripts/jw_jteam_design_factory.py --check`, `python -m pytest -q tests/test_jw_jteam_design_factory.py tests/test_jw_skill_contract.py`, and `design-lab/e2e_browser.py` after isolated Motion installation and build. Measured outcomes require exact CI SHA. Reuse existing J TEAM focused/expanded/all regression and provide screenshot artifacts. Never invent visual PASS.
