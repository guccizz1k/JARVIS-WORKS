---
name: jt-design-system-bridge
description: Penpot token bridge with offline design-to-code consistency checks under existing UI regression and accessibility gates.
---

# jt-design-system-bridge — J TEAM optional capability (review only)

Scope: Design tokens and Penpot design metadata validation. J1–J6 and five-role J team authorization remain higher priority. Follow exact SHA evidence, independent verification and the existing 5-Gate harness; never infer an actual external runtime from local code.

1. Confirm `agents/team/jarvis_v1/capability_routing.json` and run `python scripts/jw_jteam_optional_capabilities.py --check` before use.
2. Use only sanitized locally exported scalar token maps with `penpot_token_diff`; never connect or mutate a remote Penpot MCP session implicitly.
3. A token match is not pixel-perfect UI, responsive browser testing, WCAG or actual Penpot MCP validation; keep visual and accessibility gates outstanding.
4. Mark external connection, independent model results, enterprise tenant-data correctness and deployment `NOT RUN` or `BLOCKED` until separately verified. Candidate fixture tests may be `PASS` only with command output.
5. Do not install upstream packages automatically, transmit private source or customer data, incur a paid API charge, merge `main`, modify an existing J1–J6 contract, or deploy outside an explicitly reviewed and authorized scope.

Approval: jarvis_lead can propose on isolated review branches. A successful local pilot is not a production approval.
