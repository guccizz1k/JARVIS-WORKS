# J team — five-tool role routing (review-only)

J1–J6 and the eight-stage design workflow remain mandatory. These are tool **assignments and opt-in pilot proposals**, not evidence of new installations or test PASS.

| Tool | Owner | Reviewer | Use |
|---|---|---|---|
| Playwright | 차장 | 부장 | Reuse existing Chromium browser test scripts; 과장 extends scenarios |
| axe-core | 차장 | 부장 | WCAG audits in isolated browser pilot; not installed |
| Ruff | 과장 | 부장 | Baseline Python lint; no broad reformat |
| Hypothesis | 과장 | 부장 | Property tests for integer KRW, OCR parsing, idempotency |
| Schemathesis | 과장 | 부장 | Isolated FastAPI OpenAPI negative/adversarial testing |

대리 verifies GitHub sources, licenses, pinned revisions, dependency advisories and alternatives for all five. 총괄 자비스 reconciles measured pilot results and prepares Draft PR only.

## Acceptance gates
1. Record source/license/commit and maintenance/security risks.
2. Check existing dependency versions, lock state, Python/browser compatibility.
3. Run baseline and candidate on the same **synthetic** fixtures in an isolated environment.
4. Record tests, failures, skips, latency, memory, false positives, vulnerabilities and rollback.
5. Obtain independent review on exact SHA; submit Draft PR. Main merge and production require separate user approval.

Existing Playwright scripts are in `scripts/ci_playwright_cli_*.py`. axe-core, Ruff, Hypothesis and Schemathesis remain uninstalled until individual pilots are verified. This commit makes no third-party dependency change and makes no model API call.
