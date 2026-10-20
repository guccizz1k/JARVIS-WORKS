# JARVIS WORKS — permission-based B2B discovery kit

**INTERNAL / REVIEW ONLY. NOT RELEASED. NOT AN ADVERTISEMENT.** Prepared 2026-10-20. No personally identifying contact list, unsolicited messages, company onboarding, production customer data or spend.

## Evidence-safe positioning
Working hypothesis: Korean SMEs handling quotes, purchase orders, files and messages with multiple counterparties may have trouble maintaining context. This is a hypothesis, not a proven pain or a market-size statistic.

One-line prototype narrative: **"거래처와 주고받는 대화·파일·발주서의 맥락을 이어주는 기업 업무 메신저 — 검증 중".** Existing code is a nonproduction review candidate; identity verification, full real PostgreSQL cutover and rollback, platform security and privacy must pass before public launch.

## Three distinctly testable value messages
- **A. 업무 단순성** — "거래처를 검색해 바로 대화하고, 파일을 같은 흐름에서 확인하는 경험." What feels simpler than a general messenger?
- **B. 거래 맥락** — "발주서가 오가는 대화에서 누가 왜 보냈는지 이해하기 쉽도록." Which evidence of action matters to users?
- **C. 인수인계** — "메일·파일·메신저 사이에서 놓치는 업무 맥락을 줄이는 방법." Which actual handoff breaks today?

These are hypotheses, not performance guarantees or already-released capabilities. Evaluate with a synthetic demo, not real enterprise documents.

## Consent-first moderated interview outline (20–25 min)
Only ask after explicit consent and with a clear privacy notice; record anonymous aggregate feedback by default.
1. How many partner companies do you communicate with in a typical week? (voluntary)
2. Describe the last time you lost the context of a quotation or order (no company names).
3. Which tools were involved? What follow-up steps were needed?
4. What mistakes or delays actually resulted? Can the respondent quantify without confidential details?
5. When starting a new supplier conversation, how do you find the correct partner?
6. Would search plus scroll, immediate message and `+` attachments solve the observed task?
7. Which document types need a durable and retrievable association with the thread?
8. What prevents a company from trusting a new enterprise messenger?
9. Rank narratives A/B/C; ask what each fails to explain.
10. What conditions would need to hold before a real pilot? Would they join a later, permission-based follow-up?

## Success gate / non-metrics
Proposed recruitment target: 5–10 independently consented participants; **actual recruited: NOT MEASURED**. Count verified concrete pain descriptions and observed task-completion improvement on fictional fixtures, not likes or optimistic feedback. Keep security and privacy objections as failures to resolve. No public 'launch', 'Korea No.1', 'certified security', or 'verified customers' wording. Do not contact anyone or collect emails until the owner approves the privacy-safe intake and contact workflow.

## Upstream release blocker
The V3.6 observed PostgreSQL disposable synthetic shadow-copy PASSED but reported **BLOCKED: Production cutover incompatible legacy order/attachment/receipt semantics**. This is still a hard release block, not cleared by the marketing plan. No web waitlist is activated by this document.
