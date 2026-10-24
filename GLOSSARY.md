# JARVIS WORKS — domain glossary (v9 review)

Use these canonical Korean/English terms in specifications, test names and review evidence; this glossary does not alter the product database schema.

| Term | Meaning and invariant |
|---|---|
| 기업 / tenant | Organization owning data; every business query and message must enforce DB-side access boundaries |
| 거래번호 / transaction ID | Durable identifier linking business events and their derived documents; never infer or silently merge conflicts |
| 견적 / quote | Proposed line items, integer KRW pricing and explicit workflow state |
| 승인 견적 / accepted quote | Accepted state prerequisite for authorized quote→order conversion |
| 수주·발주 / order | Order derived from confirmed data, preserving source and avoiding duplicate creation |
| 청구서 / invoice | Business billing document, **not** an official electronic tax invoice |
| 입금 / payment record | Evidence of payment; not an external bank transfer |
| 원클릭 문서 전환 / one-click conversion | Reuse validated transaction data, without manual re-entry or unapproved silent changes |
| 문서 원본 / source snapshot | Immutable data captured when an approved document is created |
| 승인자 / approver | Responsible name recorded in final document process; actor identity is not supplied by untrusted browser claims |
| 메신저 / messenger | Registered business-to-business conversations; messages cannot be deleted, edits allowed only within 30 minutes |
| 메시지 커서 / message cursor | Monotonic cursor that must not skip a later-committed message |
| 멱등성 / idempotency | Replayed identical request yields one effect; conflicting replay is denied |
| FORCE RLS | PostgreSQL forced Row-Level Security; privileged-role shortcuts are not acceptable evidence of tenant isolation |
| 개발용 독립 계정 / staged login | Dedicated non-superuser business/auth PostgreSQL principals with reciprocal role isolation |
| Gate evidence | A reproducible executed observation (run, result, hash, screenshot); source text and intentions alone are not proof |
| 5-Gate | Code/env, functionality, stability/regression, UI/UX, operations/security |
| J1–J5 | Existing governance, execution, ground-truth, verified improvement, operational recovery harness; remains authoritative |
| 회귀 보호 / regression integrity | Confirm protected behavior and original source before/after a focused change |
| 복원 검증 / restore drill | Successful real restore with integrity checks and measured duration, not merely backup-file creation |
