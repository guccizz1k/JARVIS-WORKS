# V22.3 auth session integration candidate — NO DEPLOY

Base: `03863d1d14f1c9bc04a7d4ba74cb66ef16e995bb`. Local branch: `review/codex-v223-p0p2-races-20261116`. Original owner HTML SHA256 `953c1b00cead79173c0c7a9c40319344e510bec9f6a1f646f30e0a147356076d` and app/main.py blob `775f500c8a7549d434ce196a8e0763aea33e1c67` remain unchanged.

## Defects and correction

The adapter permitted overlapping auth transitions, cleared new identity on old401 responses, and returned old-user data when the old and new users shared an organization. Serialize login/logout/restore at the adapter boundary; capture a monotonically increasing epoch across fetch, JSON parsing and composed business calls. Refuse stale responses regardless of organization equality. This is a per-adapter guarantee, not cross-tab or server-global authentication atomicity.

Independent review found a partial-login and UX seam: login POST can issue a valid HttpOnly cookie before /me fails, and the UI swallowed logout failure and falsely confirmed server logout. When local identity is absent, logout now reads server identity/CSRF before revoking the cookie-backed session.401 confirms no current server session; other failures remain visible and never become a success message. Existing API paths, CSRF checks and HttpOnly/Secure/SameSite cookies remain authoritative. No browser-local records are used.

Node deferred-response tests reproduce old failures before the patch and cover overlapping login/restore/logout, old401, same-company and cross-company responses, late JSON, network recovery, current expiry, CSRF and guest rejection. Actual trusted loopback HTTPS tests execute the real adapter against the original FastAPI cookie session: same-company and cross-company races, delayed401, partial login cleanup, missing CSRF403, logout401, and customer→quote→accepted→order→fulfilled→statement→invoice→payment→readback. Replaying an identical payment reference is intentionally idempotent; conflicting amounts fail. The first HTTPS fixture incorrectly expected identical replay rejection; its failure was preserved and the check corrected to the existing documented idempotency contract without changing the backend.

##17-screen capability boundary

| Menu | Current real server link | Completeness |
|---|---|---|
|home|customers,quotes,orders,invoices plus explicit business forms|review subset; not full original product|
|docs|records, explicit upload preview/detail and human confirmation|verified-source document review flow; not full original product parity|
|deals|quotes and order creation/state conversion|implemented review flow|
|papers|quote listing|broader document parity incomplete|
|money|invoices,payments,fulfillment and statements|implemented review flow; original product parity not certified|
|partners|customers list/create|review subset; editing/removal not exposed|
|messenger|threads|read-only; conversation/send/attachment UI incomplete|
|automation|server timing,start/finish/cancel and statements|implemented review subset|
|stats|dashboard,time-savings|server reads; not original analytics parity|
|export|draft summary/create/detail/freshness-checked XLSX download|review draft export implemented; not complete accounting/settlement export|
|inbox|queue/detail, digest-bound explicit original review and confirmation|approval flow implemented; server has no reject endpoint|
|files|explicit upload preview plus verified records|original raw files are not retained; not a binary attachment archive|
|activity|audit|read-only server data|
|team|security overview users|read-only; staff management UI incomplete|
|security|security overview|read-only; original MFA/recovery UI parity incomplete|
|settings|no handler; explicitly unwired|NOT IMPLEMENTED; configuration semantics/API must not be invented|
|account|verified server identity|read-only; profile update UI incomplete|

A17-menu list is not17 implemented workflows. Existing verified-source draft XLSX APIs are now wired through an opt-in module; creation requires explicit confirmation and download requires a separate click. Binary MIME/size/ZIP magic, stale invoice balance, tenant scope and session epochs are checked. No schema or original HTML/CSS change. Preserve ChatGPT's original design and do not silently replace missing product behavior with a server-review placeholder. Full P2 remains blocked until those user flows and actual browser/accessibility/mobile behavior are integrated and verified. Physical iPhone Safari is not inferred from Node or Linux browser tests.

## P0 and CI boundary

Main's530 existing paths are all present. The24 shared modified files require per-file impact review, not just existence checks. The independent review ledger and exact-SHA results live in the local evidence directory outside this commit. Historical J1–J6 and TLS workflow allowlists target older source/branch scopes; the new review-only workflow deliberately pins this base, this exact fourteen-file delta and the protected original blobs. It runs full Python, all Node CJS suites and independent disposable PG17 TLS/fault checks. Preparing this workflow does not publish a commit, start CI, authorize costs or certify remote success. New remote push/PR/manual workflow dispatch require explicit scoped authorization.

Local artifacts must identify source SHA, command, environment, exit status, failures/skips and scope. Do not reuse03863 or5b63 successful logs as proof of this new candidate. No production/main/Render/persistent DB changes, no original UI mutations, no secret export, no paid execution. Rollback is the focused review-branch diff; server schema and business engines have no migration to reverse.

Document review now uses multipart browser upload with CSRF, explicit original_checked attestation, fresh digest/type/status matching, supported type restrictions and server non-accounting/non-payment/non-stock response guards. No automatic approval or original-file archival claim. Actual HTTPS fixture tests preview→queue→confirmation→record readback, foreign-tenant denial and duplicate confirmation refusal.

Independent review reproduced a same-page preview-selection race and legacy null source-size incompatibility. Per-selection and refresh generations now prevent slow previews/uploads/approval completions from replacing the newest selected document. Legacy null/missing size is displayed as unknown without inventing bytes or rewriting source hashes/digests; new uploads still require exact byte-size equality. Regression tests cover all three competing actions and legacy read/approval compatibility. Full original product UI/browser acceptance is still separate.
