# V14.5 — stage-2 signup safety and stage-3 invoice-preview review (2026-10-30 KST)

## Protected baseline
- Forked exact parent Draft PR #57 HEAD: `92afea924d14b05e84a107b91db58250cc00f885`; do not merge into main or modify PR #57.
- Isolated non-production PostgreSQL17 + FastAPI staging only. No changes to existing Supabase schema, policies, passwords, Render services, payment RPCs, or live data.
- Existing J1–J6 baseline review runs cannot certify this *new SHA*. Keep independent signoff and release **BLOCKED**.

## Stage 2 — actual DEV catalog check
`scripts/review/v145_signup_readiness_readonly.sql` was executed as **read-only** SQL against the existing DEV project:
- Normalized email UNIQUE index: TRUE
- Business number UNIQUE index on messenger_companies: TRUE
- Dedicated no-inheritance, no-RLS-bypass trade/auth login separation: TRUE
- 35 forced-RLS tables: TRUE
- V85 auth session issuer: TRUE
- Verdict: **PASS_EXISTING_PREREQUISITES_ONLY**
- Business-ownership verification, password reset out-of-band delivery and full hosted signup: **NOT_VERIFIED**; official stage 2 **BLOCKED for complete acceptance**. Existing login/MFA/lockout positive test logs do not fill these gaps.
- **Do not add public signup, mass GRANT, generic unauthenticated duplicate-account lookup, password reset without verified channel, or fake PASS.** A separate reviewed onboarding design/migration is necessary before exposing any write endpoint.

## Stage 3 — genuinely implemented review-only functionality
- Added `app/pg_invoice_preview_v145.py` and mounted it **only** in `scripts/jw_v104_standalone.py` after existing verified authentication, stage gating, forced RLS and tenant identity.
- GET `/api/pg-stage/v145/orders/{32_lower_hex_id}/invoice-preview`
- Retrieves only current-session organization's fulfilled, acknowledged order; refuses another company's/missing order, previous invoice and malformed/missing lines.
- Rejects quantity/price/position inconsistencies, duplicate item IDs, empty/zero-value invoice, unsupported VAT, excessive subtotal.
- Uses integer KRW and a deterministic SHA256 receipt for the exact order snapshot, with no-store HTTP response.
- **Never writes, approves, posts, charges, or asserts physical delivery evidence**. Returns `draft_only=true`, `requires_human_approval=true`, `physical_delivery_verified=false`.
- Physical delivery-note source, real approval/posting, durable concurrency and true hosted product lifecycle remain **NOT RUN / PARTIAL**.
- Only a new reviewed writer with a physical-delivery approval chain can unlock actual posting.

## Gates and evidence
1. G1 syntax/compatibility: isolated `compileall` PASS; full product build/SDK environment NOT RUN.
2. G2 function: local isolated pytest `19 passed` (arithmetic, tenant filters, no CSRF-bypassing mutation, duplicate invoice, invalid items).
3. G3 regression: local unit and source checks PASS; J1–J6 **complete exact-new-SHA CI NOT RUN**.
4. G4 UI: desktop product and real staging browser **NOT RUN**.
5. G5 security: actual database catalog preflight PASS, forced-RLS policies read-only inspected, no grants/migrations; hosted test of new route NOT RUN.

**Official release remains BLOCKED.** The reviewer must independently verify the exact new SHA; signed Stage 1–8 receipts must not be authored by ordinary review CI. No customer data, schema changes, production deployment, main merge, or paid resources.
