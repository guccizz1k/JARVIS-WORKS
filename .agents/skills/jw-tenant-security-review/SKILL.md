---
name: jw-tenant-security-review
description: When modifying JARVIS-WORKS PostgreSQL RLS, company access, authentication, security-definer functions, database privileges, or cross-tenant API routes.
---

# Tenant security and PostgreSQL verification

J1–J6 subordinate project skill. Review only; `main` untouched. Release BLOCKED until verified.

1. Confirm source SHA and exact `jw_dev` 35 FORCE RLS business table inventory. Inspect real database read-only catalog with restricted credentials where permitted; no catalog-only SELECT counts may be mislabeled tenant proof.
2. Trace session verification, actor/org identity, SQL parameter binding, CSRF, function ownership and `SET LOCAL ROLE` on every changed route and RPC.
3. Design positive A/B/C organization fixtures and cross-tenant SELECT/INSERT/UPDATE/DELETE, attachment and security-definer denials in **approved disposable PG17** only. Include allowed owner case, not only empty-table reads.
4. Deny superuser, BYPASSRLS, PUBLIC privileges and shortcuts which weaken tenant boundaries. Persistent Supabase or Render DB DDL requires separate owner approval.
5. Run source-appropriate J1–J6 five gates. Record exact SHA, actual tests, FAIL/SKIP, rollback and missing evidence as NOT RUN; do not infer PASS.
6. Use existing `jw-verified-delivery` and `jw-evidence-retro` only on proven failures, not as an auto-approval chain.

Existing seams: `scripts/jw_v108_schema_fingerprint.py`, `app/pg_v90_integrated_entry.py`, `scripts/jw_eight_stage_release_gate.py`.
