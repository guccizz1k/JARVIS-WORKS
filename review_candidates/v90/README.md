# V9.0 secure directory — DRAFT REVIEW ONLY

This isolated additive candidate is **not a release**.

## Proven state
* GitHub `main` is older than the local V8.8 source bundle; V8.9 local commit `a3783ef` and V8.9 ZIP are not available on this linked remote / workspace.
* PostgreSQL dev project `jarvis-works-dev` `jw_dev` applied and verified `search_messenger_companies_v90` via a separate connected Supabase session.
* Supabase synthetic transaction verified Hangul company-name search, business ID lookup, pagination, self-exclusion, literal wildcard handling, invalid session rejection, query bound, restricted EXECUTE, and complete rollback.
* Existing SQLite V8.8 snapshot: added separate FastAPI development router `/api/pg-stage/v90/companies`; 13 new tests pass. Existing `app/main.py` unchanged.
* Two demo organizations in the locally running **SQLite** app exchanged a message and a file using genuine loopback HTTP. This does not demonstrate PostgreSQL live messenger E2E.

## Integration gate
1. Recover and inspect real V8.9 files & commit first. Never overwrite V8.9 from an older V8.8 bundle.
2. Import the tested stage-only V9.0 FastAPI router from the offline package and reconcile against V8.9 route/auth changes.
3. Verify and align SQL migration history; do not execute a duplicate destructive migration.
4. Actual distinct, non-admin DB login roles remain `NOLOGIN`. SSL `verify-full` E2E, independent payment contention, browser E2E, and customer-data migration remain BLOCKED / NOT RUN.
5. Do not merge, deploy, enable credentials or migrate customer data until these gates pass.

## Security
SQL uses a fixed schema-qualified SECURITY DEFINER function with explicit search_path and EXECUTE grants for `jw_app_dev` only. It returns only verified companies' name and org ID, never private staff or contact details. All filtering inputs are bounded and handled as literal values.
