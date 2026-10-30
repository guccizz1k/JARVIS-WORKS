# V10.5 Render free HTTPS transport-only stage

**Approval boundary**: user approved isolated HTTPS *testing*, not production release or public disclosure of business data. This is the initial safe public network probe, not a live fully connected business application.

- Separate free-plan Render web service, Singapore region matching the existing free PG17 Render DB.
- Deploy pinned GitHub review branch with `autoDeploy=no`; do not promote or merge into main.
- `scripts.jw_v105_render_https_probe:create_app` has public `/` and `/healthz` status **only**, with all business endpoints disabled and no PostgreSQL DSN, no secrets or customer data.
- Startup strictly requires `JW_ENV=review`, `JW_HTTPS_PROBE_MODE=HTTPS_TRANSPORT_PROBE`, `JW_HTTPS_PROBE_ACK=REVIEW_ONLY_NO_BUSINESS_ENDPOINTS`. Runtime refuses DB credentials and any production/release flags. Web process is behind Render-managed HTTPS termination.
- This probe does **not** attest any company auth, RLS, financial workflow, OCR, WebSocket, DB TLS or recovery. Existing CI ephemeral PG17+HTTPS+WSS evidence remains independently valid.
- Render free PG17 database currently has an empty external IP allowlist; **do not loosen it**. Render internal same-region access may be used in a *later independently approved* role-scoped migration and credential setup. Render documents say internal PG endpoints support `sslmode=require` but not `verify-full`; existing `scripts/jw_v104_standalone.py` requires `verify-full` and therefore cannot simply be configured with the Render internal URL. This must be explicitly resolved and tested; do not downgrade TLS globally.
- No permanent HTTPS service must be called finished before live deployment's HTTP and TLS response, available status, branch revision and zero-product-route checks are verified.

**Next security gates**: Render GitHub repo access, successful free-service deployment, live HTTPS request, separate least-privilege PG logins and approved schema bootstrapping, auth/MFA validation, privacy, full multi-tenant browser E2E. DB and user data remain untouched in this phase.
