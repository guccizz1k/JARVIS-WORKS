# JW V10.5 external HTTPS smoke

A GitHub Actions read-only runner connects to the actual Render URL with Python trusted CA / hostname checking enabled. It confirms safe GET /, /healthz, no cookie, security headers, missing legacy/PG business APIs and denied POST route. No DB credentials or user data are sent. Render deployment pinned ca4537763850ffde4b95c320fc9ba38040dcf6fd, distinct from GitHub workflow checkout SHA because auto-deploy OFF. Scope: external HTTPS probe only; NOT DB, auth, finance, OCR, WSS or release verification.
