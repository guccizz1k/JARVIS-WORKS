# V10.8 11-part PostgreSQL17 source-vs-target fingerprint gate

Source: the connected development Supabase PostgreSQL17 jw_dev schema, read using catalog-only SELECT. Read-only counts and ordered MD5 digests; **no customer rows, no secrets, no function bodies, no SQL dump or metadata DDL** were transferred into GitHub. Raw schema transfer was declined by a tool safety guard, so it was abandoned. The fingerprint artifact contains ONLY non-sensitive counts/digests.

Scope: 35 tables with 35 FORCE RLS, 282 columns, 183 constraints, 87 indexes, 40 policies, 45 triggers, 28 functions, one sequence, 40 stage-table grants and 18 stage-function grants. Digests incorporate ordered definitions/expression strings, without exporting their contents.

Source JSON: db/review/v108_source_schema_fingerprints.json.
Read-only target check module: scripts/jw_v108_schema_fingerprint.py. It **requires** the existing V10.7 two independent restricted DB logins, checked NOINHERIT/role isolation, exact 35-table names and RLS. It then recomputes eleven fingerprints using READ ONLY on an independently opened restricted trade connection, rolls back and closes. A mismatch returns only section names, not schema SQL or credentials. The source file is a snapshot, not a migration or a user approval.

Important: matching hashes cannot by itself prove behavioral RLS resistance, correctness of owner privileges beyond V10.7, data consistency, runtime readiness, a backup, or application readiness. Dev PostgreSQL minor version 17.11 and target Render 17 may generate different canonical DDL text, in which case the check safely fails and requires review.

The persistent Render free DB is still NOT populated or connected to business APIs, and this new check must not claim it is. Source migration DDL generation/replay awaits a secure authorized schema-only source artifact and independent disposable replay; do NOT use synthetic CI seed SQL. Render public HTTPS service remains transport-only, auto deploy OFF; DB allowlist empty. Main/production untouched; final release BLOCKED.
