# V9.2 — PostgreSQL-native draft quote creation (review-only)
This standalone stage is reached only via `uvicorn app.pg_dev_entry_v92:app` with all V8.4/V8.5/V9.0 stage opt-ins and `JW_PG_QUOTE_V92=ISOLATED_DEV_QUOTE_V92`. Production `app/main.py` and existing routes are unchanged.

## Required invariants
- Actual PostgreSQL server-issued login session and CSRF, explicitly allowed HTTPS Origin, user and tenant identities derived exclusively from PG.
- Customer belongs to the current organization; never trust actor/org from JSON; 40 lines max with integer amounts and ROUND_HALF_UP subtotal VAT. Same math as existing `app.main.money`: taxable 1,309 -> 131 VAT -> 1,440 KRW.
- `quotes.source_import_id` existing globally unique index means concurrent POST retries with the same (org, request ID) cannot duplicate. Idempotent exact retry returns the original ID, conflict changed payload returns HTTP 409.
- One transaction for quote + items + audit, DB denial rolls back all changes; authorization before mutation.
- NO full PostgreSQL finance runtime, no production feature flag, and no bypass of verified-full TLS or RLS. This API is specifically for *approved staging accounts*; financial release remains BLOCKED.

## Next proof
Focused mock HTTP tests only validate orchestration. A real PG17 browser/HTTPS staging integration needs separate evidence before promoting this route, and Supabase secure CA credentials are still not present in a host-accessible secret manager. No schema changes required on current jw_dev (existing columns/index/privileges checked read-only).
