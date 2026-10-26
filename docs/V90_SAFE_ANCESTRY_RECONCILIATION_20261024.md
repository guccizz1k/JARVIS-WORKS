# V9.0 safe ancestry integration — review-only (2026-10-24)

## Verified immutable checkpoints
- Legacy remote main: `4fe542b9c5676ae3ee5237504426a938e422cd42`.
- Recovered authoritative V8.9: `a3783ef9f7aeeeff655f1f0ac376f6d8edf5b338`.
- Tested V9.0 browser/SQL review source: `6c19845477c6507fdc7b8bc9292e24d1111e099b`.
- Legacy main: 29 blobs. Original V8.9: 288 blobs. V9.0 source: 308 blobs.
- Every legacy main path exists in V8.9: 14 byte-identical, 15 deliberately evolved since early main; 259 paths newly introduced in V8.9.
- V8.9 original `app/main.py` blob `0ede250ddbcf98b19f7747c8781ca4c8aa95e738` is unchanged through V9 review.
- This review branch adds exact original dev RPC rollback definitions, guarded SQL installation and evidence. No file in the old main is deleted by the review tree.

## Integration method
1. Preserve the complete V8.9→V9 branch tree; do NOT copy the outdated 29-file main tree into the current app.
2. Create a review-only Git commit with current V9 branch as first parent and old main HEAD as second parent; preserve V9 tree exactly. This is an **intentional source-tree adoption / ancestry reconciliation**, NOT a content-wise merge of divergent versions. It establishes verifiable ancestry without erasing V9 files.
3. Verify both parents are ancestors and the immutable original app entrypoint still matches the V8.9 tree.
4. Keep the PR DRAFT; do NOT merge to main or deploy until release gates pass.

## Current release blockers
- A genuine installed live schema independently accessed through the provisioned TLS business/auth login credentials is not yet E2E verified.
- Sender and editor commit-order transaction locks were applied to dev and A/B/C + attachment rollback regressions passed; separate overlapping session *RPC send* contention remains NOT RUN until independently proven.
- SQLite browser demo evidence is NOT PostgreSQL-connected production browser E2E.
- Credentials stored encrypted in Supabase Vault; never print them or copy them into this repository.
- Production runtime still hard-fails closed because legacy app.main uses SQLite.
