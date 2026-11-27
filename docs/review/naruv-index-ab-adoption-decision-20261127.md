# NARUV ONE local PG17 index ABBA decision — 2026-11-27
Evidence: Draft PR #191, head 38b70250a3dba35da0acfba1ccd84ee3f44f2286, GitHub Actions run 45987361767, job 140466295789, completed success including disposable container removal. Script blob d1aad99c0e2493eb7a3820ba980b227815d38c02; index plan blob 11c1de05e851e81ffb3d76095983a62818514b4f.
Four fresh same-image local PG17 TLS arms in ABBA order:
| Arm | p95 ms | median ledger read ms | elapsed s | added index bytes |
|---|---:|---:|---:|---:|
| baseline | 526.266 | 520.431 | 4.974 | 0 |
| indexed | 607.903 | 614.913 | 5.757 | 499712 |
| indexed | 634.746 | 607.512 | 5.774 | 499712 |
| baseline | 525.000 | 518.668 | 4.927 | 0 |
Median of two arm summaries: baseline p95 525.633ms, median read 519.5495ms, elapsed 4.9505s; indexed p95 621.3245ms, median read 611.2125ms, elapsed 5.7655s. Added latency ~18.2% and ~17.6%, elapsed ~16.5%, storage 488KiB. These are medians of arm metrics, not pooled sample quantiles or production SLA.
Functional PASS: 160 committed batches, 1120 business RPC, 160 exact replays, 160 balanced journals, 24 stock +24 valuation checks, 8 ledger checks plus 40 timed ledger reads. Identical A/B tenant stock 120/80/20 and inventory values 25200/49200 across all four arms. Cleanup PASS.
Decision: REJECT blanket adoption of all 35 indexes at tested scale; retain exact original engine/indexes. No index drops or production changes. Do not extrapolate to large data or individual index effects. No rerun of this same comparison absent changed requirements/invalidating evidence. Any targeted future indexes require workload-specific query plans and evidence. Hosted performance remains NOT RUN; overall Gate5 BLOCKED. Existing reconciliation candidate local functional PASS remains separate. No additional CI requested by this record; actual approved run charge unverified.
