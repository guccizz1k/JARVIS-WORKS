# Gate 5 owner evidence checkpoint — 2026-11-27
Review-only, no production or policy change. Preserve predecessor CI: P1 carrier c436c6b25ef2a624be3c74886e500fe7637a001b and P2 9957bf3181193c60e975d8c715db21ef9090428f, four workflows 45904926397 / 45904926416 / 45904926424 / 45904929685, 32/32 jobs success.

## Owner-provided actual terminal evidence
Final receipt script SHA256 6e7a2514db35dd77c9e0f49978ab2f03d6216448980fe15e9e6f5eec37c4884a. Owner screenshot of final execution shows IAP_SSH_BANNER=PASS, 2 candidate directories, 0 search read errors, 1 incomplete candidate, 1 mixed-owner content-valid pair, FINAL_CONTENT=PASS, GCP_RECEIPT_CONTENT_READONLY=PASS, SSH_COMMAND_EXIT=0, VM_TERMINATED=PASS, CURRENT_SWAP_ENTRIES=0. Both receipt file hashes displayed as a47ddc28f07d7195dbebb68f25b278532943ddb68ed42d85e02681830f481548. Same digest true. ORIGINAL_PATH_TRUST=BLOCKED_MIXED_OWNER. SCOPE_BINDING_IN_RECEIPTS=NOT_ATTESTED. HISTORICAL_ACL=NOT_ATTESTED. HISTORICAL_HOST_ISOLATION=NOT_ATTESTED. OFFLINE_KEY_COPIES=NOT_VERIFIED. P2_ACCEPTANCE=BLOCKED.

This is owner screenshot evidence, not independent attestation or direct receipt acquisition by the reviewer. Retain prior owner-reported 22 real restores and 22 B2 live metadata checks. Do not rerun either merely to obtain the same evidence. No raw receipts, keys or screenshot uploaded here. Current swap status is not historical isolation evidence.

## Prospective storage remediation (proposal only)
The pinned strict verifier rejects a root-owned receipt directory beneath a login-user-owned ancestor. The separate read-only mixed-owner inspector validated the receipt contents but not historic namespace custody. A new root-controlled private directory with exclusive byte-identical copies, independent observed hash pin and strict readback can demonstrate NEW_STORAGE_PATH_TRUST=PASS_STRICT from preservation time, not original path trust or historical scope binding. Do not chown/chmod/move/delete the original. Any actual new copy and VM start requires owner approval; no rerun requested now. Identical legacy/staged receipts cannot independently identify the two historical runs.

## Remaining acceptance
P1: actual provider/test channel and real employee mapping; independent labor/tax review. Existing synthetic verifier and local provider probe do not prove those.
P2: actual offline key copy/access and account recovery; historically reliable provenance/host isolation; approved authoritative recovery ACL/role baseline with effective RLS. Prospective authorization policy is not historical ACL parity and must be approved separately. Gate 5 remains BLOCKED. No new cost or live change performed.
