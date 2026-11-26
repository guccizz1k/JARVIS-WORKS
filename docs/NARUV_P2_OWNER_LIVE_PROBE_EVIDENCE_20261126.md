# NARUV ONE P2 owner live probe evidence — 2026-11-26

## Evidence scope
Owner-supplied Codespaces terminal screenshot reviewed in chat; not an independently downloaded B2 audit. No credentials, plaintext, provider object IDs or original screenshot uploaded to this repository. Source candidate f9ed648dc9dde144ce1581fb2c4000d2cf235504; runner blob 98c3f681d37aeae3e7c41a22744b5b514953c877. Verified draft PR #164 head 21f8d2d01b38a892bee9515977e7fd6e27759552 and Actions 45763872638, 45763872640, 45763872641 all success. Preflight 14950 cases; CI isolated synthetic PG17 dump and restore succeeded.

## Owner-reported real provider outcome
- Status: SYNTHETIC_B2_LIVE_PROBE_PASS
- Scope SHA-256: e0612a28ce5fb35e91f75d289aee185ccd72c110169ebbe29e9ee513c2223863
- Verified objects: 1; ciphertext size: 1714 bytes.
- Local synthetic PG17 restore: true.
- Provider readback verified: true.
- Compliance minimum 30 days: true.
- Existing backups modified: 0; operational keys modified: 0.
- Physical custody verified: false; production authorized: false.
- Temporary writer and audit keys created with 1-hour validity; expiry/revocation not independently checked.
- Owner entered FREE10 and UPLOAD. Actual invoice and account usage not independently inspected.

## Acceptance boundary
Single-object live synthetic upload/readback and retention test: PASS on owner terminal evidence. Preserve prior 22-object receipt/retention successes. Do not repeat upload, issue more keys, modify retention or download again solely to revalidate this pass. Local result and journal remain in owner's private directory; no private artifact transferred. Local pre-upload synthetic restore is not an independent custodian restore. Remaining: independent key/site custody and restoration, production key governance, P1 statutory payroll and actual workflow acceptance. No main merge, production DB, UI, operational keys, original backups or AI work authorized by this evidence.

Evidence-only branch; code and original validated CI source remain unchanged.
