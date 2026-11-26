# NARUV ONE independent recovery and statutory review — review-only decision record

2026-11-26. Scope: design and service evaluation approved, no provisioning, key transfer, real archive transmission, production changes, contract or release. Preserve existing two key sets, all 22 backups and existing receipts.

## Candidate architecture
- Google Cloud Compute Engine Seoul, separate account/project controlled by an independently designated custodian; e2-standard-2, 2 vCPU/8 GiB, encrypted ephemeral disk, no public IP, IAP SSH/OS Login, no production service account or peering. Review actual pricing and network setup before provisioning; bounded temporary egress for pinned source, Docker image and ciphertext staging only. Do not confuse IAP with all network isolation. Revoke staging network access before key release; use networkless local Docker PG17, prohibit persistent plaintext and logs. Destroy disposable VM/disk after redacted receipt; preserve independent signed evidence.
- Existing PR #152 pinned source ba65b8dddcf2678fd570b8893ff86b9f1e76b1b3. This currently obtains exact private Git blobs; if GitHub inaccessible, an independently accessible archive and source package path is still required, not solved by VM. Do not pretend B2 is supported by that runner without an independently verified adapter. No real restore until separately approved exact vault SHA, sorted blob scope and independent references.
- Independent key escrow candidates: The Escrow Company, SES Secure, EscrowTech. Confirm explicitly that they accept arbitrary raw 32-byte AES recovery keys or sealed key material, separately controlled keys and ciphertext, independent recovery even if original owner loses access, dual approval/release criteria, MFA and audited signed custody/restore receipts, jurisdiction, retention, exit and fees. Software escrow is not automatically key escrow. No keys or archives supplied for quotation. No substitution with ordinary cloud KMS alone.
- Existing signed custody assertion validator and local challenge journal remain authoritative technical evidence boundary; signatures authenticate assertions, not actual independent custody. Actual independent custodian, externally pinned trust roots and real restore receipts are mandatory.
- Acceptance: independently controlled site, isolated network, read-only exact ciphertext per scope 11+11, AES-GCM authentication, complete PG17 restore and catalog/rows against independent reference, verified cleanup, signed redacted challenge receipt and retention evidence. No key activation/retirement or original deletion.

## Statutory external review package scope
Only synthetic cases and proposed results: independent Korean labor/tax specialist must confirm effective law, scope, ordinary/overtime/night/holiday, paid leave/rest, minimum wage, cash inclusion, bonus, severance, annual/termination settlement, six deductions, insurance exceptions and rounding, statement fields, recipient authentication and delivery/retention. Separate authoritative expected values and legal citations from implementation; record disagreements and versioned signed acceptance. No actual employee records, source secrets or live backups sent; expert not yet retained. Implementation test success is not legal acceptance.

## Sources
- https://docs.cloud.google.com/iap/docs/using-tcp-forwarding
- https://cloud.google.com/products/compute/pricing/general-purpose?hl=ko
- https://www.escrowlondon.com/llm-info/
- https://www.ses-secure.co.uk/software-escrow-services
- https://www.escrowtech.com/
- https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys-considerations.html

## Owner-operated GCP synthetic setup evidence (2026-11-26)
User terminal screenshots show PG17 networkless synthetic 1000-row restore, AES-GCM invalid key/tamper rejection, row SHA-256 match, container cleanup, NAT/router absent, IAP-only configuration and actual SSH admin login with 2FA, original firewall equality, VM TERMINATED. This is owner-operated, not independent custodian evidence. Negative actual traffic test remains NOT RUN. New B2 exact-version ciphertext staging and offline reread adapter is review-only; no live B2 call, no key, no existing object changes, no restore-runner integration yet. The legal case inventory is synthetic and incomplete as a legal acceptance package; no external transmission or signed expert opinion.
