# JARVIS-WORKS V22.3 — S4 immutable reviewed-snapshot regression (2026-11-14)

## Scope / provenance
- Base: `review/jw-v223-a-isolate-headers-20261114` at `26e7b1b8aaa2c0f30fad7a56ead178f69df33172`.
- Isolated review branch: `review/jw-v223-s4-snapshot-guard-20261114`.
- Existing `main`, operational DB, backups, Docker volumes and Render services were NOT changed.
- No production secrets, client data, real sessions or live DB were used in the synthetic regression.
- Current Codex local candidate `faa97d10c89853faa1bea3d1e272c41ee8c3faac` is NOT present in GitHub. Do not overwrite or falsely claim to have integrated it.

## Exact defect
`provisional_unique_subtotal(AuditResult, cinema_quotes)` originally used `result.consistent_for_manual_review` from an earlier audit but calculated the forensic subtotal from **new caller-provided** quote objects. A changed price, quantity, document/business number or status could be silently counted; duplicate/unreviewed rows were ignored. The function was always forensic-only; `approved_unique_subtotal` was already fail-closed and remains so.

## Red → green evidence
- New 12-case isolated synthetic unittest: `tests/test_cinema_pg_s4_snapshot_integrity_20261114.py`.
- **Before fix:** GitHub Actions run `43573083368` — 12 collected, 2 PASS / 9 FAIL / 1 ERROR, reflecting ten reproduced unsafe cases.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43573083368
- **Fix:** `b489ac3f043c5fe2125d135acb558417ad624d00`. Recalculate canonical SHA-256 of every currently supplied CINEMA quote and require it to match the corresponding reviewed digest; check quote identity, ledger, status, duplicates and exact set coverage. Continue blocking publication.
- **New tests after fix:** GitHub Actions run `43573261226` — 12/12 PASS.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43573261226
- **Existing + new tests:** commit `0d34268ddac6560424f35dd45eddad47d5fc298b`, GitHub Actions run `43573378935`: Python compile PASS, pytest **62 PASS, 0 FAIL, 0 ERROR, 0 SKIP**.
  https://github.com/guccizz1k/JARVIS-WORKS/actions/runs/43573378935

## Existing branch reconciliation
The previously reviewed Track A/B integration branch, QA E2E branch, and current A security branch all shared the identical S4 reconciliation module blob `354910387a48488422e13aa56eebb428dbfd7fd0`; the newly guarded module is blob `4cab27a8ed53cfc4c4edb82a479e867481b8c649`. Existing reconciliation test blob was unchanged.

The existing header/session security fix is preserved in the new branch. **This is a small remote review-branch patch, not an integration of the unpushed Codex local candidate.**

## Development PG17 catalog — read-only spot check
- Queried Supabase project catalog only; no DDL/DML and no real row data returned.
- `jw_dev.quotes` and `jw_dev.cinema_pg_quotes` both: RLS true; FORCE RLS true; `anon` and `authenticated` direct SELECT false.
- `jw_dev.cinema_pg_transitions` is an internal-looking table with RLS false; `anon` and `authenticated` direct SELECT false. Grants observed to owner and backup-readonly role. This alone does **not** prove data exposure; analyze privilege inheritance and intended use before recommending changes.
- Live source-to-restored data equality remains NOT RUN; catalog inspection alone cannot establish it.

## Safety and remaining release gates
- Existing S4 Python pure audit remains non-publishable; server-side authenticated approval / immutable link provenance and live trading E2E NOT VERIFIED.
- Approval snapshot changing in the **original** v92 ledger after audit cannot be reverified by this function alone; no original snapshot is passed to it. A live approval endpoint must independently validate both sides.
- Latest Codex local SHA `faa97d10` unavailable; S4 code may already be repaired differently there. On obtaining it, diff and integrate **only missing** changes, then rerun targeted and full regression.
- Latest UI integration, physical GPU/mobile, Render HTTPS E2E, Supavisor 403 access and independent security QA remain BLOCKED / NOT VERIFIED. No launch ALL PASS claim.
