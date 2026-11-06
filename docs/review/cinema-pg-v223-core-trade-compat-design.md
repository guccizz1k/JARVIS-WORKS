# V22.3 P0-2/P0-3 — server-side compatibility layer for the core trade chain (design + first piece)

Decision recorded from the project owner: keep the confirmed V22.2 UI unchanged (option A, server
side), build it step by step from the core trade chain (option C), **never create fake deliveries or
statements**, keep every existing feature, and switch a step to PostgreSQL only after equivalence
with the formal PG procedure has been verified.

## What exists after this change
* `app/pg_cinema_compat_v1.py` — pure translation rules (legacy request -> PG request) with stable
  refusal codes. **Not wired to any route**: the running app behaves exactly as before.
* `tests/test_cinema_pg_compat_v1.py` — 23 DB-free tests (12 deliberate breakages of the rules were
  each caught).
* `docs/review/cinema-pg-v223-route-matrix.md` — which routes the UI calls and which exist.
* CI: the "app/ and db/ unchanged" assertion of the V22.3 workflow now allows exactly one added file
  (`app/pg_cinema_compat_v1.py`) and still fails on any other change under `app/` or `db/`.

## Facts the design rests on (verified, not assumed)
1. The PG engine's SQL gate (`scripts/ci_cinema_pg_sql_gate.py`, psql only) was run on a throw-away
   **PostgreSQL 16.15** cluster: **222/222 PASS** (G1 1, G2 40, G3 104, G5 77). It is a PG16 run;
   the CI workflow runs the same gate on PG17 and that has NOT been run for this SHA.
2. That gate proves the formal chain and its guards: a delivery needs previously uploaded evidence
   (G3.32/G3.80), the recorder cannot confirm their own delivery (G3.38), a statement needs a
   confirmed delivery (G3.39), an invoice needs a confirmed statement and a review before
   confirmation (G3.41-43), a payment needs a confirmed invoice (G3.43b), nothing can be written
   around the engine (G3.50-53), cross-tenant keys are rejected even for a superuser (G3.65).
3. Therefore the legacy shortcut `POST /api/invoices/from-order` cannot be emulated honestly: it
   would have to invent a delivery, its evidence, a second confirming user and a statement.
4. The PG tables have no column for order `due_date` or payment `note`, both accepted by the legacy
   API. A quote's partner and VAT mode are immutable in PG, but a legacy edit may send them.
5. Legacy and PG use different words and ids: `sent/accepted` vs `submitted/approved`;
   `customer_id` vs `partner_id`; legacy `/orders/{id}/status` sets a status, PG derives it.

## Per-step policy
| class | steps (see the matrix) | policy |
|---|---|---|
| ADAPT (8) | customers create/update, quotes create/update/status, orders from-quote, payment create/reverse | translate with `pg_cinema_compat_v1`; refuse with a code when a field cannot be carried |
| READ (8) | the list/read routes | generic PG listing; there is no get-by-id route yet, so a thin filter or a new read function is needed |
| GAP (8) | invoice from order, statement from order, order edit / acknowledge / status, 3 adjustment routes | **stay on the legacy SQLite route**; in a PG-backed mode they answer `409` with the codes in `UNSUPPORTED`. No synthesis |

## Decisions (updated 2026-11-06 after the owner's F7 message)
* **Cutover unit - decided:** one organisation's whole trade chain; existing SQLite data is preserved
  and never copied into the PG chain with invented records. Details: `cinema-pg-v223-org-cutover-design.md`.
* **`due_date` and payment `note` - decided to keep, not remove:** a PG schema proposal exists and is
  behaviour-tested on a throw-away PG16; it is **not applied**. Details:
  `cinema-pg-v223-terms-and-two-person-proposal.md`. Until it is approved, the compat layer still refuses these
  two fields rather than dropping them. The same document also covers the invoice **pay-by** date, which the
  first version of this design had missed.
* **Two-person approval - kept, with a correction.** An earlier version of this file said PG itself requires
  an administrator *other than the submitter* to approve a quote. **That was wrong**: the engine checks only
  the administrator role (delivery confirmation is the only database-enforced "different person" rule). The
  quote rule is now enforced in the compat layer, fail-closed; a database constraint is proposed with its
  measured impact on the 222-case gate.
* **Still open for the owner:** administrator-only steps in PG versus "any signed-in user" in legacy (member
  accounts would get 403 in a PG-home organisation); how PG ids are told apart from legacy ids in the UI
  (both are 32-hex).

## Equivalence check that must pass before any step is switched
For every ADAPT step run the same synthetic input through the legacy route and through the
compat route on PG17 and compare: HTTP status class, the money fields (subtotal, VAT, total - the
G2.41 test already pins the VAT helper to the legacy rule), the resulting status, and the audit
rows. Differences are listed, not hidden. This needs FastAPI and PG17 together, i.e. the CI job.

## What this does NOT prove
No route is wired, no HTTP was exercised, no browser was driven, and the PG17 run of the gate has
not happened for this SHA. P0-2 is therefore **PARTIAL** (analysis, rules, tests), not PASS.
