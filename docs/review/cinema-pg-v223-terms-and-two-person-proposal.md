# V22.3 P0-2 — PG schema proposal: order due date, invoice pay-by date, payment note, and the quote two-person rule

**Status: PROPOSAL. Not applied to any Supabase project, not applied to `main`.** Applying anything
below to the development schema is a database change and waits for explicit owner approval.
The owner asked that `due_date` and the payment `note` are **not removed**; this is the plan that keeps them.

요약(한국어): 납기일·입금기한·입금 메모를 지우지 않고 PG에 담는 보강안입니다. 감사 대상인 엔진 테이블과 SQL 함수는
한 줄도 바꾸지 않고 "부속 테이블 3개 + 쓰기 함수 3개"를 추가합니다. 임시 PG16에서 36개 항목과 변형 7종으로
확인했습니다(PG17·Supabase 아님). 별도로, 견적 2인 승인은 현재 PG 엔진이 강제하지 않는다는 것을 측정했고, DB 제약을
넣었을 때의 영향도 함께 기록했습니다.

## 1. What is missing in PG (measured against the legacy DDL)
| legacy field | legacy rule | PG today |
|---|---|---|
| `orders.due_date` (NOT NULL) | set at order creation, "today or later" (`main.py:1295`) | no column |
| `invoices.due_date` (NOT NULL) | the **pay-by** date typed at invoice creation; drives the `overdue` status (`main.py:505`, `1383`) | no column; `overdue` cannot be computed in PG |
| `payments.note` | free text, default `''` | no column |

## 2. Why side tables instead of new columns
* `cinema_pg_result()` returns `to_jsonb(<whole row>)`; a new column would change the JSON of every
  existing response (checked: the order entity has exactly `created_at, created_by, id, items, org_id,
  partner_id, quote_id, status, trade_no, updated_at, vat_mode`).
* The three SECURITY DEFINER functions that would have to change (`order_create`, `invoice_create`,
  `payment_record`) are the audited core; changing them re-opens their review and the pinned engine blob.
* Payments and order items are append-only by trigger; a note written after the fact is a new row, which
  fits a side table.

## 3. Objects (file: `scripts/review/cinema_pg_v223_terms_proposal.sql`, one transaction)
| object | rule |
|---|---|
| `cinema_pg_order_terms(org_id, order_id PK, due_date, set_by, set_at)` | append-only, FORCE RLS, writer = SELECT only |
| `cinema_pg_invoice_terms(org_id, invoice_id PK, pay_by, ...)` | same |
| `cinema_pg_payment_notes(org_id, payment_id PK, note 1..500, ...)` | same |
| `cinema_pg_order_terms_set(request, order, due)` | admin (like `order_create`); order must be `open`; not in the past; set once; audited; idempotent by request id |
| `cinema_pg_invoice_terms_set(request, invoice, pay_by)` | admin or the invoice creator; only while `draft`/`reviewed`; not in the past; once |
| `cinema_pg_payment_note_set(request, payment, note)` | the admin who recorded the payment; not reversed; 1..500 chars; once |

Consequences to accept:
* the due date must be written **right after the order is created, in the same transaction** (an order
  that is already fulfilled is refused - check T1.14). The compat layer will do both calls together.
* terms are write-once. The legacy "edit order" feature (a GAP step) stays in legacy.
* an invoice without a pay-by date has no `overdue` status in PG; the compat layer must show "no pay-by date".

## 4. Evidence (throw-away **PostgreSQL 16.15**, not PG17, not Supabase)
* Engine SQL gate before the change: 222/222 PASS (same cluster).
* `scripts/ci_cinema_pg_terms_gate_v223.py` (installs fixtures + unchanged engine, applies the proposal, then
  checks): **36 checks, 0 failed** - role gates (42501), cross-organisation (P0002), replay and payload
  mismatch (23505), past/NULL dates (23514), fulfilled order (23514), direct INSERT/UPDATE by the writer
  (42501), owner UPDATE blocked by trigger, RLS isolation between organisations, audit rows, engine
  `integrity_check` still empty, no PUBLIC execute, `search_path` pinned, FORCE RLS on all three tables.
* 7 deliberate breakages of the SQL (any admin may add a note, past dates allowed, FORCE RLS removed,
  invoice status check removed, append-only trigger removed, PUBLIC execute left, open-order check removed)
  were each caught by a named check.
* A CI workflow (`jw-cinema-pg-v223-terms-gate.yml`) runs the same script on PG17; **not run yet** (no push).

## 5. Role differences between the legacy API and PG (from the code; decide before wiring)
Legacy requires only a signed-in user for: quote status change (`main.py:989`), order from quote
(`:1288`), invoice from order (`:1377`), payment (`:1408`). PG requires an **administrator** for quote
approve/reject/cancel, order creation, delivery confirmation, statement and invoice steps, and payments.
A member who can do these today in legacy would get `admin_required` (403) in a PG-home organisation.
Owner decision needed: accept that, or define a PG role for "trade operator".

## 6. The quote two-person rule is not a property of the PG engine today
Measured, not assumed:
* `cinema_pg_quote_transition` checks the admin role only; there is no `approved_by <> submitted_by` check
  anywhere (the only "different person" rule is delivery confirmation, `engine.sql:909`).
* The existing 222-case gate itself submits and approves quotes with the **same** administrator
  (`hash_a_admin1`) at five places: two Python helpers (`ci_cinema_pg_sql_gate.py:411,485`) and three blocks
  of the engine test SQL (`..._test.sql:206-207, 487-488, 560-561`). The first quote flow
  (G2.04-G2.07: a member submits, an administrator approves) is a genuine two-person path and would keep working.
* Experiment: a copy of the engine with
  `CONSTRAINT cinema_pg_quote_two_person CHECK(status NOT IN ('approved','ordered') OR (submitted_by IS NOT NULL AND approved_by<>submitted_by))`
  made the gate **abort in its own setup** ("only an approved quote can become an order"), so it
  reports no pass count at all. The fixtures would have to use a second administrator first.

Therefore:
1. **Now, without touching the engine:** the compat layer refuses approval when the acting user is the
   submitter or either identity is unknown (`quote_second_person_required`,
   `quote_approval_identity_unknown`, HTTP 409) - tested, with 7 breakages caught.
**Independent QA correction (2026-11-06):** On the real development PG17 server, `submitted_by`
 and `approved_by` are both nullable. The first proposal's `approved_by IS DISTINCT FROM submitted_by`
 incorrectly accepted `approved_by=NULL` with a non-NULL submitter (verified using read-only
 SQL scalar evaluation). The revised proposal explicitly requires `approved_by IS NOT NULL` and
 counts nullable approvers as pre-existing invalid rows. `T5.16` copies the *installed constraint*
 expression into a disposable temp table and proves both `approved` and `ordered` reject a null
 approver. This new PG16/PG17 gate has **not been run** in this environment.

2. **Candidate implemented and tested, not applied:** `scripts/review/cinema_pg_v223_quote_two_person_proposal.sql`
   adds `cinema_pg_quote_two_person` as a **separate migration applied after the engine and its 222 checks**,
   so the audited engine and its tests (which self-approve in five places) are not edited and stay 222/222.
   It is `NOT VALID` (new/updated rows are checked, old rows are not) and is checked by 17 extra checks (T5.*) in
   `ci_cinema_pg_terms_gate_v223.py` on a throw-away PG16.15: self-approval refused (23514) and mapped from the
   real PG error text to `quote_second_person_required`; a different administrator, or a member-submitted quote,
   still approves; a resubmission cannot be approved by whoever resubmitted it; order conversion still works;
   the engine's integrity check stays empty. 5 breakages of the migration were each caught.
   **Consequences measured, owner must accept before applying to the dev schema:**
   * `VALIDATE CONSTRAINT` is refused while self-approved rows exist (the audited fixtures hold 6 such rows);
   * a quote that was self-approved **before** the migration can no longer become an order (23514), because a
     `NOT VALID` check still applies when the row is updated; it **can** still be cancelled, which is how the owner
     clears such rows after reviewing them with the count query in the SQL header.
3. Until (2) happens, anyone with direct `jw_cinema_writer` access (the gated `/api/pg-stage/...` routes)
   can still approve their own quote. The compat layer does not cover those routes.

## 7. Not decided / not proven
Owner decisions: apply the side tables (yes/no, when); require admin for order creation or add an operator role;
add the quote constraint and fixture change. Not proven: PG17 behaviour (CI pending), the Supabase project,
any HTTP route, any UI behaviour, the 36 checks against a database that holds real data.
