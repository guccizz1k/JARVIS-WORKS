# V22.3 P0-2 — per-organisation cutover of the trade chain, with the SQLite data preserved

Status: **DESIGN + a measuring tool. Nothing here is wired, applied or executed against real data.**
Owner direction followed: the unit that switches is one **organisation's whole trade chain**; existing
SQLite real data is preserved; the legacy order -> invoice shortcut is never emulated with invented
deliveries or statements; the two-person approval principle for quotes and deliveries is kept.

요약(한국어): 전환 단위는 "기업 1곳의 거래 체인 전체"입니다. 기존 SQLite 데이터는 지우지도, 가짜 납품·명세로
PG에 옮기지도 않습니다. 이관 가능한 것은 거래처(고객→partner) 기준 데이터뿐이고, 견적·주문·청구·입금 이력은
SQLite에 그대로 둡니다. 새 문서만 PG에서 만들고, 진행 중이던 문서는 시작한 쪽(레거시)에서 끝냅니다.

## 1. Facts this design rests on (checked in the code, not assumed)
| # | fact | where |
|---|---|---|
| 1 | The PG chain is quote -> order -> delivery (uploaded evidence, confirmed by a *different* admin) -> statement -> invoice (reviewed, confirmed) -> payment. Every link is a NOT NULL foreign key. | `cinema_pg_write_engine.sql` (tables `cinema_pg_deliveries`, `_statements`, `_invoices`) |
| 2 | A legacy invoice is created straight from an order (`invoices.order_id UNIQUE`); it has no delivery, evidence or statement. | `app/main.py:185`, route at `main.py:1383` |
| 3 | PG tables are append-only or guarded by triggers and are written only by SECURITY DEFINER functions. A bulk `INSERT` of history would bypass the engine's own invariants, which its SQL gate asserts cannot be done (G3.50-53). | engine triggers and grants |
| 4 | Legacy ids are `uuid4().hex` (32 hex). PG ids are `replace(gen_random_uuid()::text,'-','')` (32 hex). **The two cannot be told apart by format.** | `main.py:69`, `cinema_pg_new_id()` |
| 5 | Legacy `customers` allow duplicate or free-text business numbers; PG partners require a 10-digit number or empty, unique per organisation. Legacy `payments.reversed_at` has no reason; PG reversals require one (1..300 chars). | DDL of both |
| 6 | Order `due_date`, invoice `due_date` (the pay-by date used for the `overdue` status) and payment `note` have no PG column. | see the terms proposal |

## 2. What can and cannot be moved
| legacy data | can it enter PG honestly? | decision |
|---|---|---|
| customers | yes, as partners, if every row fits the PG limits (inventory reports the blockers) | **import after the owner fixes blockers**, through `cinema_pg_partner_upsert` (audited), never by bulk SQL |
| quotes `draft` | technically yes (new PG drafts) but they would get new numbers and ids | **do not import**; finish or discard in legacy |
| quotes `sent/accepted/rejected`, orders, invoices, payments | **no** - the PG chain would need deliveries, evidence and statements that never existed | **stay in SQLite**, read-only after the org switches (or "legacy home" while in flight) |
| audit logs, security events | not part of the trade chain | unchanged |

Nothing is deleted from SQLite at any step. A cutover can be rolled back by turning the organisation
back to `legacy`; PG documents created in the meantime stay in PG and are listed there.

## 3. Cutover unit and routing
* **Unit:** one organisation. Flag `trade_backend` = `legacy` (default) | `pg`. For the pilot use an
  environment allow-list (`JW_PG_TRADE_ORGS=<org ids>`): no schema change, rollback = remove the
  variable and redeploy. A table is a later step.
* **Home of a document = the store it was created in, and the id says which (decided).** Legacy and PG ids
  have the same 32-hex shape (fact 4), so PG ids are exposed as `pg_<32 hex>` on **every** PG entity
  (`app/pg_cinema_compat_view_v1.py`). Checked in the V22.2 UI source: ids are opaque - the only things done
  with them are `order.quote_id === quote.id` (so the prefix must be applied to every entity, which the tests
  assert), `id.split('|')` on the UI's own `id|status` pairs (the prefix has no `|`), and URL path use (the
  prefix is `[A-Za-z0-9_]`). Routing looks only at the prefix: `pg_` plus 32 hex goes to PG, a malformed or
  differently cased `pg_` id is refused (never treated as legacy), anything else is legacy. No lookup in both
  stores is needed, and a collision is impossible by construction.
* **Creation** (new quote, order from quote, payment) goes to the organisation's backend.
* **Continuation** of a legacy document goes to legacy, including the six steps that have no PG
  equivalent (invoice from order, statement from order, order edit/acknowledge/status, adjustments).
  Those steps are refused with a stable 409 only for PG-home documents. Legacy-home documents keep
  every feature they have today.
* **Lists** show both homes with a `source` field; a PG row is never mixed into a legacy total
  without saying so.

## 4. Entering a switch: the gate before an organisation may be set to `pg`
Run `scripts/ci_cinema_pg_cutover_inventory_v223.py --db <copy>` on a copy of the SQLite file with the
application stopped. It is read-only (SQLite `mode=ro` + `query_only`, SHA-256 before and after) and
prints counts only. An organisation may switch when:
1. `partner_import = READY` (or the owner accepts importing none and creating partners afresh);
2. `new_documents_in_pg` is `CLEAN_START`, **or** the owner accepts `DUAL_HOME_REQUIRED` (some legacy
   orders / unpaid invoices will finish in legacy);
3. the owner has decided the three schema questions in
   `cinema-pg-v223-terms-and-two-person-proposal.md` (due date, pay-by date, payment note);
4. at least two administrators exist in the organisation (delivery confirmation needs a second one).

## 5. Two-person principle in PG mode
| step | enforced by | status |
|---|---|---|
| delivery confirmation: approver != recorder, and the approver must have opened the stored evidence | **PG engine** (`engine.sql:909`, tests G3.38, G3.86) | enforced in the database |
| quote approval: approver != submitter | **not enforced by PG** (measured: the engine checks only the admin role) | enforced **in the compat layer, fail-closed** (`quote_approval_guard`); a database constraint is proposed and its impact on the existing 222 checks is measured in the proposal |
| invoice review, then confirmation | PG engine requires the order (draft -> reviewed -> confirmed) and an administrator at each step, but **the same administrator may do both** (measured; outside the owner's quote/delivery principle, recorded so it is not mistaken for a two-person step) | order enforced, two-person **not** enforced |

UI consequence to accept: where the legacy UI lets one person do everything, a PG-home document shows
"waiting for a second administrator". Codes: `quote_second_person_required`,
`delivery_second_person_required` (both HTTP 409, Korean messages in `PG_ERROR_MAP`).

## 6. Order of work (each item verifiable without the dev database)
1. Inventory tool + tests - **done** (15 tests, 14 mutants killed, run on synthetic DBs built from the real DDL).
2. Compat rules, two-person guard, engine-error mapping - **done**; response views (PG entity -> legacy shape, `pg_` ids, KST times, legacy money rule) - **done**, pinned to real engine output (59 tests, 16 breakages caught).
3. Terms side tables + database-level quote two-person rule, behaviour-tested on a throw-away PG16 - **done** (59 checks incl. real-output view contract); PG17 via CI is pending.
4. Wire routes behind the allow-list in an environment that has FastAPI and PG17 (CI) - **not started**.
5. Legacy-vs-PG equivalence run for the ADAPT steps (status class, money fields, resulting status, audit rows) - **not started**.
6. E2E for company A/B/C: sign-up, login, MFA, CSRF, RLS, quote -> payment -> report - **not started**.

## 7. What this does not prove
No route is wired; no HTTP request was made; no real SQLite data was inspected (the tool was run only on
synthetic databases); PG17 was not used for any check in this document; the UI was not driven.
P0-2 stays **PARTIAL**.
