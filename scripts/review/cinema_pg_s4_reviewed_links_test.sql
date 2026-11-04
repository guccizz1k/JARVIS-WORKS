-- S4 independently reviewable historical mapping: entirely synthetic PG17 test.
-- Runs only in a database with prefix jw_cinema_s4_link_. No real data.
CREATE SCHEMA jw_s4_link_test;
CREATE FUNCTION jw_s4_link_test.ok(n text,v boolean) RETURNS void LANGUAGE plpgsql AS $f$
BEGIN RAISE NOTICE 'TEST|%|%|',n,CASE WHEN v IS TRUE THEN 'PASS' ELSE 'FAIL' END; END $f$;
CREATE FUNCTION jw_s4_link_test.deny(n text,q text,s text)
RETURNS void LANGUAGE plpgsql AS $f$
BEGIN
 EXECUTE q;
 RAISE NOTICE 'TEST|%|FAIL|accepted forbidden action',n;
EXCEPTION WHEN OTHERS THEN
 RAISE NOTICE 'TEST|%|%|SQLSTATE=%',n,
   CASE WHEN SQLSTATE=s THEN 'PASS' ELSE 'FAIL' END,SQLSTATE;
END $f$;
GRANT USAGE ON SCHEMA jw_s4_link_test TO jw_cinema_writer,anon;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA jw_s4_link_test TO jw_cinema_writer,anon;

INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at)
VALUES('s4-link-member-a','ci-a','member@invalid.test','synthetic','Member A','member',now()::text);
INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at)
VALUES('s4-link-admin-a','hash_a_admin1','ci-ua',(now()+interval '2 hours')::text,'csrf',now()::text),
 ('s4-link-member','hash_a_member','s4-link-member-a',(now()+interval '2 hours')::text,'csrf',now()::text),
 ('s4-link-admin-b','hash_b_admin','ci-ub',(now()+interval '2 hours')::text,'csrf',now()::text);

UPDATE jw_dev.customers SET business_number='123-45-67890' WHERE id='ci-customer-a';
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,
 title,status,vat_mode,created_at,updated_at) VALUES
 ('old-q-a','ci-a','ci-customer-a','Synthetic A','Q-2026-S4-0001',
  'Synthetic Historical','approved','taxable',now()::text,now()::text);
INSERT INTO jw_dev.quote_items(id,quote_id,name,quantity,unit_price,position) VALUES
 ('old-line-a1','old-q-a','Part A',5,3501,0),
 ('old-line-a2','old-q-a','Part B',2,1000,1);
INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,business_number,created_by)
 VALUES('s4-part-a','ci-a','Synthetic Client','1234567890','s4-link-member-a');
INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,
 vat_mode,created_by)
 VALUES('new-q-a','ci-a','T261105-S4A','s4-part-a','Synthetic CINEMA','draft',
  'taxable','s4-link-member-a');
INSERT INTO jw_dev.cinema_pg_quote_items(id,org_id,quote_id,position,name,quantity,unit_price)
 VALUES('new-line-a1','ci-a','new-q-a',0,'Part B',2,1000),
       ('new-line-a2','ci-a','new-q-a',1,'Part A',5,3501);
UPDATE jw_dev.cinema_pg_quotes SET status='submitted',version=2,
 submitted_by='s4-link-member-a' WHERE id='new-q-a';
UPDATE jw_dev.cinema_pg_quotes SET status='approved',version=3,
 approved_by='ci-ua',approved_at=now() WHERE id='new-q-a';

-- SHA baseline of the ENTIRE old quote identity and its item multiset,
-- captured before any approval, never provided by client-side metadata.
CREATE TABLE jw_s4_link_test.original_quote_sha(sha text NOT NULL);
INSERT INTO jw_s4_link_test.original_quote_sha(sha)
SELECT encode(sha256(convert_to(
 jw_dev.cinema_pg_s4_legacy_snapshot('ci-a','old-q-a')::text,'UTF8')),'hex');

SELECT jw_s4_link_test.ok('S4L.01_review_table_force_rls',
 (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
  WHERE oid='jw_dev.cinema_pg_s4_reviewed_links'::regclass));
SELECT jw_s4_link_test.ok('S4L.02_no_public_link_grants',
 NOT has_table_privilege('jw_cinema_writer','jw_dev.cinema_pg_s4_reviewed_links','INSERT')
 AND NOT has_table_privilege('jw_app_dev','jw_dev.cinema_pg_s4_reviewed_links','SELECT')
 AND NOT has_table_privilege('anon','jw_dev.cinema_pg_s4_reviewed_links','SELECT'));
SELECT jw_s4_link_test.ok('S4L.03_two_original_doc_numbers_differ',
 (SELECT doc_no FROM jw_dev.quotes WHERE id='old-q-a')
 <> (SELECT trade_no FROM jw_dev.cinema_pg_quotes WHERE id='new-q-a'));
SELECT jw_s4_link_test.ok('S4L.04_claims_empty_and_link_empty',
 (SELECT count(*) FROM jw_dev.cinema_pg_s4_reviewed_links)=0);

SET ROLE jw_cinema_writer;
SELECT set_config('jw.session_hash','hash_a_admin1',false);
SELECT jw_s4_link_test.deny('S4L.05_no_implicit_sum_without_link',
 $$SELECT jw_dev.cinema_pg_s4_single_source_total()$$,'23514');
SELECT jw_s4_link_test.deny('S4L.06_writer_cannot_insert_links',
 $$INSERT INTO jw_dev.cinema_pg_s4_reviewed_links(org_id,legacy_quote_id,cinema_quote_id,
  legacy_sha256,cinema_sha256,approved_by,audit_reference,request_id)
 VALUES('ci-a','x','y',repeat('0',64),repeat('0',64),'x','fake approved ref','attempt111')$$,'42501');
SELECT set_config('jw.session_hash','hash_a_member',false);
SELECT jw_s4_link_test.deny('S4L.07_member_cannot_approve',
 $$SELECT jw_dev.cinema_pg_s4_link_approve('s4-review-member-0001',
   'old-q-a','new-q-a','valid evidence ref 0001')$$,'42501');
SELECT set_config('jw.session_hash','hash_b_admin',false);
SELECT jw_s4_link_test.deny('S4L.08_other_tenant_cannot_approve',
 $$SELECT jw_dev.cinema_pg_s4_link_approve('s4-review-cross-0001',
   'old-q-a','new-q-a','valid evidence ref 0002')$$,'42501');
SELECT set_config('jw.session_hash','hash_a_admin1',false);
SELECT jw_s4_link_test.deny('S4L.09_short_review_ref_rejected',
 $$SELECT jw_dev.cinema_pg_s4_link_approve('s4-review-invalid-01',
   'old-q-a','new-q-a','short')$$,'23514');

DO $t$
DECLARE r jsonb;
BEGIN
 r:=jw_dev.cinema_pg_s4_link_approve('s4-review-approved-0001',
     'old-q-a','new-q-a','independent-admin-review-evidence-a');
 PERFORM jw_s4_link_test.ok('S4L.10_server_admin_approved',
    (r->>'approved_by')='ci-ua' AND (r->>'org')='ci-a'
    AND (r->>'replayed')='false');
 r:=jw_dev.cinema_pg_s4_link_approve('s4-review-approved-0001',
     'old-q-a','new-q-a','independent-admin-review-evidence-a');
 PERFORM jw_s4_link_test.ok('S4L.11_idempotent_same_request',
    (r->>'replayed')='true');
EXCEPTION WHEN OTHERS THEN
 RAISE NOTICE 'TEST|S4L.10_or_11|FAIL|SQLSTATE=%',SQLSTATE;
END $t$;

SELECT jw_s4_link_test.ok('S4L.12_audit_immutable_actor_recorded',
 (SELECT count(*) FROM jw_dev.cinema_pg_audit WHERE org_id='ci-a'
  AND actor_id='ci-ua' AND action='historical_link_reviewed'
  AND request_id='s4-review-approved-0001')=1);
SELECT jw_s4_link_test.ok('S4L.13_single_source_19505_krw',
 jw_dev.cinema_pg_s4_single_source_total()=19505);
SELECT jw_s4_link_test.deny('S4L.14_conflicting_request_id_rejected',
 $$SELECT jw_dev.cinema_pg_s4_link_approve('s4-review-reuse-0002',
   'old-q-a','new-q-a','independent-admin-review-evidence-a')$$,'23505');
SELECT jw_s4_link_test.deny('S4L.15_cannot_change_approved_links',
 $$UPDATE jw_dev.cinema_pg_s4_reviewed_links SET approved_by='intruder' WHERE org_id='ci-a'$$,'42501');
SELECT jw_s4_link_test.deny('S4L.16_wrong_tenant_cannot_read_approval',
 $$SELECT jw_dev.cinema_pg_s4_link_approve('s4-review-nonexistent-a1',
   'old-q-b','new-q-a','independent-admin-review-evidence-a')$$,'42501');

RESET ROLE;
-- Synthetic unlinked quote exists ONLY inside this rollback. CINEMA sources
-- are append-only and must never be deleted merely to clean up a test.
BEGIN;
INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,
 vat_mode,created_by)
 VALUES('new-q-unlinked','ci-a','T261105-S4B','s4-part-a','Unlinked CINEMA','draft',
  'taxable','s4-link-member-a');
INSERT INTO jw_dev.cinema_pg_quote_items(id,org_id,quote_id,position,name,quantity,unit_price)
 VALUES('new-line-unlinked','ci-a','new-q-unlinked',0,'Part A',1,50);
UPDATE jw_dev.cinema_pg_quotes SET status='submitted',version=2,
 submitted_by='s4-link-member-a' WHERE id='new-q-unlinked';
UPDATE jw_dev.cinema_pg_quotes SET status='approved',version=3,
 approved_by='ci-ua',approved_at=now() WHERE id='new-q-unlinked';
SET ROLE jw_cinema_writer;
SELECT set_config('jw.session_hash','hash_a_admin1',false);
SELECT jw_s4_link_test.deny('S4L.17_unmapped_second_quote_blocks_sum',
 $SELECT jw_dev.cinema_pg_s4_single_source_total()$,'23514');
ROLLBACK;

-- The old v92 quote_items can still change in this disposable fixture. Never
-- continue using the approved link without verifying the stored source hash.
UPDATE jw_dev.quote_items SET unit_price=3502 WHERE id='old-line-a1';
SET ROLE jw_cinema_writer;
SELECT set_config('jw.session_hash','hash_a_admin1',false);
SELECT jw_s4_link_test.deny('S4L.18_stale_original_data_blocks_total',
 $$SELECT jw_dev.cinema_pg_s4_single_source_total()$$,'23514');
SELECT jw_s4_link_test.deny('S4L.19_stale_approval_cannot_replay',
 $$SELECT jw_dev.cinema_pg_s4_link_approve('s4-review-approved-0001',
  'old-q-a','new-q-a','independent-admin-review-evidence-a')$$,'23514');
RESET ROLE;
UPDATE jw_dev.quote_items SET unit_price=3501 WHERE id='old-line-a1';

SET ROLE jw_cinema_writer;
SELECT set_config('jw.session_hash','hash_a_admin1',false);
SELECT jw_s4_link_test.ok('S4L.20_original_restored_total_recomputes',
 jw_dev.cinema_pg_s4_single_source_total()=19505);
RESET ROLE;
SELECT jw_s4_link_test.ok('S4L.21_old_quote_not_rewritten',
 (SELECT doc_no FROM jw_dev.quotes WHERE id='old-q-a')='Q-2026-S4-0001');
SELECT jw_s4_link_test.ok('S4L.22_total_links_exactly_one',
 (SELECT count(*) FROM jw_dev.cinema_pg_s4_reviewed_links WHERE org_id='ci-a')=1);

SELECT jw_s4_link_test.ok('S4L.23_original_v92_snapshot_hash_identical',
 (SELECT sha FROM jw_s4_link_test.original_quote_sha)=
 encode(sha256(convert_to(jw_dev.cinema_pg_s4_legacy_snapshot('ci-a','old-q-a')::text,'UTF8')),'hex'));
