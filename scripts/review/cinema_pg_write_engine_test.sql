-- Test script for cinema_pg_write_engine.sql. DISPOSABLE DATABASE ONLY.
-- Run as a superuser after the base jw_dev CI schema and the engine are applied.
-- Every check prints:  TEST|<gate>.<id>_<name>|PASS|FAIL|<detail>
-- Gate prefixes: G2 = functional correctness, G3 = stability/regression,
-- G5 = database-level security. (G1 build/hash and G4 UI are NOT covered here.)

CREATE SCHEMA jw_test;
GRANT USAGE ON SCHEMA jw_test TO jw_cinema_writer, anon, jw_app_dev;

CREATE FUNCTION jw_test.ok(p_name text, p_cond boolean, p_detail text DEFAULT '') RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  RAISE NOTICE 'TEST|%|%|%', p_name, CASE WHEN p_cond IS TRUE THEN 'PASS' ELSE 'FAIL' END, p_detail;
END $$;

CREATE FUNCTION jw_test.expect_err(p_name text, p_sql text, p_state text) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE p_sql;
  RAISE NOTICE 'TEST|%|FAIL|no error raised, expected %', p_name, p_state;
EXCEPTION WHEN OTHERS THEN
  IF SQLSTATE = p_state THEN
    RAISE NOTICE 'TEST|%|PASS|%', p_name, left(SQLERRM,120);
  ELSE
    RAISE NOTICE 'TEST|%|FAIL|expected % got % %', p_name, p_state, SQLSTATE, left(SQLERRM,160);
  END IF;
END $$;

CREATE FUNCTION jw_test.as_(p_hash text) RETURNS void LANGUAGE sql AS
$$ SELECT set_config('jw.session_hash', p_hash, false) $$;
CREATE FUNCTION jw_test.put(k text, v text) RETURNS void LANGUAGE sql AS
$$ SELECT set_config('jwt.'||k, v, false) $$;
CREATE FUNCTION jw_test.get(k text) RETURNS text LANGUAGE sql AS
$$ SELECT current_setting('jwt.'||k) $$;
CREATE FUNCTION jw_test.id_of(r jsonb) RETURNS text LANGUAGE sql IMMUTABLE AS
$$ SELECT r->'entity'->>'id' $$;
CREATE FUNCTION jw_test.q(p_sql text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE v text; BEGIN EXECUTE p_sql INTO v; RETURN v; END $$;
-- Uploads synthetic evidence (a tiny PDF-looking blob) as the CURRENT session and returns the
-- SHA-256 the SERVER computed. Deterministic request id => idempotent per session+text.
CREATE FUNCTION jw_test.ev(p_text text) RETURNS text LANGUAGE plpgsql AS $$
DECLARE r jsonb;
BEGIN
  r := jw_dev.cinema_pg_evidence_put(
         'rq-ev-'||encode(sha256(convert_to(p_text||current_setting('jw.session_hash'),'UTF8')),'hex'),
         p_text||'.pdf','application/pdf',convert_to('%PDF-1.4 '||p_text,'UTF8'));
  RETURN r->'entity'->>'content_sha256';
END $$;
-- Opens the stored evidence behind a delivery as the CURRENT session (the audited "원본 대조").
CREATE FUNCTION jw_test.view_ev(p_delivery text) RETURNS void LANGUAGE plpgsql AS $$
DECLARE v_ev text;
BEGIN
  SELECT e.id INTO v_ev FROM jw_dev.cinema_pg_deliveries d
    JOIN jw_dev.cinema_pg_evidence_files e ON e.org_id=d.org_id AND e.content_sha256=d.evidence_sha256
   WHERE d.id=p_delivery;
  PERFORM * FROM jw_dev.cinema_pg_evidence_open(
     'rq-vw-'||encode(sha256(convert_to(p_delivery||current_setting('jw.session_hash'),'UTF8')),'hex'),v_ev);
END $$;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA jw_test TO jw_cinema_writer, anon, jw_app_dev;

-- ------------------------------------------------------------ fixtures
INSERT INTO jw_dev.users(id,org_id,email,password_hash,name,role,created_at) VALUES
 ('ci-ua2','ci-a','a2@invalid.test','synthetic','A Admin 2','admin',now()::text),
 ('ci-ua3','ci-a','a3@invalid.test','synthetic','A Member','member',now()::text);
INSERT INTO jw_dev.sessions(id,token_hash,user_id,expires_at,csrf_token,created_at) VALUES
 ('s-a1','hash_a_admin1','ci-ua', (now()+interval '2 hours')::text,'csrf-a1',now()::text),
 ('s-a2','hash_a_admin2','ci-ua2',(now()+interval '2 hours')::text,'csrf-a2',now()::text),
 ('s-a3','hash_a_member','ci-ua3',(now()+interval '2 hours')::text,'csrf-a3',now()::text),
 ('s-b1','hash_b_admin','ci-ub',  (now()+interval '2 hours')::text,'csrf-b1',now()::text),
 ('s-c1','hash_c_admin','ci-uc',  (now()+interval '2 hours')::text,'csrf-c1',now()::text),
 ('s-ax','hash_a_expired','ci-ua',(now()-interval '1 hour')::text,'csrf-ax',now()::text);

-- =====================================================================
-- G2: functional correctness (normal flow with exact KRW figures)
-- =====================================================================
SET ROLE jw_cinema_writer;

DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_partner_upsert('rq-g2-partner-01',NULL,'ACME Trading','123-45-67890','Kim','kim@acme.test','02-000-0000',NULL);
  PERFORM jw_test.put('pA',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.01_partner_create', (r->'entity'->>'version')='1' AND (r->>'replayed')='false'
         AND (r->'entity'->>'business_number')='1234567890', 'hyphenated number normalised to digits');
  r := jw_dev.cinema_pg_partner_upsert('rq-g2-partner-02',jw_test.get('pA'),'ACME Trading Co.','1234567890','Kim','kim@acme.test','02-000-0000',1);
  PERFORM jw_test.ok('G2.02_partner_update_bumps_version', (r->'entity'->>'version')='2' AND (r->'entity'->>'name')='ACME Trading Co.');
  r := jw_dev.cinema_pg_partner_upsert('rq-g2-partner-03',NULL,'No BN Partner','','','','',NULL);
  PERFORM jw_test.ok('G2.03_partner_without_business_number', (r->'entity'->>'business_number')='');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.0x_partner|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_a_member');
  r := jw_dev.cinema_pg_quote_create('rq-g2-quote-01',jw_test.get('pA'),'Q1 draft','taxable',
        '[{"name":"Widget","quantity":5,"unit_price":3501}]'::jsonb);
  PERFORM jw_test.put('q1',jw_test.id_of(r));
  PERFORM jw_test.put('trade1',r->'entity'->>'trade_no');
  PERFORM jw_test.ok('G2.04_member_creates_draft_quote', (r->'entity'->>'status')='draft'
        AND (r->'entity'->>'trade_no') ~ '^T[0-9]{6}-0001$', r->'entity'->>'trade_no');
  r := jw_dev.cinema_pg_quote_update('rq-g2-quote-02',jw_test.get('q1'),1,'Q1 final',
        '[{"name":"Widget","quantity":5,"unit_price":3501},{"name":"Gadget","quantity":2,"unit_price":1000}]'::jsonb);
  PERFORM jw_test.ok('G2.05_draft_quote_update_replaces_lines', (r->'entity'->>'version')='2'
        AND jsonb_array_length(r->'entity'->'items')=2 AND (r->'entity'->>'title')='Q1 final');
  r := jw_dev.cinema_pg_quote_transition('rq-g2-quote-03',jw_test.get('q1'),2,'submitted');
  PERFORM jw_test.ok('G2.06_submit_quote', (r->'entity'->>'status')='submitted' AND (r->'entity'->>'version')='3');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.0x_quote|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_quote_transition('rq-g2-quote-04',jw_test.get('q1'),3,'approved');
  PERFORM jw_test.ok('G2.07_admin_approves_quote', (r->'entity'->>'status')='approved'
        AND (r->'entity'->>'approved_by')='ci-ua');
  r := jw_dev.cinema_pg_order_create('rq-g2-order-01',jw_test.get('q1'));
  PERFORM jw_test.put('o1',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.08_order_from_approved_quote', (r->'entity'->>'status')='open'
        AND (r->'entity'->>'trade_no')=jw_test.get('trade1') AND jsonb_array_length(r->'entity'->'items')=2);
  PERFORM jw_test.ok('G2.09_quote_marked_ordered', jw_test.q(format('SELECT status FROM jw_dev.cinema_pg_quotes WHERE id=%L',jw_test.get('q1')))='ordered');
  PERFORM jw_test.put('w1',jw_test.q(format('SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id=%L AND position=0',jw_test.get('o1'))));
  PERFORM jw_test.put('g1',jw_test.q(format('SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id=%L AND position=1',jw_test.get('o1'))));
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.0x_order|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r jsonb; BEGIN
  -- partial delivery 1: 3 of 5 Widgets, recorded by the member, confirmed by an admin
  PERFORM jw_test.as_('hash_a_member');
  r := jw_dev.cinema_pg_delivery_record('rq-g2-deliv-01',jw_test.get('o1'),
        format('[{"order_item_id":"%s","quantity":3}]',jw_test.get('w1'))::jsonb,
        jw_test.ev('evidence-1'),'dn-001.pdf');
  PERFORM jw_test.put('d1',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.10_partial_delivery_recorded_pending', (r->'entity'->>'status')='recorded' AND (r->'entity'->>'seq')='1');
  PERFORM jw_test.as_('hash_a_admin1');
  PERFORM jw_test.view_ev(jw_test.get('d1'));
  r := jw_dev.cinema_pg_delivery_confirm('rq-g2-deliv-02',jw_test.get('d1'));
  PERFORM jw_test.ok('G2.11_delivery_confirmed_by_other_admin', (r->'entity'->>'status')='confirmed' AND (r->'entity'->>'approved_by')='ci-ua');
  PERFORM jw_test.ok('G2.12_order_stays_open_after_partial', jw_test.q(format('SELECT status FROM jw_dev.cinema_pg_orders WHERE id=%L',jw_test.get('o1')))='open');
  -- delivery 2: remaining 2 Widgets + 2 Gadgets
  PERFORM jw_test.as_('hash_a_member');
  r := jw_dev.cinema_pg_delivery_record('rq-g2-deliv-03',jw_test.get('o1'),
        format('[{"order_item_id":"%s","quantity":2},{"order_item_id":"%s","quantity":2}]',jw_test.get('w1'),jw_test.get('g1'))::jsonb,
        jw_test.ev('evidence-2'),'dn-002.pdf');
  PERFORM jw_test.put('d2',jw_test.id_of(r));
  PERFORM jw_test.as_('hash_a_admin2');
  PERFORM jw_test.view_ev(jw_test.get('d2'));
  r := jw_dev.cinema_pg_delivery_confirm('rq-g2-deliv-04',jw_test.get('d2'));
  PERFORM jw_test.ok('G2.13_full_confirmation_fulfils_order', jw_test.q(format('SELECT status FROM jw_dev.cinema_pg_orders WHERE id=%L',jw_test.get('o1')))='fulfilled');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.1x_delivery|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_a_member');
  r := jw_dev.cinema_pg_statement_create('rq-g2-stmt-01',jw_test.get('d1'));
  PERFORM jw_test.put('s1',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.14_statement1_money', (r->'entity'->>'subtotal_krw')='10503' AND (r->'entity'->>'vat_krw')='1050'
        AND (r->'entity'->>'total_krw')='11553' AND (r->'entity'->>'status')='draft', 'subtotal 10503 vat 1050 total 11553');
  r := jw_dev.cinema_pg_statement_create('rq-g2-stmt-02',jw_test.get('d2'));
  PERFORM jw_test.put('s2',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.15_statement2_money', (r->'entity'->>'subtotal_krw')='9002' AND (r->'entity'->>'vat_krw')='900'
        AND (r->'entity'->>'total_krw')='9902', 'subtotal 9002 vat 900 total 9902');
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_statement_confirm('rq-g2-stmt-03',jw_test.get('s1'));
  PERFORM jw_test.ok('G2.16_statement_confirmed', (r->'entity'->>'status')='confirmed' AND (r->'entity'->>'confirmed_by')='ci-ua');
  r := jw_dev.cinema_pg_statement_confirm('rq-g2-stmt-04',jw_test.get('s2'));
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.1x_statement|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_a_member');
  r := jw_dev.cinema_pg_invoice_create('rq-g2-inv-01',jw_test.get('s1'));
  PERFORM jw_test.put('i1',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.17_invoice_draft_from_statement', (r->'entity'->>'total_krw')='11553' AND (r->'entity'->>'status')='draft'
        AND (r->'entity'->>'invoice_no') = 'INV-'||jw_test.get('trade1')||'-01');
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_invoice_review('rq-g2-inv-02',jw_test.get('i1'));
  PERFORM jw_test.ok('G2.18_invoice_reviewed', (r->'entity'->>'status')='reviewed');
  r := jw_dev.cinema_pg_invoice_confirm('rq-g2-inv-03',jw_test.get('i1'));
  PERFORM jw_test.ok('G2.19_invoice_confirmed', (r->'entity'->>'status')='confirmed');
  r := jw_dev.cinema_pg_payment_record('rq-g2-pay-01',jw_test.get('i1'),5000,current_date,'BANKREF-0001');
  PERFORM jw_test.put('p1',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.20_partial_payment_recorded', (r->'entity'->>'amount_krw')='5000' AND (r->'entity'->>'bank_confirmed')='false');
  PERFORM jw_test.ok('G2.21_balance_after_partial', (jw_dev.cinema_pg_trade_trace(jw_test.get('trade1'))->'invoices'->0->>'balance_krw')='6553');
  r := jw_dev.cinema_pg_payment_record('rq-g2-pay-02',jw_test.get('i1'),6553,current_date,'BANKREF-0002');
  PERFORM jw_test.put('p2',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.22_balance_zero_when_fully_paid', (jw_dev.cinema_pg_trade_trace(jw_test.get('trade1'))->'invoices'->0->>'balance_krw')='0');
  r := jw_dev.cinema_pg_payment_reverse('rq-g2-pay-03',jw_test.get('p2'),'bank rejected transfer');
  PERFORM jw_test.ok('G2.23_payment_reversal_restores_balance', (r->'entity'->>'reversed')='true'
        AND (jw_dev.cinema_pg_trade_trace(jw_test.get('trade1'))->'invoices'->0->>'balance_krw')='6553');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.2x_invoice_payment|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE v jsonb; n integer; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  v := jw_dev.cinema_pg_trade_trace(jw_test.get('trade1'));
  PERFORM jw_test.ok('G2.24_trace_links_every_document', jsonb_array_length(v->'quotes')=1 AND jsonb_array_length(v->'orders')=1
        AND jsonb_array_length(v->'deliveries')=2 AND jsonb_array_length(v->'statements')=2
        AND jsonb_array_length(v->'invoices')=1 AND jsonb_array_length(v->'payments')=2);
  PERFORM jw_test.ok('G2.25_trace_never_claims_bank_settlement', (v->'flags'->>'bank_settlement_confirmed')='false'
        AND (v->'flags'->>'payment_basis')='internal_record_only' AND (v->'flags'->>'release_ready')='false');
  PERFORM jw_test.ok('G2.26_trace_reports_measured_seconds_only', jsonb_array_length(v->'measured_seconds')=2
        AND (v->'measured_seconds'->0->>'record_to_confirm')::numeric >= 0);
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_integrity_check();
  PERFORM jw_test.ok('G2.27_integrity_check_clean_after_full_flow', n=0, 'violations='||n);
  -- quote 4 + order 1 + deliveries 4 + statements 4 + invoice 3 + payments 3 = 19 state changes
  PERFORM jw_test.ok('G2.28_trace_audit_has_one_row_per_state_change', jsonb_array_length(v->'audit') = 19, 'audit rows='||jsonb_array_length(v->'audit'));
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.2x_trace|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

-- second trade: cancel / reverse / void paths
DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_quote_create('rq-g2-quote-t2a',jw_test.get('pA'),'Q2','exempt','[{"name":"Bolt","quantity":10,"unit_price":100}]'::jsonb);
  PERFORM jw_test.put('q2',jw_test.id_of(r)); PERFORM jw_test.put('trade2',r->'entity'->>'trade_no');
  PERFORM jw_test.ok('G2.29_second_trade_gets_next_number', (r->'entity'->>'trade_no') ~ '-0002$');
  PERFORM jw_dev.cinema_pg_quote_transition('rq-g2-quote-t2b',jw_test.get('q2'),1,'submitted');
  PERFORM jw_dev.cinema_pg_quote_transition('rq-g2-quote-t2c',jw_test.get('q2'),2,'approved');
  r := jw_dev.cinema_pg_order_create('rq-g2-order-t2',jw_test.get('q2'));
  PERFORM jw_test.put('o2',jw_test.id_of(r));
  PERFORM jw_test.put('b2',jw_test.q(format('SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id=%L AND position=0',jw_test.get('o2'))));
  PERFORM jw_test.as_('hash_a_member');
  r := jw_dev.cinema_pg_delivery_record('rq-g2-t2-d1',jw_test.get('o2'),
        format('[{"order_item_id":"%s","quantity":10}]',jw_test.get('b2'))::jsonb,jw_test.ev('evidence-t2a'),'t2a.pdf');
  PERFORM jw_test.put('d3',jw_test.id_of(r));
  r := jw_dev.cinema_pg_delivery_cancel('rq-g2-t2-d1x',jw_test.get('d3'),'wrong consignee');
  PERFORM jw_test.ok('G2.30_pending_delivery_cancel', (r->'entity'->>'status')='cancelled');
  r := jw_dev.cinema_pg_delivery_record('rq-g2-t2-d2',jw_test.get('o2'),
        format('[{"order_item_id":"%s","quantity":10}]',jw_test.get('b2'))::jsonb,jw_test.ev('evidence-t2b'),'t2b.pdf');
  PERFORM jw_test.ok('G2.31_cancel_releases_reserved_quantity', (r->'entity'->>'seq')='2');
  PERFORM jw_test.put('d4',jw_test.id_of(r));
  PERFORM jw_test.as_('hash_a_admin1');
  PERFORM jw_test.view_ev(jw_test.get('d4'));
  PERFORM jw_dev.cinema_pg_delivery_confirm('rq-g2-t2-d2c',jw_test.get('d4'));
  r := jw_dev.cinema_pg_statement_create('rq-g2-t2-s1',jw_test.get('d4'));
  PERFORM jw_test.put('s3',jw_test.id_of(r));
  PERFORM jw_test.ok('G2.32_exempt_statement_has_zero_vat', (r->'entity'->>'vat_krw')='0' AND (r->'entity'->>'total_krw')='1000');
  PERFORM jw_test.expect_err('G2.33_reverse_delivery_blocked_while_statement_active',
     format('SELECT jw_dev.cinema_pg_delivery_reverse(%L,%L,%L)','rq-g2-t2-r1',jw_test.get('d4'),'x'),'23514');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.3x_second_trade|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  PERFORM jw_dev.cinema_pg_statement_confirm('rq-g2-t2-s1c',jw_test.get('s3'));
  r := jw_dev.cinema_pg_invoice_create('rq-g2-t2-i1',jw_test.get('s3'));
  PERFORM jw_test.put('i2',jw_test.id_of(r));
  PERFORM jw_dev.cinema_pg_invoice_review('rq-g2-t2-i1r',jw_test.get('i2'));
  PERFORM jw_dev.cinema_pg_invoice_confirm('rq-g2-t2-i1c',jw_test.get('i2'));
  r := jw_dev.cinema_pg_payment_record('rq-g2-t2-p1',jw_test.get('i2'),1000,current_date,'T2-REF-1');
  PERFORM jw_test.put('p3',jw_test.id_of(r));
  PERFORM jw_test.expect_err('G2.34_void_invoice_blocked_with_active_payment',
     format('SELECT jw_dev.cinema_pg_invoice_void(%L,%L,%L)','rq-g2-t2-iv1',jw_test.get('i2'),'x'),'23514');
  PERFORM jw_dev.cinema_pg_payment_reverse('rq-g2-t2-p1r',jw_test.get('p3'),'customer error');
  r := jw_dev.cinema_pg_invoice_void('rq-g2-t2-iv2',jw_test.get('i2'),'issued in error');
  PERFORM jw_test.ok('G2.35_invoice_void_after_payment_reversal', (r->'entity'->>'status')='voided');
  r := jw_dev.cinema_pg_statement_void('rq-g2-t2-sv',jw_test.get('s3'),'redo');
  PERFORM jw_test.ok('G2.36_statement_void_after_invoice_void', (r->'entity'->>'status')='voided');
  r := jw_dev.cinema_pg_delivery_reverse('rq-g2-t2-r2',jw_test.get('d4'),'goods returned');
  PERFORM jw_test.ok('G2.37_confirmed_delivery_reversed_not_deleted', (r->'entity'->>'status')='reversed');
  PERFORM jw_test.ok('G2.38_reversal_reopens_order', jw_test.q(format('SELECT status FROM jw_dev.cinema_pg_orders WHERE id=%L',jw_test.get('o2')))='open');
  PERFORM jw_test.expect_err('G2.39_statement_on_reversed_delivery_blocked',
     format('SELECT jw_dev.cinema_pg_statement_create(%L,%L)','rq-g2-t2-s2',jw_test.get('d4')),'23514');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G2.3x_void_paths|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

RESET ROLE;
SELECT jw_test.ok('G2.41_vat_helper_matches_existing_rule',
  jw_dev.cinema_pg_vat(19505,'taxable')=1951 AND jw_dev.cinema_pg_vat(19504,'taxable')=1950
  AND jw_dev.cinema_pg_vat(0,'taxable')=0 AND jw_dev.cinema_pg_vat(19505,'exempt')=0
  AND jw_dev.cinema_pg_vat(4,'taxable')=0 AND jw_dev.cinema_pg_vat(5,'taxable')=1,
  '(subtotal+5)/10 half-up, identical to pg_quote_api_v92.quote_money');

-- =====================================================================
-- G3: stability / regression (idempotency, validation, atomicity, immutability)
-- =====================================================================
SET ROLE jw_cinema_writer;

DO $t$ DECLARE r1 jsonb; r2 jsonb; n integer; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  r1 := jw_dev.cinema_pg_partner_upsert('rq-g3-idem-p1',NULL,'Idem Partner','9998887776','','','',NULL);
  r2 := jw_dev.cinema_pg_partner_upsert('rq-g3-idem-p1',NULL,'Idem Partner','9998887776','','','',NULL);
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_partners WHERE name='Idem Partner';
  PERFORM jw_test.ok('G3.01_partner_replay_same_entity_no_duplicate', jw_test.id_of(r1)=jw_test.id_of(r2) AND (r2->>'replayed')='true' AND n=1);
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.01|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r1 jsonb; r2 jsonb; n integer; BEGIN
  r1 := jw_dev.cinema_pg_quote_create('rq-g3-idem-q1',jw_test.get('pA'),'Idem Q','exempt','[{"name":"X","quantity":1,"unit_price":10}]'::jsonb);
  r2 := jw_dev.cinema_pg_quote_create('rq-g3-idem-q1',jw_test.get('pA'),'Idem Q','exempt','[{"name":"X","quantity":1,"unit_price":10}]'::jsonb);
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_quotes WHERE title='Idem Q';
  PERFORM jw_test.ok('G3.02_quote_replay_no_duplicate_and_no_extra_trade_number', jw_test.id_of(r1)=jw_test.id_of(r2) AND n=1
        AND (r1->'entity'->>'trade_no')=(r2->'entity'->>'trade_no'));
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.02|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE r1 jsonb; r2 jsonb; n integer; BEGIN
  -- replaying an already-executed payment request must not post a second payment
  r1 := jw_dev.cinema_pg_payment_record('rq-g3-pay-replay',jw_test.get('i1'),100,current_date,'REPLAY-REF-1');
  r2 := jw_dev.cinema_pg_payment_record('rq-g3-pay-replay',jw_test.get('i1'),100,current_date,'REPLAY-REF-1');
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_payments WHERE reference='REPLAY-REF-1';
  PERFORM jw_test.ok('G3.03_payment_replay_posts_once', jw_test.id_of(r1)=jw_test.id_of(r2) AND n=1 AND (r2->>'replayed')='true');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.03|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

SELECT jw_test.expect_err('G3.04_request_id_reused_with_different_payload',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,%s,current_date,%L)','rq-g3-pay-replay',jw_test.get('i1'),101,'REPLAY-REF-1'),'23505');
SELECT jw_test.expect_err('G3.05_request_id_too_short',
  format('SELECT jw_dev.cinema_pg_partner_upsert(%L,NULL,%L,%L,%L,%L,%L,NULL)','short','n','','','',''),'23514');
SELECT jw_test.expect_err('G3.06_request_id_bad_characters',
  format('SELECT jw_dev.cinema_pg_partner_upsert(%L,NULL,%L,%L,%L,%L,%L,NULL)','bad id with spaces!!','n','','','',''),'23514');
SELECT jw_test.expect_err('G3.07_stale_partner_version',
  format('SELECT jw_dev.cinema_pg_partner_upsert(%L,%L,%L,%L,%L,%L,%L,%s)','rq-g3-stale-p1',jw_test.get('pA'),'Stale','','','','',1),'40001');
SELECT jw_test.expect_err('G3.08_stale_quote_version',
  format('SELECT jw_dev.cinema_pg_quote_transition(%L,%L,%s,%L)','rq-g3-stale-q1',jw_test.get('q2'),1,'cancelled'),'40001');
SELECT jw_test.expect_err('G3.09_overpayment_by_one_krw_blocked',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,%s,current_date,%L)','rq-g3-over-1',jw_test.get('i1'),6454,'OVER-REF-1'),'23514');
SELECT jw_test.expect_err('G3.10_duplicate_payment_reference_new_request',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,%s,current_date,%L)','rq-g3-dupref-1',jw_test.get('i1'),10,'BANKREF-0001'),'23505');
SELECT jw_test.expect_err('G3.11_zero_payment_blocked',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,%s,current_date,%L)','rq-g3-zero-1',jw_test.get('i1'),0,'ZERO-REF'),'23514');
SELECT jw_test.expect_err('G3.12_negative_payment_blocked',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,%s,current_date,%L)','rq-g3-neg-1',jw_test.get('i1'),-5,'NEG-REF'),'23514');
SELECT jw_test.expect_err('G3.13_future_dated_payment_blocked',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,%s,current_date+1,%L)','rq-g3-future-1',jw_test.get('i1'),5,'FUT-REF'),'23514');
SELECT jw_test.expect_err('G3.14_quote_line_fractional_quantity',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-frac-1',jw_test.get('pA'),'t','exempt','[{"name":"X","quantity":1.5,"unit_price":10}]'),'23514');
SELECT jw_test.expect_err('G3.15_quote_line_fractional_price',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-frac-2',jw_test.get('pA'),'t','exempt','[{"name":"X","quantity":1,"unit_price":10.5}]'),'23514');
SELECT jw_test.expect_err('G3.16_quote_line_string_quantity',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-str-1',jw_test.get('pA'),'t','exempt','[{"name":"X","quantity":"5","unit_price":10}]'),'23514');
SELECT jw_test.expect_err('G3.17_quote_line_negative_price',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-neg-2',jw_test.get('pA'),'t','exempt','[{"name":"X","quantity":1,"unit_price":-1}]'),'23514');
SELECT jw_test.expect_err('G3.18_quote_line_quantity_over_limit',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-big-1',jw_test.get('pA'),'t','exempt','[{"name":"X","quantity":100001,"unit_price":1}]'),'23514');
SELECT jw_test.expect_err('G3.19_quote_line_price_over_limit',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-big-2',jw_test.get('pA'),'t','exempt','[{"name":"X","quantity":1,"unit_price":1000000001}]'),'23514');
SELECT jw_test.expect_err('G3.20_quote_with_41_lines',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,(SELECT jsonb_agg(jsonb_build_object(%L,%L||g,%L,1,%L,1)) FROM generate_series(1,41) g))','rq-g3-41-lines',jw_test.get('pA'),'t','exempt','name','L','quantity','unit_price'),'23514');
SELECT jw_test.expect_err('G3.21_quote_with_empty_name_line',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-name-1',jw_test.get('pA'),'t','exempt','[{"name":"  ","quantity":1,"unit_price":1}]'),'23514');
SELECT jw_test.expect_err('G3.22_quote_with_no_lines',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-none-1',jw_test.get('pA'),'t','exempt','[]'),'23514');
SELECT jw_test.expect_err('G3.23_quote_items_not_an_array',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-obj-1',jw_test.get('pA'),'t','exempt','{"name":"X"}'),'23514');
SELECT jw_test.expect_err('G3.24_quote_invalid_vat_mode',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g3-vat-1',jw_test.get('pA'),'t','reduced','[{"name":"X","quantity":1,"unit_price":1}]'),'23514');
SELECT jw_test.expect_err('G3.25_approve_draft_without_submit_is_illegal_transition',
  format('SELECT jw_dev.cinema_pg_quote_transition(%L,(SELECT id FROM jw_dev.cinema_pg_quotes WHERE title=%L),1,%L)','rq-g3-ill-1','Idem Q','approved'),'23514');

DO $t$ DECLARE n0 integer; n1 integer; r jsonb; BEGIN
  -- atomicity: line 2 invalid => nothing persists, request id and trade number stay usable
  SELECT count(*) INTO n0 FROM jw_dev.cinema_pg_quotes;
  BEGIN
    PERFORM jw_dev.cinema_pg_quote_create('rq-g3-atomic-1',jw_test.get('pA'),'Atomic','exempt',
       '[{"name":"ok","quantity":1,"unit_price":10},{"name":"bad","quantity":0,"unit_price":10}]'::jsonb);
  EXCEPTION WHEN OTHERS THEN NULL; END;
  SELECT count(*) INTO n1 FROM jw_dev.cinema_pg_quotes;
  PERFORM jw_test.ok('G3.26_failed_create_leaves_no_partial_rows', n0=n1);
  r := jw_dev.cinema_pg_quote_create('rq-g3-atomic-1',jw_test.get('pA'),'Atomic','exempt','[{"name":"ok","quantity":1,"unit_price":10}]'::jsonb);
  PERFORM jw_test.ok('G3.27_failed_request_id_is_reusable_after_rollback', (r->>'replayed')='false');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.26|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

-- delivery quantity / evidence rules (order 1 is fully delivered; order 2 reopened)
SELECT jw_test.expect_err('G3.28_delivery_on_fulfilled_order_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-del-ful',jw_test.get('o1'),
     format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('w1')),jw_test.ev('evidence-x1'),'x.pdf'),'23514');
SELECT jw_test.expect_err('G3.29_delivery_exceeding_remaining_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-del-over',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":11}]',jw_test.get('b2')),jw_test.ev('evidence-x2'),'x.pdf'),'23514');
SELECT jw_test.expect_err('G3.30_delivery_zero_quantity_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-del-zero',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":0}]',jw_test.get('b2')),jw_test.ev('evidence-x3'),'x.pdf'),'23514');
SELECT jw_test.expect_err('G3.31_delivery_fractional_quantity_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-del-frac',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":1.5}]',jw_test.get('b2')),jw_test.ev('evidence-x4'),'x.pdf'),'23514');
SELECT jw_test.expect_err('G3.32_delivery_without_evidence_hash_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,NULL,%L)','rq-g3-del-noev',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('b2')),'x.pdf'),'23514');
SELECT jw_test.expect_err('G3.33_delivery_with_malformed_evidence_hash_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-del-badev',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('b2')),'not-a-sha256','x.pdf'),'23514');
SELECT jw_test.expect_err('G3.34_delivery_duplicate_line_in_one_request_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-del-dup',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":1},{"order_item_id":"%s","quantity":1}]',jw_test.get('b2'),jw_test.get('b2')),
     jw_test.ev('evidence-x5'),'x.pdf'),'23514');
SELECT jw_test.expect_err('G3.35_delivery_item_from_another_order_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-del-xo',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('w1')),jw_test.ev('evidence-x6'),'x.pdf'),'P0002');

DO $t$ DECLARE r jsonb; BEGIN
  -- reservation: a pending delivery holds its quantity, so a second one cannot take it
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_delivery_record('rq-g3-res-1',jw_test.get('o2'),
        format('[{"order_item_id":"%s","quantity":8}]',jw_test.get('b2'))::jsonb,jw_test.ev('evidence-res1'),'res1.pdf');
  PERFORM jw_test.put('d5',jw_test.id_of(r));
  PERFORM jw_test.expect_err('G3.36_pending_delivery_reserves_quantity',
     format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-res-2',jw_test.get('o2'),
        format('[{"order_item_id":"%s","quantity":3}]',jw_test.get('b2')),jw_test.ev('evidence-res2'),'res2.pdf'),'23514');
  PERFORM jw_test.expect_err('G3.37_same_evidence_hash_cannot_back_two_deliveries',
     format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g3-res-3',jw_test.get('o2'),
        format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('b2')),jw_test.ev('evidence-res1'),'res3.pdf'),'23505');
  PERFORM jw_test.expect_err('G3.38_recorder_cannot_confirm_own_delivery',
     format('SELECT jw_dev.cinema_pg_delivery_confirm(%L,%L)','rq-g3-self-1',jw_test.get('d5')),'42501');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.36|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

SELECT jw_test.expect_err('G3.39_statement_from_unconfirmed_delivery_blocked',
  format('SELECT jw_dev.cinema_pg_statement_create(%L,%L)','rq-g3-st-unc',jw_test.get('d5')),'23514');
SELECT jw_test.expect_err('G3.40_second_active_statement_for_same_delivery_blocked',
  format('SELECT jw_dev.cinema_pg_statement_create(%L,%L)','rq-g3-st-dup',jw_test.get('d1')),'23505');
SELECT jw_test.expect_err('G3.41_second_active_invoice_for_same_statement_blocked',
  format('SELECT jw_dev.cinema_pg_invoice_create(%L,%L)','rq-g3-inv-dup',jw_test.get('s1')),'23505');
SELECT jw_test.expect_err('G3.42_invoice_from_voided_statement_blocked',
  format('SELECT jw_dev.cinema_pg_invoice_create(%L,%L)','rq-g3-inv-void',jw_test.get('s3')),'23514');
DO $t$ DECLARE r jsonb; BEGIN
  -- a draft invoice exists for statement 2; it must not skip the review step
  r := jw_dev.cinema_pg_invoice_create('rq-g3-inv-draft',jw_test.get('s2'));
  PERFORM jw_test.put('i3',jw_test.id_of(r));
  PERFORM jw_test.expect_err('G3.43_confirm_invoice_before_review_blocked',
     format('SELECT jw_dev.cinema_pg_invoice_confirm(%L,%L)','rq-g3-inv-skip',jw_test.get('i3')),'23514');
  PERFORM jw_test.expect_err('G3.43b_payment_on_unconfirmed_invoice_blocked',
     format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,1,current_date,%L)','rq-g3-pay-draft',jw_test.get('i3'),'DRAFT-REF'),'23514');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.43|FAIL|% %',SQLSTATE,SQLERRM; END $t$;
SELECT jw_test.expect_err('G3.44_order_from_unapproved_quote_blocked',
  format('SELECT jw_dev.cinema_pg_order_create(%L,(SELECT id FROM jw_dev.cinema_pg_quotes WHERE title=%L))','rq-g3-ord-unapp','Idem Q'),'23514');
SELECT jw_test.expect_err('G3.45_second_order_from_same_quote_blocked',
  format('SELECT jw_dev.cinema_pg_order_create(%L,%L)','rq-g3-ord-twice',jw_test.get('q1')),'23514');
SELECT jw_test.expect_err('G3.46_payment_on_voided_invoice_blocked',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,%s,current_date,%L)','rq-g3-pay-void',jw_test.get('i2'),10,'VOID-REF'),'23514');
SELECT jw_test.expect_err('G3.47_double_reversal_of_payment_blocked',
  format('SELECT jw_dev.cinema_pg_payment_reverse(%L,%L,%L)','rq-g3-rev-twice',jw_test.get('p2'),'again'),'23505');
SELECT jw_test.expect_err('G3.48_cancel_confirmed_delivery_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_cancel(%L,%L,%L)','rq-g3-cancel-conf',jw_test.get('d1'),'no'),'23514');
SELECT jw_test.expect_err('G3.49_void_statement_with_active_invoice_blocked',
  format('SELECT jw_dev.cinema_pg_statement_void(%L,%L,%L)','rq-g3-void-st',jw_test.get('s1'),'no'),'23514');

-- direct DML is not possible through the writer role
SELECT jw_test.expect_err('G3.50_writer_cannot_insert_payment_directly',
  format('INSERT INTO jw_dev.cinema_pg_payments(id,org_id,invoice_id,trade_no,amount_krw,paid_on,reference,recorded_by) VALUES (%L,%L,%L,%L,1,current_date,%L,%L)','x','ci-a',jw_test.get('i1'),jw_test.get('trade1'),'DIRECT','ci-ua'),'42501');
SELECT jw_test.expect_err('G3.51_writer_cannot_update_invoice_directly',
  format('UPDATE jw_dev.cinema_pg_invoices SET total_krw=1 WHERE id=%L',jw_test.get('i1')),'42501');
SELECT jw_test.expect_err('G3.52_writer_cannot_delete_audit',
  'DELETE FROM jw_dev.cinema_pg_audit','42501');
SELECT jw_test.expect_err('G3.53_writer_cannot_forge_confirmed_statement',
  format('INSERT INTO jw_dev.cinema_pg_statements(id,org_id,trade_no,delivery_id,order_id,vat_mode,subtotal_krw,vat_krw,total_krw,source_sha256,status,created_by,confirmed_by,confirmed_at) VALUES (%L,%L,%L,%L,%L,%L,1,0,1,%L,%L,%L,%L,now())','f','ci-a','T',jw_test.get('d1'),jw_test.get('o1'),'exempt',repeat('a',64),'confirmed','ci-ua','ci-ua'),'42501');

-- trigger-level immutability, tested with a SUPERUSER session (triggers still fire)
RESET ROLE;
SELECT jw_test.expect_err('G3.54_confirmed_statement_total_immutable_even_for_superuser',
  format('UPDATE jw_dev.cinema_pg_statements SET total_krw=1,subtotal_krw=1,vat_krw=0 WHERE id=%L',jw_test.get('s1')),'23514');
SELECT jw_test.expect_err('G3.55_audit_rows_cannot_be_updated',
  'UPDATE jw_dev.cinema_pg_audit SET action=''x''','23514');
SELECT jw_test.expect_err('G3.56_audit_rows_cannot_be_deleted',
  'DELETE FROM jw_dev.cinema_pg_audit','23514');
SELECT jw_test.expect_err('G3.57_payment_rows_are_append_only',
  format('UPDATE jw_dev.cinema_pg_payments SET amount_krw=1 WHERE id=%L',jw_test.get('p1')),'23514');
SELECT jw_test.expect_err('G3.58_confirmed_delivery_cannot_go_back_to_recorded',
  format('UPDATE jw_dev.cinema_pg_deliveries SET status=''recorded'' WHERE id=%L',jw_test.get('d1')),'23514');
SELECT jw_test.expect_err('G3.59_delivery_evidence_hash_immutable',
  format('UPDATE jw_dev.cinema_pg_deliveries SET evidence_sha256=%L WHERE id=%L',repeat('b',64),jw_test.get('d1')),'23514');
SELECT jw_test.expect_err('G3.60_approved_quote_content_frozen',
  format('UPDATE jw_dev.cinema_pg_quotes SET title=%L WHERE id=%L','tampered',jw_test.get('q1')),'23514');
SELECT jw_test.expect_err('G3.61_order_items_are_append_only',
  format('UPDATE jw_dev.cinema_pg_order_items SET quantity=1 WHERE id=%L',jw_test.get('w1')),'23514');
SELECT jw_test.expect_err('G3.62_quote_items_frozen_after_draft',
  format('DELETE FROM jw_dev.cinema_pg_quote_items WHERE quote_id=%L',jw_test.get('q1')),'23514');
SELECT jw_test.expect_err('G3.63_voided_statement_cannot_be_reactivated',
  format('UPDATE jw_dev.cinema_pg_statements SET status=''confirmed'',confirmed_by=%L,confirmed_at=now() WHERE id=%L','ci-ua',jw_test.get('s3')),'23514');
SELECT jw_test.expect_err('G3.64_bank_confirmed_cannot_be_true',
  format('INSERT INTO jw_dev.cinema_pg_payments(id,org_id,invoice_id,trade_no,amount_krw,paid_on,reference,recorded_by,bank_confirmed) VALUES (%L,%L,%L,%L,1,current_date,%L,%L,true)','y','ci-a',jw_test.get('i1'),jw_test.get('trade1'),'BANKTRUE','ci-ua'),'23514');
SELECT jw_test.expect_err('G3.65_cross_tenant_foreign_key_rejected_even_for_superuser',
  format('INSERT INTO jw_dev.cinema_pg_orders(id,org_id,trade_no,quote_id,partner_id,vat_mode,status,created_by) VALUES (%L,%L,%L,%L,%L,%L,%L,%L)','z','ci-b','TX',jw_test.get('q2'),jw_test.get('pA'),'exempt','open','ci-ub'),'23503');
SELECT jw_test.expect_err('G3.66_deleting_a_partner_is_not_possible',
  format('DELETE FROM jw_dev.cinema_pg_partners WHERE id=%L',jw_test.get('pA')),'23514');

-- Derived documents are re-derived from source at confirmation time. To prove that, the
-- stored totals are corrupted with triggers disabled (privileged tampering) and restored.
SELECT jw_test.as_('hash_a_admin1');
SELECT jw_dev.cinema_pg_invoice_review('rq-g3-tamper-rev',jw_test.get('i3'));
RESET ROLE;
SET session_replication_role = replica;
UPDATE jw_dev.cinema_pg_invoices SET subtotal_krw=subtotal_krw+1000, total_krw=total_krw+1000
 WHERE id=(SELECT jw_test.get('i3'));
SET session_replication_role = origin;
SET ROLE jw_cinema_writer;
SELECT jw_test.expect_err('G3.67_invoice_confirm_rejects_total_that_differs_from_statement',
  format('SELECT jw_dev.cinema_pg_invoice_confirm(%L,%L)','rq-g3-tamper-conf',jw_test.get('i3')),'23514');
DO $t$ DECLARE n integer; k text; BEGIN
  SELECT count(*), min(check_name) INTO n, k FROM jw_dev.cinema_pg_integrity_check();
  PERFORM jw_test.ok('G3.68_integrity_check_detects_tampered_invoice', n=1 AND k='invoice_statement_mismatch', 'rows='||n||' first='||coalesce(k,'-'));
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.68|FAIL|% %',SQLSTATE,SQLERRM; END $t$;
RESET ROLE;
SET session_replication_role = replica;
UPDATE jw_dev.cinema_pg_invoices SET subtotal_krw=subtotal_krw-1000, total_krw=total_krw-1000
 WHERE id=(SELECT jw_test.get('i3'));
SET session_replication_role = origin;
SET ROLE jw_cinema_writer;

-- Same idea for a draft statement whose stored totals were corrupted before confirmation.
DO $t$ DECLARE r jsonb; o text; it text; d text; s text; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_quote_create('rq-g3-tm-q',jw_test.get('pA'),'Tamper Q','exempt','[{"name":"T","quantity":3,"unit_price":700}]'::jsonb);
  PERFORM jw_dev.cinema_pg_quote_transition('rq-g3-tm-q2',jw_test.id_of(r),1,'submitted');
  PERFORM jw_dev.cinema_pg_quote_transition('rq-g3-tm-q3',jw_test.id_of(r),2,'approved');
  o := jw_test.id_of(jw_dev.cinema_pg_order_create('rq-g3-tm-o',jw_test.id_of(r)));
  it := jw_test.q(format('SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id=%L',o));
  PERFORM jw_test.as_('hash_a_member');
  d := jw_test.id_of(jw_dev.cinema_pg_delivery_record('rq-g3-tm-d',o,format('[{"order_item_id":"%s","quantity":3}]',it)::jsonb,
        jw_test.ev('evidence-tamper'),'tm.pdf'));
  PERFORM jw_test.as_('hash_a_admin1');
  PERFORM jw_test.view_ev(d);
  PERFORM jw_dev.cinema_pg_delivery_confirm('rq-g3-tm-dc',d);
  s := jw_test.id_of(jw_dev.cinema_pg_statement_create('rq-g3-tm-s',d));
  PERFORM jw_test.put('tmS',s);
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.69setup|FAIL|% %',SQLSTATE,SQLERRM; END $t$;
RESET ROLE;
SET session_replication_role = replica;
UPDATE jw_dev.cinema_pg_statements SET subtotal_krw=subtotal_krw+1, total_krw=total_krw+1
 WHERE id=(SELECT jw_test.get('tmS'));
SET session_replication_role = origin;
SET ROLE jw_cinema_writer;
SELECT jw_test.as_('hash_a_admin1');
SELECT jw_test.expect_err('G3.69_statement_confirm_rejects_totals_that_differ_from_delivery_source',
  format('SELECT jw_dev.cinema_pg_statement_confirm(%L,%L)','rq-g3-tm-sc',jw_test.get('tmS')),'23514');
RESET ROLE;
SET session_replication_role = replica;
UPDATE jw_dev.cinema_pg_statements SET subtotal_krw=subtotal_krw-1, total_krw=total_krw-1
 WHERE id=(SELECT jw_test.get('tmS'));
SET session_replication_role = origin;
SET ROLE jw_cinema_writer;
SELECT jw_test.as_('hash_a_admin1');
SELECT jw_test.ok('G3.70_statement_confirms_once_totals_are_restored',
  (jw_dev.cinema_pg_statement_confirm('rq-g3-tm-sc2',jw_test.get('tmS'))->'entity'->>'status')='confirmed');

-- =====================================================================
-- S3: delivery evidence is stored, re-hashed and opened on the SERVER
-- =====================================================================
DO $t$ DECLARE r jsonb; r2 jsonb; b bytea := convert_to('%PDF-1.4 s3-a','UTF8'); n integer; BEGIN
  PERFORM jw_test.as_('hash_a_member');
  r := jw_dev.cinema_pg_evidence_put('rq-s3-put-1','scan-a.pdf','application/pdf',b);
  PERFORM jw_test.put('s3e',jw_test.id_of(r));
  PERFORM jw_test.ok('G3.71_server_recomputes_evidence_sha256',
     (r->'entity'->>'content_sha256')=encode(sha256(b),'hex') AND (r->'entity'->>'size_bytes')=octet_length(b)::text AND (r->>'replayed')='false');
  r2 := jw_dev.cinema_pg_evidence_put('rq-s3-put-2','renamed.pdf','application/pdf',b);
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_evidence_files WHERE content_sha256=encode(sha256(b),'hex');
  PERFORM jw_test.ok('G3.72_identical_content_is_stored_once_per_tenant',
     jw_test.id_of(r2)=jw_test.id_of(r) AND (r2->>'duplicate_content')='true' AND n=1, 'rows='||n);
  r2 := jw_dev.cinema_pg_evidence_put('rq-s3-put-1','scan-a.pdf','application/pdf',b);
  PERFORM jw_test.ok('G3.73_same_request_replays_without_new_row', (r2->>'replayed')='true' AND jw_test.id_of(r2)=jw_test.id_of(r));
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.71|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

SELECT jw_test.expect_err('G3.74_request_id_reused_for_different_file',
  format('SELECT jw_dev.cinema_pg_evidence_put(%L,%L,%L,%L::bytea)','rq-s3-put-1','scan-a.pdf','application/pdf',
         encode(convert_to('%PDF-1.4 other','UTF8'),'hex')::text), '23505') ;
SELECT jw_test.expect_err('G3.75_empty_evidence_rejected',
  $$SELECT jw_dev.cinema_pg_evidence_put('rq-s3-empty','x.pdf','application/pdf','\x'::bytea)$$,'23514');
SELECT jw_test.expect_err('G3.76_oversize_evidence_rejected',
  $$SELECT jw_dev.cinema_pg_evidence_put('rq-s3-big','big.pdf','application/pdf',convert_to('%PDF-'||repeat('a',5242880),'UTF8'))$$,'23514');
SELECT jw_test.expect_err('G3.77_unlisted_content_type_rejected',
  $$SELECT jw_dev.cinema_pg_evidence_put('rq-s3-type','x.txt','text/plain',convert_to('%PDF-1.4 t','UTF8'))$$,'23514');
SELECT jw_test.expect_err('G3.78_content_not_matching_declared_type_rejected',
  $$SELECT jw_dev.cinema_pg_evidence_put('rq-s3-magic','x.png','image/png',convert_to('%PDF-1.4 m','UTF8'))$$,'23514');
SELECT jw_test.expect_err('G3.79_blank_file_name_rejected',
  $$SELECT jw_dev.cinema_pg_evidence_put('rq-s3-name','   ','application/pdf',convert_to('%PDF-1.4 n','UTF8'))$$,'23514');

-- An admin who downloaded proof BEFORE a delivery was recorded must open it again
-- after the delivery is created. A mere matching SHA-256 and historical audit is insufficient.
SELECT jw_test.as_('hash_a_admin2');
SELECT jw_test.ok('G3.90_admin_opened_evidence_before_delivery_recorded',
  (SELECT count(*) FROM jw_dev.cinema_pg_evidence_open('rq-s3-preopen',jw_test.get('s3e')))=1);
SELECT jw_test.as_('hash_a_member');

DO $t$ DECLARE r jsonb; o text; it text; d text; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_quote_create('rq-s3-q1',jw_test.get('pA'),'S3 evidence flow','exempt','[{"name":"S3 part","quantity":3,"unit_price":900}]'::jsonb);
  PERFORM jw_dev.cinema_pg_quote_transition('rq-s3-q2',jw_test.id_of(r),1,'submitted');
  PERFORM jw_dev.cinema_pg_quote_transition('rq-s3-q3',jw_test.id_of(r),2,'approved');
  o := jw_test.id_of(jw_dev.cinema_pg_order_create('rq-s3-ord1',jw_test.id_of(r)));
  it := jw_test.q(format('SELECT id FROM jw_dev.cinema_pg_order_items WHERE order_id=%L',o));
  PERFORM jw_test.put('s3o',o); PERFORM jw_test.put('s3i',it);
  PERFORM jw_test.as_('hash_a_member');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.80setup|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

SELECT jw_test.expect_err('G3.80_delivery_with_never_uploaded_evidence_hash_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-s3-d-none',jw_test.get('s3o'),
     format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('s3i')),repeat('c',64),'x.pdf'),'23514');
SELECT jw_test.as_('hash_a_admin2');
SELECT jw_test.put('s3adm_sha',jw_test.ev('s3-admin-file'));
SELECT jw_test.as_('hash_a_member');
SELECT jw_test.expect_err('G3.81_evidence_uploaded_by_someone_else_cannot_back_my_delivery',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-s3-d-other',jw_test.get('s3o'),
     format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('s3i')),jw_test.get('s3adm_sha'),'x.pdf'),'23514');

DO $t$ DECLARE r jsonb; v_sha text; BEGIN
  PERFORM jw_test.as_('hash_a_member');
  SELECT content_sha256 INTO v_sha FROM jw_dev.cinema_pg_evidence_files
    WHERE id=jw_test.get('s3e');
  r := jw_dev.cinema_pg_delivery_record('rq-s3-oldopen-d',jw_test.get('s3o'),
        format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('s3i'))::jsonb,
        v_sha,'scan-a.pdf');
  PERFORM jw_test.put('s3_oldopen_delivery',jw_test.id_of(r));
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.91setup|FAIL|% %',SQLSTATE,SQLERRM; END $t$;
SELECT jw_test.as_('hash_a_admin2');
SELECT jw_test.expect_err('G3.91_pre_delivery_file_open_does_not_authorize_delivery_confirmation',
    format('SELECT jw_dev.cinema_pg_delivery_confirm(%L,%L)',
         'rq-s3-oldopen-confirm',jw_test.get('s3_oldopen_delivery')),'23514');
SELECT jw_test.as_('hash_a_member');
SELECT jw_test.ok('G3.92_pre_delivery_open_test_can_cancel_pending_delivery',
   (jw_dev.cinema_pg_delivery_cancel('rq-s3-oldopen-cancel',
     jw_test.get('s3_oldopen_delivery'),'temporal audit negative control')->'entity'->>'status')='cancelled');

DO $t$ DECLARE r jsonb; v_sha text; BEGIN
  PERFORM jw_test.as_('hash_a_member');
  v_sha := jw_test.ev('s3-delivery-proof');
  r := jw_dev.cinema_pg_delivery_record('rq-s3-d-ok',jw_test.get('s3o'),
        format('[{"order_item_id":"%s","quantity":3}]',jw_test.get('s3i'))::jsonb,v_sha,'ignored-client-name.pdf');
  PERFORM jw_test.put('s3d',jw_test.id_of(r));
  PERFORM jw_test.ok('G3.82_delivery_stores_server_file_name_not_client_name',
     (r->'entity'->>'evidence_name')='s3-delivery-proof.pdf' AND (r->'entity'->>'evidence_sha256')=v_sha, r->'entity'->>'evidence_name');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.82|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

SELECT jw_test.as_('hash_a_admin2');
SELECT jw_test.expect_err('G3.83_confirm_without_opening_stored_evidence_blocked',
  format('SELECT jw_dev.cinema_pg_delivery_confirm(%L,%L)','rq-s3-c-1',jw_test.get('s3d')),'23514');
SELECT jw_test.as_('hash_a_admin1');
SELECT jw_test.view_ev(jw_test.get('s3d'));
SELECT jw_test.as_('hash_a_admin2');
SELECT jw_test.expect_err('G3.84_another_admins_open_does_not_count',
  format('SELECT jw_dev.cinema_pg_delivery_confirm(%L,%L)','rq-s3-c-2',jw_test.get('s3d')),'23514');

DO $t$ DECLARE r jsonb; rec record; n integer; BEGIN
  PERFORM jw_test.as_('hash_a_admin2');
  SELECT * INTO rec FROM jw_dev.cinema_pg_evidence_open('rq-s3-open-1',
        (SELECT e.id FROM jw_dev.cinema_pg_deliveries d JOIN jw_dev.cinema_pg_evidence_files e
           ON e.org_id=d.org_id AND e.content_sha256=d.evidence_sha256 WHERE d.id=jw_test.get('s3d')));
  PERFORM jw_test.ok('G3.85_open_returns_exact_stored_bytes_and_matching_hash',
     rec.o_content=convert_to('%PDF-1.4 s3-delivery-proof','UTF8') AND rec.o_sha256=encode(sha256(rec.o_content),'hex')
     AND rec.o_content_type='application/pdf');
  r := jw_dev.cinema_pg_delivery_confirm('rq-s3-c-3',jw_test.get('s3d'));
  PERFORM jw_test.ok('G3.86_confirm_succeeds_after_this_admin_opened_the_file', (r->'entity'->>'status')='confirmed' AND (r->'entity'->>'approved_by')='ci-ua2');
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_audit a WHERE a.action='evidence_open' AND a.actor_id='ci-ua2'
     AND a.entity_id=(SELECT e.id FROM jw_dev.cinema_pg_deliveries d JOIN jw_dev.cinema_pg_evidence_files e
           ON e.org_id=d.org_id AND e.content_sha256=d.evidence_sha256 WHERE d.id=jw_test.get('s3d'));
  PERFORM jw_test.ok('G3.87_every_open_is_audited_with_actor', n=1, 'rows='||n);
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G3.85|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

SELECT jw_test.as_('hash_a_member');
SELECT jw_test.expect_err('G3.88_member_cannot_open_evidence_uploaded_by_another_user',
  format('SELECT * FROM jw_dev.cinema_pg_evidence_open(%L,%L)','rq-s3-open-m',
         (SELECT id FROM jw_dev.cinema_pg_evidence_files WHERE content_sha256=jw_test.get('s3adm_sha'))),'42501');
SELECT jw_test.ok('G3.89_uploader_can_open_own_file',
  (SELECT count(*) FROM jw_dev.cinema_pg_evidence_open('rq-s3-open-own',jw_test.get('s3e')))=1);

-- security of the evidence store itself
SELECT jw_test.expect_err('G5.S1_writer_cannot_read_file_bytes_directly',
  $$SELECT content FROM jw_dev.cinema_pg_evidence_files$$,'42501');
SELECT jw_test.expect_err('G5.S2_writer_cannot_insert_evidence_directly',
  $$INSERT INTO jw_dev.cinema_pg_evidence_files(id,org_id,content_sha256,size_bytes,content_type,file_name,content,uploaded_by)
    VALUES ('x','ci-a',encode(sha256('\x255044462d'::bytea),'hex'),5,'application/pdf','x.pdf','\x255044462d'::bytea,'ci-ua')$$,'42501');
SELECT jw_test.ok('G5.S3_writer_sees_evidence_metadata_only_for_own_tenant',
  (SELECT count(*) FROM jw_dev.cinema_pg_evidence_files)>0
  AND (SELECT count(*) FROM jw_dev.cinema_pg_evidence_files WHERE org_id<>'ci-a')=0);
SELECT jw_test.as_('hash_b_admin');
SELECT jw_test.expect_err('G5.S4_other_tenant_cannot_open_evidence',
  format('SELECT * FROM jw_dev.cinema_pg_evidence_open(%L,%L)','rq-s3-open-b',jw_test.get('s3e')),'P0002');
SELECT jw_test.ok('G5.S5_other_tenant_cannot_see_evidence_metadata',
  (SELECT count(*) FROM jw_dev.cinema_pg_evidence_files WHERE id=jw_test.get('s3e'))=0);
RESET ROLE;
SELECT jw_test.expect_err('G5.S6_stored_evidence_bytes_cannot_be_replaced_even_by_superuser',
  format('UPDATE jw_dev.cinema_pg_evidence_files SET content=%L::bytea WHERE id=%L','\x255044462d00',jw_test.get('s3e')),'23514');
SELECT jw_test.expect_err('G5.S7_database_rejects_hash_that_does_not_match_the_bytes',
  $$INSERT INTO jw_dev.cinema_pg_evidence_files(id,org_id,content_sha256,size_bytes,content_type,file_name,content,uploaded_by)
    VALUES ('forged','ci-a',repeat('a',64),5,'application/pdf','x.pdf','\x255044462d'::bytea,'ci-ua')$$,'23514');
SELECT jw_test.expect_err('G5.S8_delivery_cannot_point_at_a_missing_evidence_file',
  format($f$INSERT INTO jw_dev.cinema_pg_deliveries(id,org_id,order_id,trade_no,seq,status,evidence_sha256,evidence_name,recorded_by)
    VALUES ('dx','ci-a',%L,'T000000-0000',99,'recorded',repeat('e',64),'x.pdf','ci-ua3')$f$,jw_test.get('s3o')),'23503');
SET ROLE jw_cinema_writer;

-- =====================================================================
-- G5: database-level security (tenant isolation, roles, privileges)
-- =====================================================================
SET ROLE jw_cinema_writer;

DO $t$ DECLARE r jsonb; BEGIN
  PERFORM jw_test.as_('hash_b_admin');
  r := jw_dev.cinema_pg_partner_upsert('rq-g5-b-partner',NULL,'Beta Corp','5556667778','','','',NULL);
  PERFORM jw_test.put('pB',jw_test.id_of(r));
  r := jw_dev.cinema_pg_quote_create('rq-g5-b-quote',jw_test.get('pB'),'B quote','taxable','[{"name":"B item","quantity":1,"unit_price":100}]'::jsonb);
  PERFORM jw_test.put('qB',jw_test.id_of(r));
  PERFORM jw_test.ok('G5.01_tenant_b_has_independent_trade_numbering', (r->'entity'->>'trade_no') ~ '-0001$', r->'entity'->>'trade_no');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G5.01|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

DO $t$ DECLARE na integer; nb integer; BEGIN
  PERFORM jw_test.as_('hash_b_admin');
  SELECT count(*) INTO nb FROM jw_dev.cinema_pg_partners;
  PERFORM jw_test.as_('hash_a_admin1');
  SELECT count(*) INTO na FROM jw_dev.cinema_pg_partners;
  PERFORM jw_test.ok('G5.02_each_tenant_sees_only_own_partners', nb=1 AND na=3, 'A='||na||' B='||nb);
  PERFORM jw_test.as_('hash_c_admin');
  SELECT count(*) INTO nb FROM jw_dev.cinema_pg_quotes;
  PERFORM jw_test.ok('G5.03_tenant_c_sees_no_foreign_quotes', nb=0);
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G5.02|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

SELECT jw_test.as_('hash_b_admin');
SELECT jw_test.expect_err('G5.04_b_cannot_update_a_quote',
  format('SELECT jw_dev.cinema_pg_quote_update(%L,%L,1,%L,%L::jsonb)','rq-g5-x-1',jw_test.get('q2'),'hijack','[{"name":"x","quantity":1,"unit_price":1}]'),'P0002');
SELECT jw_test.expect_err('G5.05_b_cannot_transition_a_quote',
  format('SELECT jw_dev.cinema_pg_quote_transition(%L,%L,1,%L)','rq-g5-x-2',jw_test.get('q2'),'cancelled'),'P0002');
SELECT jw_test.expect_err('G5.06_b_cannot_create_order_from_a_quote',
  format('SELECT jw_dev.cinema_pg_order_create(%L,%L)','rq-g5-x-3',jw_test.get('q1')),'P0002');
SELECT jw_test.expect_err('G5.07_b_cannot_record_delivery_on_a_order',
  format('SELECT jw_dev.cinema_pg_delivery_record(%L,%L,%L::jsonb,%L,%L)','rq-g5-x-4',jw_test.get('o2'),
     format('[{"order_item_id":"%s","quantity":1}]',jw_test.get('b2')),jw_test.ev('evidence-b1'),'b.pdf'),'P0002');
SELECT jw_test.expect_err('G5.08_b_cannot_confirm_a_delivery',
  format('SELECT jw_dev.cinema_pg_delivery_confirm(%L,%L)','rq-g5-x-5',jw_test.get('d5')),'P0002');
SELECT jw_test.expect_err('G5.09_b_cannot_confirm_a_statement',
  format('SELECT jw_dev.cinema_pg_statement_confirm(%L,%L)','rq-g5-x-6',jw_test.get('s1')),'P0002');
SELECT jw_test.expect_err('G5.10_b_cannot_confirm_an_invoice',
  format('SELECT jw_dev.cinema_pg_invoice_confirm(%L,%L)','rq-g5-x-7',jw_test.get('i1')),'P0002');
SELECT jw_test.expect_err('G5.11_b_cannot_pay_a_invoice',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,1,current_date,%L)','rq-g5-x-8',jw_test.get('i1'),'XTENANT'),'P0002');
SELECT jw_test.expect_err('G5.12_b_cannot_reverse_a_payment',
  format('SELECT jw_dev.cinema_pg_payment_reverse(%L,%L,%L)','rq-g5-x-9',jw_test.get('p1'),'hijack'),'P0002');
-- Trade numbers are numbered per tenant, so B's first trade shares A's first number.
-- B must therefore see ONLY B's documents under that number, and nothing under A's second number.
SELECT jw_test.expect_err('G5.13_b_cannot_trace_a_trade_number_it_does_not_own',
  format('SELECT jw_dev.cinema_pg_trade_trace(%L)',jw_test.get('trade2')),'P0002');
DO $t$ DECLARE v jsonb; BEGIN
  v := jw_dev.cinema_pg_trade_trace(jw_test.get('trade1'));
  PERFORM jw_test.ok('G5.13b_same_trade_number_shows_only_own_documents',
     jsonb_array_length(v->'quotes')=1 AND (v->'quotes'->0->>'title')='B quote'
     AND jsonb_array_length(v->'orders')=0 AND jsonb_array_length(v->'deliveries')=0
     AND jsonb_array_length(v->'invoices')=0 AND jsonb_array_length(v->'payments')=0);
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G5.13b|FAIL|% %',SQLSTATE,SQLERRM; END $t$;
SELECT jw_test.expect_err('G5.14_b_cannot_quote_with_a_partner',
  format('SELECT jw_dev.cinema_pg_quote_create(%L,%L,%L,%L,%L::jsonb)','rq-g5-x-10',jw_test.get('pA'),'t','exempt','[{"name":"x","quantity":1,"unit_price":1}]'),'P0002');
SELECT jw_test.expect_err('G5.15_b_cannot_update_a_partner',
  format('SELECT jw_dev.cinema_pg_partner_upsert(%L,%L,%L,%L,%L,%L,%L,2)','rq-g5-x-11',jw_test.get('pA'),'hijack','','','','' ),'P0002');
SELECT jw_test.expect_err('G5.16_b_cannot_cancel_a_delivery',
  format('SELECT jw_dev.cinema_pg_delivery_cancel(%L,%L,%L)','rq-g5-x-12',jw_test.get('d5'),'hijack'),'P0002');

DO $t$ DECLARE r jsonb; BEGIN
  -- request ids are namespaced per tenant: B may reuse a request id that A used
  r := jw_dev.cinema_pg_partner_upsert('rq-g2-partner-01',NULL,'Beta Two','4443332221','','','',NULL);
  PERFORM jw_test.ok('G5.17_request_ids_are_tenant_scoped', (r->>'replayed')='false');
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G5.17|FAIL|% %',SQLSTATE,SQLERRM; END $t$;

-- role gating: a member cannot perform administrator actions
SELECT jw_test.as_('hash_a_member');
SELECT jw_test.expect_err('G5.18_member_cannot_approve_quote',
  format('SELECT jw_dev.cinema_pg_quote_transition(%L,(SELECT id FROM jw_dev.cinema_pg_quotes WHERE title=%L),1,%L)','rq-g5-m-1','Atomic','approved'),'42501');
SELECT jw_test.expect_err('G5.19_member_cannot_create_order',
  format('SELECT jw_dev.cinema_pg_order_create(%L,%L)','rq-g5-m-2',jw_test.get('q1')),'42501');
SELECT jw_test.expect_err('G5.20_member_cannot_confirm_delivery',
  format('SELECT jw_dev.cinema_pg_delivery_confirm(%L,%L)','rq-g5-m-3',jw_test.get('d5')),'42501');
SELECT jw_test.expect_err('G5.21_member_cannot_confirm_statement',
  format('SELECT jw_dev.cinema_pg_statement_confirm(%L,%L)','rq-g5-m-4',jw_test.get('s1')),'42501');
SELECT jw_test.expect_err('G5.22_member_cannot_review_invoice',
  format('SELECT jw_dev.cinema_pg_invoice_review(%L,%L)','rq-g5-m-5',jw_test.get('i1')),'42501');
SELECT jw_test.expect_err('G5.23_member_cannot_record_payment',
  format('SELECT jw_dev.cinema_pg_payment_record(%L,%L,1,current_date,%L)','rq-g5-m-6',jw_test.get('i1'),'MEMBER'),'42501');
SELECT jw_test.expect_err('G5.24_member_cannot_reverse_payment',
  format('SELECT jw_dev.cinema_pg_payment_reverse(%L,%L,%L)','rq-g5-m-7',jw_test.get('p1'),'x'),'42501');
SELECT jw_test.expect_err('G5.25_member_cannot_void_invoice',
  format('SELECT jw_dev.cinema_pg_invoice_void(%L,%L,%L)','rq-g5-m-8',jw_test.get('i1'),'x'),'42501');
SELECT jw_test.expect_err('G5.26_member_cannot_reverse_delivery',
  format('SELECT jw_dev.cinema_pg_delivery_reverse(%L,%L,%L)','rq-g5-m-9',jw_test.get('d1'),'x'),'42501');

-- identity gating
SELECT jw_test.as_('');
SELECT jw_test.expect_err('G5.27_empty_session_rejected',
  format('SELECT jw_dev.cinema_pg_partner_upsert(%L,NULL,%L,%L,%L,%L,%L,NULL)','rq-g5-ns-1','n','','','',''),'42501');
SELECT jw_test.as_('totally-unknown-session-hash');
SELECT jw_test.expect_err('G5.28_unknown_session_rejected',
  format('SELECT jw_dev.cinema_pg_trade_trace(%L)',jw_test.get('trade1')),'42501');
SELECT jw_test.as_('hash_a_expired');
SELECT jw_test.expect_err('G5.29_expired_session_rejected',
  format('SELECT jw_dev.cinema_pg_partner_upsert(%L,NULL,%L,%L,%L,%L,%L,NULL)','rq-g5-ex-1','n','','','',''),'42501');
SELECT jw_test.expect_err('G5.30_expired_session_cannot_read_integrity',
  'SELECT * FROM jw_dev.cinema_pg_integrity_check()','42501');
SELECT jw_test.as_('');
SELECT jw_test.ok('G5.31_no_session_sees_zero_rows_in_tables',
  (SELECT count(*) FROM jw_dev.cinema_pg_quotes)=0 AND (SELECT count(*) FROM jw_dev.cinema_pg_payments)=0
  AND (SELECT count(*) FROM jw_dev.cinema_pg_audit)=0);

-- privilege boundaries
SELECT jw_test.as_('hash_a_admin1');
SELECT jw_test.expect_err('G5.32_writer_cannot_read_idempotency_table',
  'SELECT count(*) FROM jw_dev.cinema_pg_requests','42501');
SELECT jw_test.expect_err('G5.33_writer_cannot_read_trade_counters',
  'SELECT count(*) FROM jw_dev.cinema_pg_trade_counters','42501');
SELECT jw_test.expect_err('G5.34_writer_cannot_read_transition_table',
  'SELECT count(*) FROM jw_dev.cinema_pg_transitions','42501');
SELECT jw_test.expect_err('G5.35_writer_cannot_call_internal_audit_helper',
  format('SELECT jw_dev.cinema_pg_audit_add(%L,%L,%L,%L,%L,%L,%L::jsonb,%L)','ci-a','ci-ua','x','x','x','forged','{}','rq-forged-audit'),'42501');
SELECT jw_test.expect_err('G5.36_writer_cannot_call_internal_begin_helper',
  format('SELECT * FROM jw_dev.cinema_pg_begin(%L,%L,%L::jsonb)','rq-forged-begin','x','{}'),'42501');
-- (Escalation to jw_cinema_owner cannot be tested here: SET ROLE is authorised against the
--  SESSION user, which is a superuser in this script. It is tested with a real unprivileged
--  login in ci_cinema_pg_sql_gate.py as G5.L5.)

RESET ROLE;
SET ROLE anon;
SELECT jw_test.expect_err('G5.38_anon_cannot_execute_api',
  format('SELECT jw_dev.cinema_pg_partner_upsert(%L,NULL,%L,%L,%L,%L,%L,NULL)','rq-g5-anon-1','n','','','',''),'42501');
SELECT jw_test.expect_err('G5.39_anon_cannot_read_tables',
  'SELECT count(*) FROM jw_dev.cinema_pg_quotes','42501');
RESET ROLE;
SET ROLE jw_app_dev;
SELECT jw_test.expect_err('G5.40_generic_trade_role_cannot_execute_engine',
  format('SELECT jw_dev.cinema_pg_trade_trace(%L)','x'),'42501');
SELECT jw_test.expect_err('G5.41_generic_trade_role_cannot_read_engine_tables',
  'SELECT count(*) FROM jw_dev.cinema_pg_payments','42501');
RESET ROLE;

-- data-handling checks as the writer
SET ROLE jw_cinema_writer;
DO $t$ DECLARE r jsonb; n integer; BEGIN
  PERFORM jw_test.as_('hash_a_admin1');
  r := jw_dev.cinema_pg_partner_upsert('rq-g5-inject-1',NULL,'x''); DROP TABLE jw_dev.cinema_pg_quotes;--','','','','',NULL);
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_quotes;
  PERFORM jw_test.ok('G5.42_sql_metacharacters_stored_as_data', (r->'entity'->>'name') LIKE 'x''); DROP TABLE%' AND n>0);
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_integrity_check();
  PERFORM jw_test.ok('G5.43_integrity_clean_for_tenant_a', n=0, 'violations='||n);
  PERFORM jw_test.as_('hash_b_admin');
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_integrity_check();
  PERFORM jw_test.ok('G5.44_integrity_clean_for_tenant_b', n=0, 'violations='||n);
  SELECT count(*) INTO n FROM jw_dev.cinema_pg_audit;
  -- tenant B performed exactly four audited actions (2 partners, 1 quote, 1 evidence upload)
  PERFORM jw_test.ok('G5.45_tenant_b_sees_only_own_audit_rows', n=4, 'rows='||n);
EXCEPTION WHEN OTHERS THEN RAISE NOTICE 'TEST|G5.42|FAIL|% %',SQLSTATE,SQLERRM; END $t$;
RESET ROLE;

-- every state-changing function leaves an audit row (superuser read, all tenants)
SELECT jw_test.ok('G5.46_audit_covers_all_entity_types',
  (SELECT count(DISTINCT entity_type) FROM jw_dev.cinema_pg_audit)=8, 'entity types with audit rows: '||(SELECT string_agg(DISTINCT entity_type,',') FROM jw_dev.cinema_pg_audit));
SELECT jw_test.ok('G5.47_no_audit_row_lacks_actor_or_request',
  (SELECT count(*) FROM jw_dev.cinema_pg_audit WHERE actor_id='' OR request_id='')=0);
SELECT jw_test.ok('G5.48_all_tenant_tables_force_rls',
  (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='jw_dev' AND c.relname LIKE 'cinema\_pg\_%' AND c.relkind='r'
      AND c.relname NOT IN ('cinema_pg_transitions') AND NOT (c.relrowsecurity AND c.relforcerowsecurity))=0);
SELECT jw_test.ok('G5.49_no_engine_table_is_readable_by_public',
  (SELECT count(*) FROM information_schema.role_table_grants WHERE table_schema='jw_dev'
    AND table_name LIKE 'cinema\_pg\_%' AND grantee='PUBLIC')=0);
SELECT jw_test.ok('G5.50_owner_role_cannot_log_in_or_bypass_rls',
  (SELECT NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper FROM pg_roles WHERE rolname='jw_cinema_owner')
  AND (SELECT NOT rolcanlogin AND NOT rolbypassrls AND NOT rolsuper FROM pg_roles WHERE rolname='jw_cinema_writer'));
