-- Synthetic temporary tables only; exact source-pinned aggregates, not a full RPC test.
BEGIN;
SET LOCAL statement_timeout='20s';
CREATE TEMP TABLE qa_recon_cases(org_id text, bill_id text, kind text, scenario int, expected numeric[], PRIMARY KEY(org_id,bill_id)) ON COMMIT DROP;
INSERT INTO qa_recon_cases
SELECT org,kind||'-'||scenario,kind,scenario,CASE scenario
 WHEN 0 THEN ARRAY[0,0,0,0,0]::numeric[]
 WHEN 1 THEN ARRAY[210,0,21,0,0]::numeric[]
 WHEN 2 THEN ARRAY[210,0,21,231,0]::numeric[]
 WHEN 3 THEN ARRAY[0,0,0,0,0]::numeric[]
 WHEN 4 THEN ARRAY[105,0,11,116,0]::numeric[]
 WHEN 5 THEN ARRAY[0,0,0,0,0]::numeric[]
 WHEN 6 THEN ARRAY[-5,105,10,-21,5]::numeric[]
 ELSE ARRAY[18446744073709551614,18446744073709551614,18446744073709551614,-18446744073709551614,18446744073709551614]::numeric[] END
FROM unnest(ARRAY['tenant-a','tenant-b']) org CROSS JOIN unnest(ARRAY['purchase','sale']) kind CROSS JOIN generate_series(0,7) scenario;
UPDATE qa_recon_cases SET expected=ARRAY[expected[1],expected[2]+17,expected[3],expected[4],expected[5]] WHERE org_id='tenant-b' AND scenario BETWEEN 1 AND 6;
CREATE TEMP TABLE qa_recon_journals(org_id text,event_id text,bill_id text,PRIMARY KEY(org_id,event_id)) ON COMMIT DROP;
CREATE TEMP TABLE qa_recon_lines(org_id text,event_id text,account text,debit bigint NOT NULL,credit bigint NOT NULL) ON COMMIT DROP;
INSERT INTO qa_recon_journals SELECT org_id,bill_id,bill_id FROM qa_recon_cases WHERE scenario<>0;
INSERT INTO qa_recon_lines
SELECT r.org_id,r.bill_id,x.account,greatest(x.delta/z.parts,0)::bigint,greatest(-x.delta/z.parts,0)::bigint
FROM qa_recon_cases r CROSS JOIN LATERAL (VALUES
 ('PURCHASE_CLEARING',r.expected[1]),('SALES',-r.expected[2]),
 (CASE WHEN r.kind='sale' THEN 'VAT_OUTPUT' ELSE 'VAT_INPUT' END,CASE WHEN r.kind='sale' THEN -r.expected[3] ELSE r.expected[3] END),
 ('CASH_CLEARING',CASE WHEN r.kind='sale' THEN r.expected[4] ELSE -r.expected[4] END),
 ('PURCHASE_COST_VARIANCE',-r.expected[5]),
 (CASE WHEN r.kind='sale' THEN 'VAT_INPUT' ELSE 'VAT_OUTPUT' END,999::numeric),('OTHER',777::numeric)
) x(account,delta) CROSS JOIN LATERAL (SELECT CASE WHEN abs(x.delta)>9223372036854775807 THEN 2 ELSE 1 END AS parts) z
CROSS JOIN LATERAL generate_series(1,z.parts) copies WHERE r.scenario<>0;
INSERT INTO qa_recon_lines SELECT org_id,bill_id,'CASH_CLEARING',13,0 FROM qa_recon_cases WHERE scenario IN (3,5) UNION ALL SELECT org_id,bill_id,'CASH_CLEARING',0,13 FROM qa_recon_cases WHERE scenario IN (3,5);
DO $test$
DECLARE r record; clearing numeric; sales numeric; vat_balance numeric; cash_balance numeric; variance_balance numeric; baseline numeric[]; actual numeric[]; n int:=0;
BEGIN
 FOR r IN SELECT * FROM qa_recon_cases ORDER BY org_id,bill_id LOOP
  SELECT coalesce(sum(l.debit::numeric-l.credit) FILTER(WHERE l.account='PURCHASE_CLEARING'),0),
 coalesce(sum(l.credit::numeric-l.debit) FILTER(WHERE l.account='SALES'),0)
 INTO clearing,sales FROM pg_temp.qa_recon_lines l JOIN pg_temp.qa_recon_journals h USING(org_id,event_id)
 WHERE h.org_id=r.org_id AND h.bill_id=r.bill_id;

  SELECT coalesce(sum(CASE WHEN r.kind='sale' AND l.account='VAT_OUTPUT' THEN l.credit-l.debit WHEN r.kind='purchase' AND l.account='VAT_INPUT' THEN l.debit-l.credit ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='CASH_CLEARING' THEN CASE WHEN r.kind='sale' THEN l.debit-l.credit ELSE l.credit-l.debit END ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='PURCHASE_COST_VARIANCE' THEN l.credit-l.debit ELSE 0 END),0)
 INTO vat_balance,cash_balance,variance_balance FROM pg_temp.qa_recon_lines l JOIN pg_temp.qa_recon_journals h USING(org_id,event_id)
 WHERE h.org_id=r.org_id AND h.bill_id=r.bill_id;

 baseline:=ARRAY[clearing,sales,vat_balance,cash_balance,variance_balance];
  SELECT coalesce(sum(l.debit::numeric-l.credit) FILTER(WHERE l.account='PURCHASE_CLEARING'),0),
 coalesce(sum(l.credit::numeric-l.debit) FILTER(WHERE l.account='SALES'),0),
coalesce(sum(CASE WHEN r.kind='sale' AND l.account='VAT_OUTPUT' THEN l.credit-l.debit WHEN r.kind='purchase' AND l.account='VAT_INPUT' THEN l.debit-l.credit ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='CASH_CLEARING' THEN CASE WHEN r.kind='sale' THEN l.debit-l.credit ELSE l.credit-l.debit END ELSE 0 END),0),
 coalesce(sum(CASE WHEN l.account='PURCHASE_COST_VARIANCE' THEN l.credit-l.debit ELSE 0 END),0)
 INTO clearing,sales,vat_balance,cash_balance,variance_balance FROM pg_temp.qa_recon_lines l JOIN pg_temp.qa_recon_journals h USING(org_id,event_id)
 WHERE h.org_id=r.org_id AND h.bill_id=r.bill_id;

 actual:=ARRAY[clearing,sales,vat_balance,cash_balance,variance_balance];
 IF baseline IS DISTINCT FROM r.expected OR actual IS DISTINCT FROM r.expected THEN RAISE EXCEPTION 'AGGREGATE_REGRESSION scenario=% kind=%',r.scenario,r.kind; END IF;
 n:=n+1;
 END LOOP;
 IF n<>32 THEN RAISE EXCEPTION 'CASE_COUNT'; END IF;
END $test$;
SELECT 'RECONCILE_AGGREGATE_EDGE_PASS' AS verdict,count(*) AS cases,count(DISTINCT org_id) AS tenants,count(DISTINCT kind) AS kinds,count(DISTINCT scenario) AS scenarios FROM qa_recon_cases;
ROLLBACK;