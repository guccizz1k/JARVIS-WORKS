-- Executes only on a fresh disposable CI S4 database after atomic gate install.
-- No production users, personal data, secrets or remote DB connections.
CREATE SCHEMA jw_s4;
CREATE FUNCTION jw_s4.ok(p_name text,p_cond boolean) RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  RAISE NOTICE 'TEST|%|%|',p_name,CASE WHEN p_cond IS TRUE THEN 'PASS' ELSE 'FAIL' END;
END $$;
CREATE FUNCTION jw_s4.reject(p_name text,p_sql text,p_state text DEFAULT '23514')
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  EXECUTE p_sql;
  RAISE NOTICE 'TEST|%|FAIL|insert unexpectedly succeeded',p_name;
EXCEPTION WHEN OTHERS THEN
  RAISE NOTICE 'TEST|%|%|state=%',p_name,CASE WHEN SQLSTATE=p_state THEN 'PASS' ELSE 'FAIL' END,SQLSTATE;
END $$;

SELECT jw_s4.ok('G5.S4A.01_five_triggers',
 (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
  JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='jw_dev'
  AND t.tgname LIKE 'cinema_pg_s4_claim_%' AND NOT t.tgisinternal)=5);
SELECT jw_s4.ok('G5.S4A.02_claims_force_rls',
 (SELECT relrowsecurity AND relforcerowsecurity FROM pg_class
  WHERE oid='jw_dev.cinema_pg_ledger_claims'::regclass));
SELECT jw_s4.ok('G5.S4A.03_writer_cannot_access_claims',
 NOT has_table_privilege('jw_cinema_writer','jw_dev.cinema_pg_ledger_claims','SELECT')
 AND NOT has_table_privilege('jw_cinema_writer','jw_dev.cinema_pg_ledger_claims','INSERT')
 AND NOT has_table_privilege('jw_app_dev','jw_dev.cinema_pg_ledger_claims','SELECT'));
SELECT jw_s4.ok('G5.S4A.04_no_admin_owner_membership',
 (SELECT count(*) FROM pg_catalog.pg_auth_members m
   JOIN pg_catalog.pg_roles granted ON granted.oid=m.roleid
   JOIN pg_catalog.pg_roles member ON member.oid=m.member
   WHERE granted.rolname='jw_cinema_owner' AND member.rolname=session_user)=0);
SELECT jw_s4.ok('G5.S4A.05_claims_initially_empty',
 (SELECT count(*) FROM jw_dev.cinema_pg_ledger_claims)=0);

INSERT INTO jw_dev.organizations(id,name,created_at) VALUES
 ('ci-d','Synthetic D',now()::text),('ci-e','Synthetic E',now()::text);
INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,created_by) VALUES
 ('s4-pa','ci-a','Synthetic A','ci-ua'),
 ('s4-pb','ci-b','Synthetic B','ci-ub'),
 ('s4-pc','ci-c','Synthetic C','ci-uc'),
 ('s4-pd','ci-d','Synthetic D','ci-uc'),
 ('s4-pe','ci-e','Synthetic E','ci-uc');

-- Legacy first, CINEMA second -> fail closed for same tenant.
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,
 status,vat_mode,created_at,updated_at) VALUES
 ('s4-lqa','ci-a','ci-customer-a','Synthetic A','Q-S4-A','Synthetic A',
  'draft','exempt',now()::text,now()::text);
SELECT jw_s4.ok('G5.S4A.06_legacy_claim_a',
 (SELECT ledger FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-a')='legacy');
SELECT jw_s4.reject('G5.S4A.07_reject_cinema_on_legacy_a',
 $$INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by)
   VALUES('s4-qa','ci-a','TS4-A','s4-pa','Synthetic A','draft','exempt','ci-ua')$$);

-- CINEMA first, legacy second -> fail closed for same tenant.
INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by)
VALUES('s4-qb','ci-b','TS4-B','s4-pb','Synthetic B','draft','exempt','ci-ub');
SELECT jw_s4.ok('G5.S4A.08_cinema_claim_b',
 (SELECT ledger FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-b')='cinema');
SELECT jw_s4.reject('G5.S4A.09_reject_legacy_on_cinema_b',
 $$INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,status,vat_mode,created_at,updated_at)
   VALUES('s4-lqb','ci-b','ci-customer-b','Synthetic B','Q-S4-B','Synthetic B','draft','exempt',now()::text,now()::text)$$);

-- Non-quote writes from the historical ledger must also claim tenant.
INSERT INTO jw_dev.orders(id,org_id) VALUES('s4-oc','ci-c');
SELECT jw_s4.ok('G5.S4A.10_legacy_order_claim_c',
 (SELECT ledger FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-c')='legacy');
SELECT jw_s4.reject('G5.S4A.11_order_blocks_cinema',
 $$INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by)
   VALUES('s4-qc','ci-c','TS4-C','s4-pc','Synthetic C','draft','exempt','ci-uc')$$);
INSERT INTO jw_dev.invoices(id,org_id) VALUES('s4-id','ci-d');
SELECT jw_s4.ok('G5.S4A.12_legacy_invoice_claim_d',
 (SELECT ledger FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-d')='legacy');
SELECT jw_s4.reject('G5.S4A.13_invoice_blocks_cinema',
 $$INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by)
   VALUES('s4-qd','ci-d','TS4-D','s4-pd','Synthetic D','draft','exempt','ci-uc')$$);
INSERT INTO jw_dev.payments(id,org_id) VALUES('s4-pe','ci-e');
SELECT jw_s4.ok('G5.S4A.14_legacy_payment_claim_e',
 (SELECT ledger FROM jw_dev.cinema_pg_ledger_claims WHERE org_id='ci-e')='legacy');
SELECT jw_s4.reject('G5.S4A.15_payment_blocks_cinema',
 $$INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by)
   VALUES('s4-qe','ci-e','TS4-E','s4-pe','Synthetic E','draft','exempt','ci-uc')$$);

-- Same-ledger retry and additional rows remain possible, other orgs isolated.
INSERT INTO jw_dev.quotes(id,org_id,customer_id,customer_name_snapshot,doc_no,title,
 status,vat_mode,created_at,updated_at) VALUES
 ('s4-lqa2','ci-a','ci-customer-a','Synthetic A','Q-S4-A2','Synthetic A2',
  'draft','exempt',now()::text,now()::text);
SELECT jw_s4.ok('G5.S4A.16_repeat_legacy_same_tenant_allowed',
 (SELECT count(*) FROM jw_dev.quotes WHERE org_id='ci-a' AND id LIKE 's4-%')=2);
INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by)
VALUES('s4-qb2','ci-b','TS4-B2','s4-pb','Synthetic B2','draft','exempt','ci-ub');
SELECT jw_s4.ok('G5.S4A.17_repeat_cinema_same_tenant_allowed',
 (SELECT count(*) FROM jw_dev.cinema_pg_quotes WHERE org_id='ci-b' AND id LIKE 's4-%')=2);
SELECT jw_s4.ok('G5.S4A.18_distinct_tenant_claims',
 (SELECT count(*) FROM jw_dev.cinema_pg_ledger_claims)=5
 AND (SELECT count(DISTINCT org_id) FROM jw_dev.cinema_pg_ledger_claims)=5);
SELECT jw_s4.ok('G5.S4A.19_no_mixed_claims',
 NOT EXISTS(SELECT 1 FROM jw_dev.cinema_pg_ledger_claims
 WHERE ledger NOT IN ('legacy','cinema')));
SELECT jw_s4.ok('G5.S4A.20_only_five_tables_triggers',
 (SELECT count(*) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
 WHERE t.tgname LIKE 'cinema_pg_s4_claim_%' AND NOT t.tgisinternal)=5);
