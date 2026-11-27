BEGIN;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='2s';
SET LOCAL search_path=pg_catalog,pg_temp;
DO $guard$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres'
 OR current_setting('server_version_num')::int/10000<>17
 OR to_regclass('naruv_qa_probe.fixture') IS NULL
 OR to_regnamespace('jw_dev') IS NOT NULL
 OR to_regnamespace('naruv_hosted_tx_review') IS NOT NULL
 OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname LIKE 'naruv_htx_%')
 THEN RAISE EXCEPTION 'HOSTED_REVIEW_SCOPE'; END IF;
 IF (SELECT count(*) FROM naruv_qa_probe.fixture)<>2 THEN RAISE EXCEPTION 'HOSTED_MARKER'; END IF;
END $guard$;
CREATE ROLE naruv_htx_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_htx_a NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_htx_b NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT naruv_htx_owner,naruv_htx_a,naruv_htx_b TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE SCHEMA naruv_hosted_tx_review AUTHORIZATION naruv_htx_owner;
SET LOCAL ROLE naruv_htx_owner;
REVOKE ALL ON SCHEMA naruv_hosted_tx_review FROM PUBLIC,anon,authenticated,service_role;
CREATE TABLE naruv_hosted_tx_review.orders(
 tenant text NOT NULL CHECK(tenant IN ('ci-a','ci-b')),
 request_id text NOT NULL,
 amount bigint NOT NULL CHECK(amount>0 AND amount<=1000000000),
 PRIMARY KEY(tenant,request_id),
 UNIQUE(tenant,request_id,amount));
CREATE TABLE naruv_hosted_tx_review.entries(
 tenant text NOT NULL,
 request_id text NOT NULL,
 amount bigint NOT NULL CHECK(amount>0),
 PRIMARY KEY(tenant,request_id),
 UNIQUE(tenant,request_id,amount),
 FOREIGN KEY(tenant,request_id,amount) REFERENCES naruv_hosted_tx_review.orders(tenant,request_id,amount));
ALTER TABLE naruv_hosted_tx_review.orders ADD CONSTRAINT order_requires_entry
 FOREIGN KEY(tenant,request_id,amount) REFERENCES naruv_hosted_tx_review.entries(tenant,request_id,amount)
 DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE naruv_hosted_tx_review.orders ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_tx_review.orders FORCE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_tx_review.entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_tx_review.entries FORCE ROW LEVEL SECURITY;
CREATE POLICY a_orders ON naruv_hosted_tx_review.orders TO naruv_htx_a USING(tenant='ci-a') WITH CHECK(tenant='ci-a');
CREATE POLICY b_orders ON naruv_hosted_tx_review.orders TO naruv_htx_b USING(tenant='ci-b') WITH CHECK(tenant='ci-b');
CREATE POLICY a_entries ON naruv_hosted_tx_review.entries TO naruv_htx_a USING(tenant='ci-a') WITH CHECK(tenant='ci-a');
CREATE POLICY b_entries ON naruv_hosted_tx_review.entries TO naruv_htx_b USING(tenant='ci-b') WITH CHECK(tenant='ci-b');
REVOKE ALL ON ALL TABLES IN SCHEMA naruv_hosted_tx_review FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON SCHEMA naruv_hosted_tx_review TO naruv_htx_a,naruv_htx_b;
GRANT SELECT,INSERT ON naruv_hosted_tx_review.orders,naruv_hosted_tx_review.entries TO naruv_htx_a,naruv_htx_b;
CREATE FUNCTION naruv_hosted_tx_review.post_order(p_tenant text,p_request text,p_amount bigint)
RETURNS text LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $fn$
DECLARE n int; existing bigint; posted bigint;
BEGIN
 IF p_request IS NULL OR p_request !~ '^[a-z0-9-]{1,64}$' THEN RAISE EXCEPTION 'INVALID_REQUEST'; END IF;
 INSERT INTO naruv_hosted_tx_review.orders VALUES(p_tenant,p_request,p_amount) ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n=0 THEN
  SELECT amount INTO existing FROM naruv_hosted_tx_review.orders WHERE tenant=p_tenant AND request_id=p_request;
  SELECT amount INTO posted FROM naruv_hosted_tx_review.entries WHERE tenant=p_tenant AND request_id=p_request;
  IF existing IS DISTINCT FROM p_amount OR posted IS DISTINCT FROM p_amount THEN RAISE EXCEPTION 'REQUEST_CONFLICT'; END IF;
  RETURN 'REPLAY';
 END IF;
 INSERT INTO naruv_hosted_tx_review.entries VALUES(p_tenant,p_request,p_amount);
 RETURN 'POSTED';
END $fn$;
REVOKE ALL ON FUNCTION naruv_hosted_tx_review.post_order(text,text,bigint) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_tx_review.post_order(text,text,bigint) TO naruv_htx_a,naruv_htx_b;
RESET ROLE;
SET LOCAL ROLE naruv_htx_a;
DO $test$ BEGIN
 IF naruv_hosted_tx_review.post_order('ci-a','same-id',100) <> 'POSTED' THEN RAISE EXCEPTION 'A_POST'; END IF;
 IF naruv_hosted_tx_review.post_order('ci-a','same-id',100) <> 'REPLAY' THEN RAISE EXCEPTION 'A_REPLAY'; END IF;
 BEGIN PERFORM naruv_hosted_tx_review.post_order('ci-a','same-id',101); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'REQUEST_CONFLICT' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_order('ci-b','forbidden',100); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO naruv_hosted_tx_review.entries VALUES('ci-a','orphan',10); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 BEGIN UPDATE naruv_hosted_tx_review.orders SET amount=1; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM naruv_hosted_tx_review.entries; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN
  INSERT INTO naruv_hosted_tx_review.orders VALUES('ci-a','missing-entry',10);
  SET CONSTRAINTS naruv_hosted_tx_review.order_requires_entry IMMEDIATE;
  RAISE EXCEPTION 'WRONG_ACCEPT';
 EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 BEGIN
  INSERT INTO naruv_hosted_tx_review.orders VALUES('ci-a','mismatched-entry',10);
  INSERT INTO naruv_hosted_tx_review.entries VALUES('ci-a','mismatched-entry',11);
  RAISE EXCEPTION 'WRONG_ACCEPT';
 EXCEPTION WHEN foreign_key_violation THEN NULL; END;
 IF pg_has_role(current_user,'naruv_htx_owner','SET') OR pg_has_role(current_user,'naruv_htx_b','SET') THEN RAISE EXCEPTION 'ROLE_ESCAPE'; END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_htx_b;
DO $test$ BEGIN
 IF naruv_hosted_tx_review.post_order('ci-b','same-id',200)<>'POSTED' THEN RAISE EXCEPTION 'B_POST'; END IF;
 IF naruv_hosted_tx_review.post_order('ci-b','same-id',200)<>'REPLAY' THEN RAISE EXCEPTION 'B_REPLAY'; END IF;
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>1 OR (SELECT sum(amount) FROM naruv_hosted_tx_review.entries)<>200 THEN RAISE EXCEPTION 'B_SCOPE'; END IF;
 BEGIN PERFORM naruv_hosted_tx_review.post_order('ci-a','forbidden',100); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_htx_a;
DO $test$ BEGIN
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>1 OR (SELECT sum(amount) FROM naruv_hosted_tx_review.entries)<>100 THEN RAISE EXCEPTION 'A_SCOPE'; END IF;
END $test$;
RESET ROLE;
DO $test$ BEGIN
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>2 OR (SELECT count(*) FROM naruv_hosted_tx_review.entries)<>2
 OR EXISTS(SELECT 1 FROM naruv_hosted_tx_review.orders o FULL JOIN naruv_hosted_tx_review.entries e USING(tenant,request_id) WHERE o.amount IS DISTINCT FROM e.amount)
 THEN RAISE EXCEPTION 'PAIR_INTEGRITY'; END IF;
 IF EXISTS(SELECT 1 FROM pg_class c WHERE c.relnamespace='naruv_hosted_tx_review'::regnamespace AND c.relkind='r' AND NOT(c.relrowsecurity AND c.relforcerowsecurity)) THEN RAISE EXCEPTION 'RLS'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['anon','authenticated','service_role']) r WHERE has_schema_privilege(r,'naruv_hosted_tx_review','USAGE') OR has_function_privilege(r,'naruv_hosted_tx_review.post_order(text,text,bigint)','EXECUTE')) THEN RAISE EXCEPTION 'API_ROLE_GRANT'; END IF;
END $test$;
SET CONSTRAINTS ALL IMMEDIATE;
SELECT 'HOSTED_PAIR_CONSTRAINT_REVIEW_PASS' AS result,2 AS orders,2 AS entries,2 AS tenants,2 AS exact_replays,2 AS new_pair_constraint_denials,3 AS api_roles_denied,false AS production_authorized;
ROLLBACK;
