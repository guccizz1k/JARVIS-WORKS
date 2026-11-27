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
CREATE ROLE naruv_htx_exec_a NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_htx_exec_b NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT naruv_htx_owner,naruv_htx_a,naruv_htx_b,naruv_htx_exec_a,naruv_htx_exec_b TO postgres WITH INHERIT FALSE, SET TRUE;
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
CREATE POLICY a_orders ON naruv_hosted_tx_review.orders TO naruv_htx_exec_a USING(tenant='ci-a') WITH CHECK(tenant='ci-a');
CREATE POLICY b_orders ON naruv_hosted_tx_review.orders TO naruv_htx_exec_b USING(tenant='ci-b') WITH CHECK(tenant='ci-b');
CREATE POLICY a_entries ON naruv_hosted_tx_review.entries TO naruv_htx_exec_a USING(tenant='ci-a') WITH CHECK(tenant='ci-a');
CREATE POLICY b_entries ON naruv_hosted_tx_review.entries TO naruv_htx_exec_b USING(tenant='ci-b') WITH CHECK(tenant='ci-b');
REVOKE ALL ON ALL TABLES IN SCHEMA naruv_hosted_tx_review FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON SCHEMA naruv_hosted_tx_review TO naruv_htx_a,naruv_htx_b;
GRANT USAGE,CREATE ON SCHEMA naruv_hosted_tx_review TO naruv_htx_exec_a,naruv_htx_exec_b;
GRANT SELECT,INSERT ON naruv_hosted_tx_review.orders,naruv_hosted_tx_review.entries TO naruv_htx_exec_a,naruv_htx_exec_b;
CREATE FUNCTION naruv_hosted_tx_review.post_order(p_tenant text,p_request text,p_amount bigint)
RETURNS text LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $fn$
DECLARE n int; existing bigint; posted bigint;
BEGIN
 IF p_request IS NULL OR p_request !~ '^[a-z0-9-]{1,64}$' OR p_amount IS NULL OR p_amount NOT BETWEEN 1 AND 1000000000 THEN RAISE EXCEPTION 'INVALID_REQUEST'; END IF;
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
GRANT EXECUTE ON FUNCTION naruv_hosted_tx_review.post_order(text,text,bigint) TO naruv_htx_exec_a,naruv_htx_exec_b;
RESET ROLE;

SET LOCAL ROLE naruv_htx_exec_a;
CREATE FUNCTION naruv_hosted_tx_review.post_a(p_request text,p_amount bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT naruv_hosted_tx_review.post_order('ci-a',p_request,p_amount)
$fn$;
CREATE FUNCTION naruv_hosted_tx_review.read_a()
RETURNS TABLE(request_id text,amount bigint) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT o.request_id,o.amount FROM naruv_hosted_tx_review.orders o
 WHERE o.tenant='ci-a' ORDER BY o.request_id
$fn$;
REVOKE ALL ON FUNCTION naruv_hosted_tx_review.post_a(text,bigint),naruv_hosted_tx_review.read_a() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_tx_review.post_a(text,bigint),naruv_hosted_tx_review.read_a() TO naruv_htx_a;
RESET ROLE;
SET LOCAL ROLE naruv_htx_exec_b;
CREATE FUNCTION naruv_hosted_tx_review.post_b(p_request text,p_amount bigint)
RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT naruv_hosted_tx_review.post_order('ci-b',p_request,p_amount)
$fn$;
CREATE FUNCTION naruv_hosted_tx_review.read_b()
RETURNS TABLE(request_id text,amount bigint) LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT o.request_id,o.amount FROM naruv_hosted_tx_review.orders o
 WHERE o.tenant='ci-b' ORDER BY o.request_id
$fn$;
REVOKE ALL ON FUNCTION naruv_hosted_tx_review.post_b(text,bigint),naruv_hosted_tx_review.read_b() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_tx_review.post_b(text,bigint),naruv_hosted_tx_review.read_b() TO naruv_htx_b;
RESET ROLE;
SET LOCAL ROLE naruv_htx_owner;
REVOKE CREATE ON SCHEMA naruv_hosted_tx_review FROM naruv_htx_exec_a,naruv_htx_exec_b;
RESET ROLE;
SET LOCAL ROLE naruv_htx_a;
DO $test$ BEGIN
 IF naruv_hosted_tx_review.post_a('same-id',100)<>'POSTED' THEN RAISE EXCEPTION 'POST'; END IF;
 IF naruv_hosted_tx_review.post_a('same-id',100)<>'REPLAY' THEN RAISE EXCEPTION 'REPLAY'; END IF;
 BEGIN PERFORM naruv_hosted_tx_review.post_a('same-id',101); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'REQUEST_CONFLICT' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_a('bad',0); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'INVALID_REQUEST' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_a('bad',NULL); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'INVALID_REQUEST' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_b('forbidden',1); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.read_b(); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_order('ci-b','forbidden',1); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO naruv_hosted_tx_review.orders VALUES('ci-a','direct',10); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO naruv_hosted_tx_review.entries VALUES('ci-a','same-id',100); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM amount FROM naruv_hosted_tx_review.orders; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM amount FROM naruv_hosted_tx_review.entries; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN UPDATE naruv_hosted_tx_review.orders SET amount=1; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM naruv_hosted_tx_review.entries; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF pg_has_role(current_user,'naruv_htx_owner','SET') OR pg_has_role(current_user,'naruv_htx_exec_a','SET') OR pg_has_role(current_user,'naruv_htx_exec_b','SET') OR pg_has_role(current_user,'naruv_htx_b','SET') THEN RAISE EXCEPTION 'ROLE_ESCAPE'; END IF;
 PERFORM set_config('naruv.tenant','ci-b',true);
 IF (SELECT count(*) FROM naruv_hosted_tx_review.read_a())<>1 OR (SELECT sum(amount) FROM naruv_hosted_tx_review.read_a())<>100 THEN RAISE EXCEPTION 'TENANT_SCOPE'; END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_htx_b;
DO $test$ BEGIN
 IF naruv_hosted_tx_review.post_b('same-id',200)<>'POSTED' THEN RAISE EXCEPTION 'POST'; END IF;
 IF naruv_hosted_tx_review.post_b('same-id',200)<>'REPLAY' THEN RAISE EXCEPTION 'REPLAY'; END IF;
 BEGIN PERFORM naruv_hosted_tx_review.post_b('same-id',201); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'REQUEST_CONFLICT' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_b('bad',0); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'INVALID_REQUEST' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_b('bad',NULL); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'INVALID_REQUEST' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_a('forbidden',1); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.read_a(); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_order('ci-a','forbidden',1); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO naruv_hosted_tx_review.orders VALUES('ci-b','direct',10); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO naruv_hosted_tx_review.entries VALUES('ci-b','same-id',200); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM amount FROM naruv_hosted_tx_review.orders; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM amount FROM naruv_hosted_tx_review.entries; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN UPDATE naruv_hosted_tx_review.orders SET amount=1; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN DELETE FROM naruv_hosted_tx_review.entries; RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF pg_has_role(current_user,'naruv_htx_owner','SET') OR pg_has_role(current_user,'naruv_htx_exec_a','SET') OR pg_has_role(current_user,'naruv_htx_exec_b','SET') OR pg_has_role(current_user,'naruv_htx_a','SET') THEN RAISE EXCEPTION 'ROLE_ESCAPE'; END IF;
 PERFORM set_config('naruv.tenant','ci-a',true);
 IF (SELECT count(*) FROM naruv_hosted_tx_review.read_b())<>1 OR (SELECT sum(amount) FROM naruv_hosted_tx_review.read_b())<>200 THEN RAISE EXCEPTION 'TENANT_SCOPE'; END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_htx_exec_a;
DO $test$ BEGIN
 BEGIN PERFORM naruv_hosted_tx_review.post_order('ci-b','definer-cross',1); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>1 THEN RAISE EXCEPTION 'EXECUTOR_SCOPE'; END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_htx_exec_b;
DO $test$ BEGIN
 BEGIN PERFORM naruv_hosted_tx_review.post_order('ci-a','definer-cross',1); RAISE EXCEPTION 'WRONG_ACCEPT'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>1 THEN RAISE EXCEPTION 'EXECUTOR_SCOPE'; END IF;
END $test$;
RESET ROLE;
DO $audit$ BEGIN
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>2 OR (SELECT count(*) FROM naruv_hosted_tx_review.entries)<>2
 OR EXISTS(SELECT 1 FROM naruv_hosted_tx_review.orders o FULL JOIN naruv_hosted_tx_review.entries e USING(tenant,request_id) WHERE o.amount IS DISTINCT FROM e.amount) THEN RAISE EXCEPTION 'PAIR_INTEGRITY'; END IF;
 IF (SELECT count(*) FROM pg_class WHERE relnamespace='naruv_hosted_tx_review'::regnamespace AND relkind='r' AND relrowsecurity AND relforcerowsecurity)<>2 THEN RAISE EXCEPTION 'RLS'; END IF;
 IF (SELECT count(*) FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner WHERE p.pronamespace='naruv_hosted_tx_review'::regnamespace AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog'] AND NOT(r.rolcanlogin OR r.rolsuper OR r.rolbypassrls) AND r.rolname IN ('naruv_htx_exec_a','naruv_htx_exec_b'))<>4 THEN RAISE EXCEPTION 'DEFINER_SCOPE'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['anon','authenticated','service_role']) r CROSS JOIN pg_proc p WHERE p.pronamespace='naruv_hosted_tx_review'::regnamespace AND (has_schema_privilege(r,'naruv_hosted_tx_review','USAGE') OR has_function_privilege(r,p.oid,'EXECUTE'))) THEN RAISE EXCEPTION 'API_GRANT'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['naruv_htx_a','naruv_htx_b']) r CROSS JOIN pg_class c WHERE c.relnamespace='naruv_hosted_tx_review'::regnamespace AND c.relkind='r' AND (has_table_privilege(r,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) THEN RAISE EXCEPTION 'DIRECT_GRANT'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['naruv_htx_a','naruv_htx_b','naruv_htx_exec_a','naruv_htx_exec_b']) r WHERE has_schema_privilege(r,'naruv_hosted_tx_review','CREATE')) THEN RAISE EXCEPTION 'SCHEMA_CREATE'; END IF;
END $audit$;
SET CONSTRAINTS ALL IMMEDIATE;
SELECT 'HOSTED_RPC_ONLY_REVIEW_PASS' AS result,2 AS orders,2 AS entries,2 AS tenants,2 AS exact_replays,26 AS negative_operation_checks,4 AS restricted_definer_functions,3 AS api_roles_denied,false AS production_authorized;
ROLLBACK;
