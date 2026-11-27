-- Managed QA identity contract rehearsal; always rolled back.
BEGIN;
SET LOCAL statement_timeout='15s';
SET LOCAL lock_timeout='2s';
SET LOCAL search_path=pg_catalog,pg_temp;
DO $g$ BEGIN
 IF current_user<>'postgres' OR session_user<>'postgres' OR current_database()<>'postgres' OR current_setting('server_version_num')::int/10000<>17 OR to_regclass('naruv_qa_probe.fixture') IS NULL OR to_regnamespace('jw_dev') IS NOT NULL OR to_regnamespace('naruv_hosted_identity_review') IS NOT NULL OR EXISTS(SELECT 1 FROM pg_roles WHERE rolname LIKE 'naruv_hid_%') THEN RAISE EXCEPTION 'IDENTITY_SCOPE'; END IF;
 IF (SELECT count(*) FROM naruv_qa_probe.fixture)<>2 THEN RAISE EXCEPTION 'IDENTITY_MARKER'; END IF;
END $g$;
CREATE ROLE naruv_hid_owner NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_reader NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_writer NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_business NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_auth NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE naruv_hid_ingest NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT naruv_hid_owner,naruv_hid_reader,naruv_hid_writer,naruv_hid_business,naruv_hid_auth,naruv_hid_ingest TO postgres WITH INHERIT FALSE, SET TRUE;
CREATE SCHEMA naruv_hosted_identity_review AUTHORIZATION naruv_hid_owner;
SET LOCAL ROLE naruv_hid_owner;
REVOKE ALL ON SCHEMA naruv_hosted_identity_review FROM PUBLIC,anon,authenticated,service_role;
CREATE TABLE naruv_hosted_identity_review.organizations(id text PRIMARY KEY,name text NOT NULL);
CREATE TABLE naruv_hosted_identity_review.users(id text PRIMARY KEY,org_id text NOT NULL REFERENCES naruv_hosted_identity_review.organizations,actor_role text NOT NULL CHECK(actor_role IN ('admin','member')),active boolean NOT NULL,epoch bigint NOT NULL DEFAULT 0 CHECK(epoch>=0));
CREATE TABLE naruv_hosted_identity_review.sessions(token_hash text PRIMARY KEY CHECK(token_hash~'^[0-9a-f]{64}$'),actor_id text NOT NULL REFERENCES naruv_hosted_identity_review.users,epoch bigint NOT NULL,csrf_token text NOT NULL CHECK(length(csrf_token) BETWEEN 32 AND 256),expires_at timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false);
INSERT INTO naruv_hosted_identity_review.organizations VALUES ('ci-a','Company A'),('ci-b','Company B');
INSERT INTO naruv_hosted_identity_review.users VALUES ('actor-a','ci-a','admin',true,0),('actor-b','ci-b','admin',true,0),('member-a','ci-a','member',true,0);
ALTER TABLE naruv_hosted_identity_review.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_identity_review.organizations FORCE ROW LEVEL SECURITY;
CREATE POLICY read_internal ON naruv_hosted_identity_review.organizations FOR SELECT TO naruv_hid_reader,naruv_hid_writer USING(true);
ALTER TABLE naruv_hosted_identity_review.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_identity_review.users FORCE ROW LEVEL SECURITY;
CREATE POLICY read_internal ON naruv_hosted_identity_review.users FOR SELECT TO naruv_hid_reader,naruv_hid_writer USING(true);
ALTER TABLE naruv_hosted_identity_review.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_hosted_identity_review.sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY read_internal ON naruv_hosted_identity_review.sessions FOR SELECT TO naruv_hid_reader,naruv_hid_writer USING(true);
CREATE POLICY update_user ON naruv_hosted_identity_review.users FOR UPDATE TO naruv_hid_writer USING(true) WITH CHECK(true);
CREATE POLICY insert_session ON naruv_hosted_identity_review.sessions FOR INSERT TO naruv_hid_writer WITH CHECK(true);
CREATE POLICY update_session ON naruv_hosted_identity_review.sessions FOR UPDATE TO naruv_hid_writer USING(true) WITH CHECK(true);
REVOKE ALL ON ALL TABLES IN SCHEMA naruv_hosted_identity_review FROM PUBLIC,anon,authenticated,service_role;
GRANT USAGE ON SCHEMA naruv_hosted_identity_review TO naruv_hid_reader,naruv_hid_writer,naruv_hid_business,naruv_hid_auth,naruv_hid_ingest;
GRANT CREATE ON SCHEMA naruv_hosted_identity_review TO naruv_hid_reader,naruv_hid_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA naruv_hosted_identity_review TO naruv_hid_reader,naruv_hid_writer;
GRANT UPDATE(active,epoch,actor_role) ON naruv_hosted_identity_review.users TO naruv_hid_writer;
GRANT INSERT,UPDATE(revoked) ON naruv_hosted_identity_review.sessions TO naruv_hid_writer;
RESET ROLE;
SET LOCAL ROLE naruv_hid_reader;
CREATE FUNCTION naruv_hosted_identity_review.stage_identity_v84()
RETURNS TABLE(actor_id text,org_id text,actor_role text,csrf_token text,org_name text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT u.id,u.org_id,u.actor_role,s.csrf_token,o.name FROM naruv_hosted_identity_review.sessions s JOIN naruv_hosted_identity_review.users u ON u.id=s.actor_id JOIN naruv_hosted_identity_review.organizations o ON o.id=u.org_id
 WHERE s.token_hash=nullif(current_setting('jw.session_hash',true),'') AND s.expires_at>clock_timestamp() AND NOT s.revoked AND u.active AND s.epoch=u.epoch
$fn$;
REVOKE ALL ON FUNCTION naruv_hosted_identity_review.stage_identity_v84() FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.stage_identity_v84() TO naruv_hid_business,naruv_hid_ingest;
RESET ROLE;
SET LOCAL ROLE naruv_hid_writer;
CREATE FUNCTION naruv_hosted_identity_review.issue(p_actor text,p_hash text,p_csrf text,p_ttl integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE u naruv_hosted_identity_review.users%ROWTYPE;
BEGIN
 IF p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' OR p_csrf IS NULL OR length(p_csrf) NOT BETWEEN 32 AND 256 OR p_ttl IS NULL OR p_ttl NOT BETWEEN 1 AND 43200 THEN RAISE EXCEPTION 'IDENTITY_INPUT' USING ERRCODE='23514'; END IF;
 SELECT * INTO u FROM naruv_hosted_identity_review.users WHERE id=p_actor FOR UPDATE;
 IF NOT FOUND OR NOT u.active THEN RAISE EXCEPTION 'IDENTITY_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 INSERT INTO naruv_hosted_identity_review.sessions(token_hash,actor_id,epoch,csrf_token,expires_at) VALUES(p_hash,u.id,u.epoch,p_csrf,clock_timestamp()+make_interval(secs=>p_ttl));
 RETURN true;
END $fn$;
CREATE FUNCTION naruv_hosted_identity_review.revoke(p_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE n int;
BEGIN
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE token_hash=p_hash AND NOT revoked;
 GET DIAGNOSTICS n=ROW_COUNT; RETURN n=1;
END $fn$;
CREATE FUNCTION naruv_hosted_identity_review.change_actor(p_actor text,p_active boolean,p_role text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE n int;
BEGIN
 IF p_active IS NULL OR p_role IS NULL OR p_role NOT IN ('admin','member') THEN RAISE EXCEPTION 'IDENTITY_INPUT' USING ERRCODE='23514'; END IF;
 UPDATE naruv_hosted_identity_review.users SET active=p_active,actor_role=p_role,epoch=epoch+1 WHERE id=p_actor;
 GET DIAGNOSTICS n=ROW_COUNT;
 IF n<>1 THEN RAISE EXCEPTION 'IDENTITY_UNAVAILABLE' USING ERRCODE='42501'; END IF;
 UPDATE naruv_hosted_identity_review.sessions SET revoked=true WHERE actor_id=p_actor AND NOT revoked;
 RETURN true;
END $fn$;
REVOKE ALL ON FUNCTION naruv_hosted_identity_review.issue(text,text,text,integer),naruv_hosted_identity_review.revoke(text),naruv_hosted_identity_review.change_actor(text,boolean,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.issue(text,text,text,integer),naruv_hosted_identity_review.revoke(text),naruv_hosted_identity_review.change_actor(text,boolean,text) TO naruv_hid_auth;
RESET ROLE;
SET LOCAL ROLE naruv_hid_owner;
REVOKE CREATE ON SCHEMA naruv_hosted_identity_review FROM naruv_hid_reader,naruv_hid_writer;
RESET ROLE;
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

-- New transaction boundary: authenticated gateway; legacy per-tenant callers removed.
CREATE ROLE naruv_htx_gateway NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT naruv_htx_gateway TO postgres WITH INHERIT FALSE,SET TRUE;
SET LOCAL ROLE naruv_hid_owner;
GRANT USAGE ON SCHEMA naruv_hosted_identity_review TO naruv_htx_gateway;
GRANT CREATE ON SCHEMA naruv_hosted_identity_review TO naruv_hid_writer;
RESET ROLE;
SET LOCAL ROLE naruv_hid_writer;
CREATE FUNCTION naruv_hosted_identity_review.lock_admin(p_tenant text,p_csrf text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE h text; actor text; u naruv_hosted_identity_review.users%ROWTYPE; s naruv_hosted_identity_review.sessions%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'AUTH_TX_ISOLATION' USING ERRCODE='25000'; END IF;
 h:=nullif(current_setting('jw.session_hash',true),'');
 IF h IS NULL OR h !~ '^[0-9a-f]{64}$' OR p_tenant IS NULL OR p_csrf IS NULL THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 SELECT actor_id INTO actor FROM naruv_hosted_identity_review.sessions WHERE token_hash=h;
 IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 -- User before session, same order as change_actor; locks held until transaction end.
 SELECT * INTO u FROM naruv_hosted_identity_review.users WHERE id=actor FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO s FROM naruv_hosted_identity_review.sessions WHERE token_hash=h FOR UPDATE;
 IF NOT FOUND OR s.actor_id IS DISTINCT FROM u.id OR s.revoked OR NOT u.active OR s.epoch<>u.epoch
 OR s.expires_at<=clock_timestamp() OR s.csrf_token IS DISTINCT FROM p_csrf OR u.actor_role<>'admin'
 OR u.org_id IS DISTINCT FROM p_tenant THEN RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
 RETURN u.org_id;
END $fn$;
REVOKE ALL ON FUNCTION naruv_hosted_identity_review.lock_admin(text,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_identity_review.lock_admin(text,text) TO naruv_htx_gateway;
RESET ROLE;
SET LOCAL ROLE naruv_hid_owner;
REVOKE CREATE ON SCHEMA naruv_hosted_identity_review FROM naruv_hid_writer;
RESET ROLE;
SET LOCAL ROLE naruv_htx_owner;
GRANT USAGE ON SCHEMA naruv_hosted_tx_review TO naruv_hid_business,naruv_htx_gateway;
GRANT CREATE ON SCHEMA naruv_hosted_tx_review TO naruv_htx_gateway;
RESET ROLE;
SET LOCAL ROLE naruv_htx_exec_a;
REVOKE ALL ON FUNCTION naruv_hosted_tx_review.post_a(text,bigint),naruv_hosted_tx_review.read_a() FROM naruv_htx_a;
GRANT EXECUTE ON FUNCTION naruv_hosted_tx_review.post_a(text,bigint),naruv_hosted_tx_review.read_a() TO naruv_htx_gateway;
RESET ROLE;
SET LOCAL ROLE naruv_htx_exec_b;
REVOKE ALL ON FUNCTION naruv_hosted_tx_review.post_b(text,bigint),naruv_hosted_tx_review.read_b() FROM naruv_htx_b;
GRANT EXECUTE ON FUNCTION naruv_hosted_tx_review.post_b(text,bigint),naruv_hosted_tx_review.read_b() TO naruv_htx_gateway;
RESET ROLE;
SET LOCAL ROLE naruv_htx_gateway;
CREATE FUNCTION naruv_hosted_tx_review.post_authenticated(p_tenant text,p_request text,p_amount bigint,p_csrf text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE org text;
BEGIN
 org:=naruv_hosted_identity_review.lock_admin(p_tenant,p_csrf);
 IF org='ci-a' THEN RETURN naruv_hosted_tx_review.post_a(p_request,p_amount);
 ELSIF org='ci-b' THEN RETURN naruv_hosted_tx_review.post_b(p_request,p_amount);
 ELSE RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
END $fn$;
CREATE FUNCTION naruv_hosted_tx_review.read_authenticated(p_tenant text,p_csrf text)
RETURNS TABLE(request_id text,amount bigint) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE org text;
BEGIN
 org:=naruv_hosted_identity_review.lock_admin(p_tenant,p_csrf);
 IF org='ci-a' THEN RETURN QUERY SELECT * FROM naruv_hosted_tx_review.read_a();
 ELSIF org='ci-b' THEN RETURN QUERY SELECT * FROM naruv_hosted_tx_review.read_b();
 ELSE RAISE EXCEPTION 'AUTH_DENIED' USING ERRCODE='42501'; END IF;
END $fn$;
REVOKE ALL ON FUNCTION naruv_hosted_tx_review.post_authenticated(text,text,bigint,text),naruv_hosted_tx_review.read_authenticated(text,text) FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION naruv_hosted_tx_review.post_authenticated(text,text,bigint,text),naruv_hosted_tx_review.read_authenticated(text,text) TO naruv_hid_business;
RESET ROLE;
SET LOCAL ROLE naruv_htx_owner;
REVOKE CREATE ON SCHEMA naruv_hosted_tx_review FROM naruv_htx_gateway;
RESET ROLE;
-- END_SETUP_BEGIN_SYNTHETIC_TESTS
SET LOCAL ROLE naruv_hid_auth;
DO $test$ BEGIN
 IF NOT naruv_hosted_identity_review.issue('actor-a',repeat('a',64),repeat('c',32),3600)
 OR NOT naruv_hosted_identity_review.issue('actor-b',repeat('b',64),repeat('d',32),3600)
 OR NOT naruv_hosted_identity_review.issue('member-a',repeat('e',64),repeat('f',32),3600)
 OR NOT naruv_hosted_identity_review.issue('actor-b',repeat('4',64),repeat('d',32),1) THEN RAISE EXCEPTION 'ISSUE'; END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_business;
DO $test$ BEGIN
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 IF naruv_hosted_tx_review.post_authenticated('ci-a','same-id',100,repeat('c',32))<>'POSTED'
 OR naruv_hosted_tx_review.post_authenticated('ci-a','same-id',100,repeat('c',32))<>'REPLAY' THEN RAISE EXCEPTION 'A_POST'; END IF;
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-a','same-id',101,repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN raise_exception THEN IF SQLERRM<>'REQUEST_CONFLICT' THEN RAISE; END IF; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-b','cross',1,repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-a','csrf',1,repeat('x',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-a','csrf-null',1,NULL); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.read_authenticated('ci-b',repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_tx_review.post_a('bypass',1); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN PERFORM naruv_hosted_identity_review.lock_admin('ci-a',repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 BEGIN INSERT INTO naruv_hosted_tx_review.orders VALUES('ci-a','bypass',1); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 IF naruv_hosted_tx_review.post_authenticated('ci-b','same-id',200,repeat('d',32))<>'POSTED'
 OR naruv_hosted_tx_review.post_authenticated('ci-b','same-id',200,repeat('d',32))<>'REPLAY' THEN RAISE EXCEPTION 'B_POST'; END IF;
 IF (SELECT sum(amount) FROM naruv_hosted_tx_review.read_authenticated('ci-b',repeat('d',32)))<>200 THEN RAISE EXCEPTION 'B_READ'; END IF;
 PERFORM set_config('jw.session_hash',repeat('e',64),true);
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-a','member',1,repeat('f',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash',repeat('0',64),true);
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-a','unknown',1,repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM pg_sleep(1.2);
 PERFORM set_config('jw.session_hash',repeat('4',64),true);
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-b','expired',1,repeat('d',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_auth;
DO $test$ BEGIN
 IF NOT naruv_hosted_identity_review.change_actor('actor-a',false,'admin') OR NOT naruv_hosted_identity_review.change_actor('actor-a',true,'member')
 OR NOT naruv_hosted_identity_review.issue('actor-a',repeat('3',64),repeat('c',32),3600) THEN RAISE EXCEPTION 'REACTIVATION'; END IF;
 IF NOT naruv_hosted_identity_review.revoke(repeat('b',64)) THEN RAISE EXCEPTION 'REVOKE'; END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_hid_business;
DO $test$ BEGIN
 PERFORM set_config('jw.session_hash',repeat('a',64),true);
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-a','same-id',100,repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash',repeat('3',64),true);
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-a','downgraded',1,repeat('c',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 PERFORM set_config('jw.session_hash',repeat('b',64),true);
 BEGIN PERFORM naruv_hosted_tx_review.post_authenticated('ci-b','revoked',1,repeat('d',32)); RAISE EXCEPTION 'UNEXPECTED'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_htx_exec_a;
DO $test$ BEGIN
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>1 OR (SELECT sum(amount) FROM naruv_hosted_tx_review.entries)<>100 THEN RAISE EXCEPTION 'A_PAIR'; END IF;
END $test$;
RESET ROLE;
SET LOCAL ROLE naruv_htx_exec_b;
DO $test$ BEGIN
 IF (SELECT count(*) FROM naruv_hosted_tx_review.orders)<>1 OR (SELECT sum(amount) FROM naruv_hosted_tx_review.entries)<>200 THEN RAISE EXCEPTION 'B_PAIR'; END IF;
END $test$;
RESET ROLE;
DO $audit$ BEGIN
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['naruv_hid_business','naruv_hid_auth','naruv_hid_ingest','naruv_htx_a','naruv_htx_b','anon','authenticated','service_role']) r CROSS JOIN pg_proc p WHERE p.pronamespace='naruv_hosted_tx_review'::regnamespace AND p.proname NOT IN ('post_authenticated','read_authenticated') AND has_function_privilege(r,p.oid,'EXECUTE')) THEN RAISE EXCEPTION 'LEGACY_RPC_BYPASS'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['naruv_hid_auth','naruv_hid_ingest','naruv_htx_a','naruv_htx_b','anon','authenticated','service_role']) r WHERE has_function_privilege(r,'naruv_hosted_tx_review.post_authenticated(text,text,bigint,text)','EXECUTE') OR has_function_privilege(r,'naruv_hosted_tx_review.read_authenticated(text,text)','EXECUTE')) THEN RAISE EXCEPTION 'UNAUTHORIZED_GATEWAY'; END IF;
 IF EXISTS(SELECT 1 FROM unnest(ARRAY['naruv_hid_business','naruv_hid_auth','naruv_hid_ingest','naruv_htx_a','naruv_htx_b','naruv_htx_gateway']) r CROSS JOIN pg_class c WHERE c.relnamespace='naruv_hosted_tx_review'::regnamespace AND c.relkind='r' AND (has_table_privilege(r,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) THEN RAISE EXCEPTION 'DIRECT_GRANT'; END IF;
END $audit$;
SET CONSTRAINTS ALL IMMEDIATE;
SELECT 'HOSTED_AUTH_TX_REVIEW_PASS' AS result,2 AS tenants,2 AS orders,2 AS entries,2 AS exact_replays,14 AS negative_checks,false AS production_authorized;
ROLLBACK;
