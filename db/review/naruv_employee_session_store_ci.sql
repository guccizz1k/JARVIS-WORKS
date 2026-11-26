-- Isolated review fixture. Never install in a production DB.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.employee_store_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'EMPLOYEE_STORE_DISPOSABLE_ONLY'; END IF;
END $$;
CREATE SCHEMA naruv_employee_ci;
REVOKE ALL ON SCHEMA naruv_employee_ci FROM PUBLIC;
CREATE TABLE naruv_employee_ci.identities(
 tenant text NOT NULL,principal text NOT NULL,worker text NOT NULL,auth_epoch bigint NOT NULL CHECK(auth_epoch>=0),
 active boolean NOT NULL, PRIMARY KEY(tenant,principal), UNIQUE(tenant,principal,worker));
CREATE TABLE naruv_employee_ci.entitlements(
 tenant text NOT NULL,worker text NOT NULL,receipt text NOT NULL,
 review_sha256 text NOT NULL CHECK(review_sha256 ~ '^[0-9a-f]{64}$'),
 render_sha256 text NOT NULL CHECK(render_sha256 ~ '^[0-9a-f]{64}$'),
 active boolean NOT NULL, PRIMARY KEY(tenant,worker,receipt));
CREATE TABLE naruv_employee_ci.sessions(
 audience text NOT NULL CHECK(audience='naruv-employee-statement-review-v1'),
 tenant text NOT NULL,principal text NOT NULL,worker text NOT NULL,auth_epoch bigint NOT NULL CHECK(auth_epoch>=0),
 receipt text NOT NULL,review_sha256 text NOT NULL CHECK(review_sha256 ~ '^[0-9a-f]{64}$'),
 render_sha256 text NOT NULL CHECK(render_sha256 ~ '^[0-9a-f]{64}$'),
 token_sha256 text PRIMARY KEY CHECK(token_sha256 ~ '^[0-9a-f]{64}$'),
 issued_at bigint NOT NULL CHECK(issued_at>=0),expires_at bigint NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 CHECK(expires_at>issued_at AND expires_at-issued_at<=300),
 FOREIGN KEY(tenant,principal,worker) REFERENCES naruv_employee_ci.identities(tenant,principal,worker),
 FOREIGN KEY(tenant,worker,receipt) REFERENCES naruv_employee_ci.entitlements(tenant,worker,receipt));
REVOKE ALL ON ALL TABLES IN SCHEMA naruv_employee_ci FROM PUBLIC;

-- CI-only broker roles; FOR SHARE requires a column UPDATE grant.
CREATE ROLE naruv_employee_ci_a NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE naruv_employee_ci_b NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA naruv_employee_ci TO naruv_employee_ci_a,naruv_employee_ci_b;
GRANT SELECT ON ALL TABLES IN SCHEMA naruv_employee_ci TO naruv_employee_ci_a,naruv_employee_ci_b;
GRANT UPDATE (active) ON naruv_employee_ci.identities,naruv_employee_ci.entitlements TO naruv_employee_ci_a,naruv_employee_ci_b;
GRANT UPDATE (revoked) ON naruv_employee_ci.sessions TO naruv_employee_ci_a,naruv_employee_ci_b;
GRANT INSERT ON naruv_employee_ci.sessions TO naruv_employee_ci_a,naruv_employee_ci_b;
ALTER TABLE naruv_employee_ci.identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_employee_ci.identities FORCE ROW LEVEL SECURITY;
CREATE POLICY broker_read ON naruv_employee_ci.identities FOR SELECT TO naruv_employee_ci_a,naruv_employee_ci_b USING (((current_user='naruv_employee_ci_a' AND tenant='ci-a') OR (current_user='naruv_employee_ci_b' AND tenant='ci-b')) AND principal='e1' AND worker='w1');
CREATE POLICY broker_lock ON naruv_employee_ci.identities FOR UPDATE TO naruv_employee_ci_a,naruv_employee_ci_b USING (((current_user='naruv_employee_ci_a' AND tenant='ci-a') OR (current_user='naruv_employee_ci_b' AND tenant='ci-b')) AND principal='e1' AND worker='w1') WITH CHECK (false);
ALTER TABLE naruv_employee_ci.entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_employee_ci.entitlements FORCE ROW LEVEL SECURITY;
CREATE POLICY broker_read ON naruv_employee_ci.entitlements FOR SELECT TO naruv_employee_ci_a,naruv_employee_ci_b USING (((current_user='naruv_employee_ci_a' AND tenant='ci-a') OR (current_user='naruv_employee_ci_b' AND tenant='ci-b')) AND worker='w1');
CREATE POLICY broker_lock ON naruv_employee_ci.entitlements FOR UPDATE TO naruv_employee_ci_a,naruv_employee_ci_b USING (((current_user='naruv_employee_ci_a' AND tenant='ci-a') OR (current_user='naruv_employee_ci_b' AND tenant='ci-b')) AND worker='w1') WITH CHECK (false);
ALTER TABLE naruv_employee_ci.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_employee_ci.sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY broker_read ON naruv_employee_ci.sessions FOR SELECT TO naruv_employee_ci_a,naruv_employee_ci_b USING (((current_user='naruv_employee_ci_a' AND tenant='ci-a') OR (current_user='naruv_employee_ci_b' AND tenant='ci-b')) AND principal='e1' AND worker='w1');
CREATE POLICY broker_lock ON naruv_employee_ci.sessions FOR UPDATE TO naruv_employee_ci_a,naruv_employee_ci_b USING (((current_user='naruv_employee_ci_a' AND tenant='ci-a') OR (current_user='naruv_employee_ci_b' AND tenant='ci-b')) AND principal='e1' AND worker='w1') WITH CHECK (false);
CREATE POLICY broker_insert ON naruv_employee_ci.sessions FOR INSERT TO naruv_employee_ci_a,naruv_employee_ci_b WITH CHECK (((current_user='naruv_employee_ci_a' AND tenant='ci-a') OR (current_user='naruv_employee_ci_b' AND tenant='ci-b')) AND principal='e1' AND worker='w1' AND NOT revoked AND EXISTS (SELECT 1 FROM naruv_employee_ci.identities i WHERE (i.tenant,i.principal,i.worker,i.auth_epoch)=(sessions.tenant,sessions.principal,sessions.worker,sessions.auth_epoch) AND i.active) AND EXISTS (SELECT 1 FROM naruv_employee_ci.entitlements e WHERE (e.tenant,e.worker,e.receipt,e.review_sha256,e.render_sha256)=(sessions.tenant,sessions.worker,sessions.receipt,sessions.review_sha256,sessions.render_sha256) AND e.active));

-- Invalidation is monotonic even if the original binding is restored.
CREATE FUNCTION naruv_employee_ci.revoke_changed_binding() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='identities' THEN
  UPDATE naruv_employee_ci.sessions SET revoked=true
  WHERE tenant=OLD.tenant AND principal=OLD.principal AND NOT revoked;
 ELSIF TG_TABLE_NAME='entitlements' THEN
  UPDATE naruv_employee_ci.sessions SET revoked=true
  WHERE tenant=OLD.tenant AND worker=OLD.worker AND receipt=OLD.receipt AND NOT revoked;
 ELSE RAISE EXCEPTION 'INVALID_REVOCATION_SOURCE';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION naruv_employee_ci.revoke_changed_binding() FROM PUBLIC;
CREATE TRIGGER revoke_identity_change AFTER UPDATE ON naruv_employee_ci.identities
 FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION naruv_employee_ci.revoke_changed_binding();
CREATE TRIGGER revoke_entitlement_change AFTER UPDATE ON naruv_employee_ci.entitlements
 FOR EACH ROW WHEN (OLD.* IS DISTINCT FROM NEW.*) EXECUTE FUNCTION naruv_employee_ci.revoke_changed_binding();
CREATE FUNCTION naruv_employee_ci.reject_session_reactivation() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.revoked AND NOT NEW.revoked THEN
  RAISE EXCEPTION 'EMPLOYEE_SESSION_REACTIVATION_DENIED' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION naruv_employee_ci.reject_session_reactivation() FROM PUBLIC;
CREATE TRIGGER reject_session_reactivation BEFORE UPDATE OF revoked ON naruv_employee_ci.sessions
 FOR EACH ROW EXECUTE FUNCTION naruv_employee_ci.reject_session_reactivation();
