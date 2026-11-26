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
