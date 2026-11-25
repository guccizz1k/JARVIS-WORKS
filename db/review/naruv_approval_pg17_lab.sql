-- Disposable PostgreSQL 17 lab ONLY. Never apply to an existing ERP database.
-- Caller is the ephemeral root; all application connections use non-owner roles.
CREATE ROLE naruv_lab_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;
CREATE ROLE naruv_lab_a LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'naruv-ci-a-fixture';
CREATE ROLE naruv_lab_b LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD 'naruv-ci-b-fixture';
CREATE SCHEMA naruv_approval_lab AUTHORIZATION naruv_lab_owner;
REVOKE ALL ON SCHEMA naruv_approval_lab FROM PUBLIC;
GRANT USAGE ON SCHEMA naruv_approval_lab TO naruv_lab_a,naruv_lab_b;
SET ROLE naruv_lab_owner;
CREATE TABLE naruv_approval_lab.actors (
  login_role name PRIMARY KEY,
  organization_id text UNIQUE NOT NULL,
  actor_id text NOT NULL,
  permission_revision text NOT NULL,
  active boolean NOT NULL,
  can_approve boolean NOT NULL,
  can_reserve boolean NOT NULL,
  last_epoch bigint NOT NULL DEFAULT 0 CHECK (last_epoch >= 0)
);
INSERT INTO naruv_approval_lab.actors VALUES
 ('naruv_lab_a','org-a','account-a','perm-1',true,true,true,0),
 ('naruv_lab_b','org-b','account-b','perm-1',true,true,true,0);
CREATE TABLE naruv_approval_lab.targets (
 organization_id text NOT NULL REFERENCES naruv_approval_lab.actors(organization_id),
 source_id text NOT NULL CHECK (source_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 entity text NOT NULL CHECK (entity IN ('customer','item')),
 snapshot_sha256 text NOT NULL CHECK (snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(organization_id,source_id,entity)
);
CREATE TABLE naruv_approval_lab.approvals (
 organization_id text NOT NULL REFERENCES naruv_approval_lab.actors(organization_id),
 approval_id text NOT NULL CHECK (approval_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 source_id text NOT NULL,
 entity text NOT NULL,
 preflight_sha256 text NOT NULL CHECK (preflight_sha256 ~ '^[a-f0-9]{64}$'),
 rows_sha256 text NOT NULL CHECK (rows_sha256 ~ '^[a-f0-9]{64}$'),
 snapshot_sha256 text NOT NULL CHECK (snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 actor_id text NOT NULL,
 permission_revision text NOT NULL,
 issued_at bigint NOT NULL CHECK (issued_at > 0),
 expires_at bigint NOT NULL CHECK (expires_at > issued_at AND expires_at-issued_at <= 900),
 status text NOT NULL DEFAULT 'APPROVED' CHECK (status IN ('APPROVED','RESERVED','REVOKED')),
 reservation_id text CHECK (reservation_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'),
 row_import_authorized boolean NOT NULL DEFAULT false CHECK (row_import_authorized = false),
 CHECK ((status = 'RESERVED') = (reservation_id IS NOT NULL)),
 PRIMARY KEY(organization_id,approval_id),
 UNIQUE(organization_id,source_id,entity,rows_sha256),
 UNIQUE(organization_id,reservation_id),
 FOREIGN KEY(organization_id,source_id,entity)
   REFERENCES naruv_approval_lab.targets(organization_id,source_id,entity)
);
ALTER TABLE naruv_approval_lab.actors ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.actors FORCE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.targets FORCE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE naruv_approval_lab.approvals FORCE ROW LEVEL SECURITY;
-- session_user is the authenticated database login, not a client-controlled GUC.
CREATE POLICY actor_scope ON naruv_approval_lab.actors
 USING (login_role = session_user) WITH CHECK (login_role = session_user);
CREATE POLICY target_scope ON naruv_approval_lab.targets
 USING (organization_id = (SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user))
 WITH CHECK (organization_id = (SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user));
CREATE POLICY approval_scope ON naruv_approval_lab.approvals
 USING (organization_id = (SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user))
 WITH CHECK (organization_id = (SELECT a.organization_id FROM naruv_approval_lab.actors a WHERE a.login_role=session_user));
-- Internal helper is not granted to application roles.
CREATE FUNCTION naruv_approval_lab.lock_actor(p_capability text)
 RETURNS naruv_approval_lab.actors
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors; n bigint;
BEGIN
 SELECT * INTO a FROM naruv_approval_lab.actors WHERE login_role=session_user FOR UPDATE;
 IF NOT FOUND OR NOT a.active OR
    (p_capability='approve' AND NOT a.can_approve) OR
    (p_capability='reserve' AND NOT (a.can_approve AND a.can_reserve)) OR
    p_capability NOT IN ('approve','reserve','inspect') THEN
   RAISE EXCEPTION 'APPROVAL_PERMISSION_DENIED';
 END IF;
 -- Lock before sampling database clock; never accept caller-controlled time.
 n := floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF n < a.last_epoch THEN RAISE EXCEPTION 'APPROVAL_CLOCK_ROLLBACK'; END IF;
 UPDATE naruv_approval_lab.actors SET last_epoch=n WHERE login_role=session_user;
 a.last_epoch := n;
 RETURN a;
END $$;
CREATE FUNCTION naruv_approval_lab.check_target(p_org text,p_source text,p_entity text,p_snapshot text)
 RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE h text;
BEGIN
 SELECT snapshot_sha256 INTO h FROM naruv_approval_lab.targets
  WHERE organization_id=p_org AND source_id=p_source AND entity=p_entity FOR UPDATE;
 IF NOT FOUND OR h IS DISTINCT FROM p_snapshot THEN
   RAISE EXCEPTION 'APPROVAL_TARGET_CHANGED';
 END IF;
END $$;
CREATE FUNCTION naruv_approval_lab.issue(p_org text,p_id text,p_source text,p_entity text,
 p_preflight text,p_rows text,p_snapshot text,p_confirmed boolean,p_ttl integer)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors; old naruv_approval_lab.approvals;
BEGIN
 a:=naruv_approval_lab.lock_actor('approve');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'APPROVAL_SCOPE'; END IF;
 IF p_confirmed IS DISTINCT FROM true THEN RAISE EXCEPTION 'APPROVAL_EXPLICIT_CONFIRMATION_REQUIRED'; END IF;
 IF p_ttl IS NULL OR p_ttl NOT BETWEEN 1 AND 900 THEN RAISE EXCEPTION 'APPROVAL_TTL'; END IF;
 IF p_id IS NULL OR p_id !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$' OR
    p_preflight IS NULL OR p_preflight !~ '^[a-f0-9]{64}$' OR
    p_rows IS NULL OR p_rows !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'APPROVAL_INPUT'; END IF;
 PERFORM naruv_approval_lab.check_target(p_org,p_source,p_entity,p_snapshot);
 SELECT * INTO old FROM naruv_approval_lab.approvals WHERE organization_id=p_org AND approval_id=p_id;
 IF FOUND THEN
   IF old.status <> 'APPROVED' THEN RAISE EXCEPTION 'APPROVAL_TERMINAL'; END IF;
   IF a.last_epoch >= old.expires_at THEN RAISE EXCEPTION 'APPROVAL_EXPIRED'; END IF;
   IF (old.source_id,old.entity,old.preflight_sha256,old.rows_sha256,old.snapshot_sha256,
       old.actor_id,old.permission_revision,old.expires_at-old.issued_at)
      IS DISTINCT FROM (p_source,p_entity,p_preflight,p_rows,p_snapshot,a.actor_id,a.permission_revision,p_ttl::bigint)
      THEN RAISE EXCEPTION 'APPROVAL_ID_CONFLICT'; END IF;
   RETURN 'ALREADY_APPROVED';
 END IF;
 IF EXISTS(SELECT 1 FROM naruv_approval_lab.approvals WHERE organization_id=p_org
          AND source_id=p_source AND entity=p_entity AND rows_sha256=p_rows)
 THEN RAISE EXCEPTION 'APPROVAL_CONTENT_ALREADY_REGISTERED'; END IF;
 IF (SELECT count(*) FROM naruv_approval_lab.approvals WHERE organization_id=p_org)>=1000
 THEN RAISE EXCEPTION 'APPROVAL_CAPACITY'; END IF;
 INSERT INTO naruv_approval_lab.approvals(organization_id,approval_id,source_id,entity,
   preflight_sha256,rows_sha256,snapshot_sha256,actor_id,permission_revision,issued_at,expires_at)
 VALUES(p_org,p_id,p_source,p_entity,p_preflight,p_rows,p_snapshot,a.actor_id,a.permission_revision,
   a.last_epoch,a.last_epoch+p_ttl);
 RETURN 'APPROVED';
END $$;
CREATE FUNCTION naruv_approval_lab.reserve(p_org text,p_id text,p_reservation text,p_source text,
 p_entity text,p_preflight text,p_rows text,p_snapshot text)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors; old naruv_approval_lab.approvals;
BEGIN
 a:=naruv_approval_lab.lock_actor('reserve');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'APPROVAL_SCOPE'; END IF;
 IF p_reservation IS NULL OR p_reservation !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
 THEN RAISE EXCEPTION 'APPROVAL_INPUT'; END IF;
 PERFORM naruv_approval_lab.check_target(p_org,p_source,p_entity,p_snapshot);
 SELECT * INTO old FROM naruv_approval_lab.approvals WHERE organization_id=p_org AND approval_id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'APPROVAL_NOT_FOUND'; END IF;
 IF old.status <> 'APPROVED' THEN RAISE EXCEPTION 'APPROVAL_TERMINAL'; END IF;
 IF a.last_epoch >= old.expires_at THEN RAISE EXCEPTION 'APPROVAL_EXPIRED'; END IF;
 IF (old.actor_id,old.permission_revision) IS DISTINCT FROM (a.actor_id,a.permission_revision)
 THEN RAISE EXCEPTION 'APPROVAL_ACTOR_CHANGED'; END IF;
 IF (old.source_id,old.entity,old.preflight_sha256,old.rows_sha256,old.snapshot_sha256)
 IS DISTINCT FROM (p_source,p_entity,p_preflight,p_rows,p_snapshot)
 THEN RAISE EXCEPTION 'APPROVAL_BINDING_CHANGED'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_approval_lab.approvals WHERE organization_id=p_org AND reservation_id=p_reservation)
 THEN RAISE EXCEPTION 'APPROVAL_RESERVATION_ID_CONFLICT'; END IF;
 UPDATE naruv_approval_lab.approvals SET status='RESERVED',reservation_id=p_reservation
 WHERE organization_id=p_org AND approval_id=p_id;
 RETURN 'RESERVED';
END $$;
CREATE FUNCTION naruv_approval_lab.revoke(p_org text,p_id text)
 RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors; old naruv_approval_lab.approvals;
BEGIN
 a:=naruv_approval_lab.lock_actor('approve');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'APPROVAL_SCOPE'; END IF;
 SELECT * INTO old FROM naruv_approval_lab.approvals WHERE organization_id=p_org AND approval_id=p_id FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'APPROVAL_NOT_FOUND'; END IF;
 IF old.status <> 'APPROVED' THEN RAISE EXCEPTION 'APPROVAL_TERMINAL'; END IF;
 IF a.last_epoch >= old.expires_at THEN RAISE EXCEPTION 'APPROVAL_EXPIRED'; END IF;
 IF old.actor_id IS DISTINCT FROM a.actor_id THEN RAISE EXCEPTION 'APPROVAL_ACTOR_CHANGED'; END IF;
 UPDATE naruv_approval_lab.approvals SET status='REVOKED' WHERE organization_id=p_org AND approval_id=p_id;
 RETURN 'REVOKED';
END $$;
CREATE FUNCTION naruv_approval_lab.inspect(p_org text,p_id text)
 RETURNS TABLE(status text,reservation_id text,row_import_authorized boolean)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a naruv_approval_lab.actors;
BEGIN
 a:=naruv_approval_lab.lock_actor('inspect');
 IF p_org IS DISTINCT FROM a.organization_id THEN RAISE EXCEPTION 'APPROVAL_SCOPE'; END IF;
 RETURN QUERY SELECT t.status,t.reservation_id,t.row_import_authorized
 FROM naruv_approval_lab.approvals t WHERE t.organization_id=p_org AND t.approval_id=p_id;
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_approval_lab FROM PUBLIC;
GRANT EXECUTE ON FUNCTION naruv_approval_lab.issue(text,text,text,text,text,text,text,boolean,integer),
 naruv_approval_lab.reserve(text,text,text,text,text,text,text,text),
 naruv_approval_lab.revoke(text,text),naruv_approval_lab.inspect(text,text)
 TO naruv_lab_a,naruv_lab_b;
RESET ROLE;
