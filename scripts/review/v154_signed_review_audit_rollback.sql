-- V15.4 real restricted-role audit append integrity check (TEST ONLY).
-- Requires the v151/v152 ledger, v153 policy, A/B/member fixtures in SAME
-- BEGIN transaction; review DDL & all synthetic rows MUST be ROLLBACKed.
SET LOCAL ROLE jw_app_dev;
SELECT pg_catalog.set_config('jw.session_hash','jw-v153-a',true);
INSERT INTO jw_dev.audit_logs
 (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
 VALUES(repeat('f',32),repeat('a',32),repeat('3',32),'delivery_review',
  repeat('c',32),'request',
  '{"source":"v154_signed_delivery_pending_review","source_sha256":"111111","evidence_sha256":"222222"}',
  now()::text);
DO $tenant_audit$
DECLARE blocked boolean:=false;
BEGIN
 BEGIN
  INSERT INTO jw_dev.audit_logs
   (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
   VALUES(repeat('0',32),repeat('b',32),repeat('3',32),'delivery_review',
          repeat('c',32),'request','{}',now()::text);
 EXCEPTION WHEN insufficient_privilege OR foreign_key_violation OR check_violation THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL_V154_FOREIGN_TENANT_AUDIT_INSERT'; END IF;
 blocked:=false;
 BEGIN
  INSERT INTO jw_dev.audit_logs
   (id,org_id,actor_id,entity_type,entity_id,action,detail,created_at)
   VALUES(repeat('0',32),repeat('a',32),repeat('4',32),'delivery_review',
          repeat('c',32),'request','{}',now()::text);
 EXCEPTION WHEN insufficient_privilege OR foreign_key_violation OR check_violation THEN blocked:=true;
 END;
 IF NOT blocked THEN RAISE EXCEPTION 'FAIL_V154_FOREIGN_ACTOR_AUDIT_INSERT'; END IF;
END $tenant_audit$;
RESET ROLE;
DO $owner_check$
BEGIN
 IF (SELECT count(*) FROM jw_dev.audit_logs WHERE id=repeat('f',32))<>1
 OR (SELECT count(*) FROM jw_dev.audit_logs WHERE id=repeat('0',32))<>0
 THEN RAISE EXCEPTION 'FAIL_V154_AUDIT_NOT_ATOMIC_OR_CROSS_TENANT'; END IF;
END $owner_check$;
