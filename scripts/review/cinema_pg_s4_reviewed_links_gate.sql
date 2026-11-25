-- S4 reviewed historical links. Disposable PostgreSQL 17 CI ONLY.
-- Standalone fixture on ci_v90 + ci_v92 + CINEMA engine; deliberately separate
-- from s4_atomic_gate.sql: that clean-install guard forbids pre-existing
-- historical dual-ledger rows. NO persistent DB migration is authorised.
DO $pre$
DECLARE is_super boolean;
BEGIN
  SELECT rolsuper INTO is_super FROM pg_catalog.pg_roles WHERE rolname=current_user;
  IF current_database() !~ '^jw_cinema_s4_link_[0-9a-f]{8}$'
     OR is_super IS DISTINCT FROM TRUE
     OR to_regclass('jw_dev.quotes') IS NULL
     OR to_regclass('jw_dev.cinema_pg_quotes') IS NULL THEN
    RAISE EXCEPTION 'S4 historical audit allowed only in fresh disposable PG17'
      USING ERRCODE='42501';
  END IF;
  IF to_regclass('jw_dev.cinema_pg_s4_reviewed_links') IS NOT NULL THEN
    RAISE EXCEPTION 'S4 historical audit already installed' USING ERRCODE='23505';
  END IF;
END $pre$;

-- Read-only privilege is granted solely to the NEW NOLOGIN owner and strictly
-- tenant-scoped by FORCE RLS. Do not relax any pre-existing v92 policy/ACL.
GRANT SELECT ON jw_dev.customers,jw_dev.quotes,jw_dev.quote_items TO jw_cinema_owner;
CREATE POLICY s4_reconcile_legacy_customers
 ON jw_dev.customers FOR SELECT TO jw_cinema_owner
 USING (org_id=jw_dev.current_org_from_session());
CREATE POLICY s4_reconcile_legacy_quotes
 ON jw_dev.quotes FOR SELECT TO jw_cinema_owner
 USING (org_id=jw_dev.current_org_from_session());
CREATE POLICY s4_reconcile_legacy_lines
 ON jw_dev.quote_items FOR SELECT TO jw_cinema_owner
 USING(EXISTS(SELECT 1 FROM jw_dev.quotes q WHERE q.id=quote_id
              AND q.org_id=jw_dev.current_org_from_session()));
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
GRANT CREATE ON SCHEMA jw_dev TO jw_cinema_owner;
SET LOCAL ROLE jw_cinema_owner;

CREATE TABLE jw_dev.cinema_pg_s4_reviewed_links (
  org_id text NOT NULL,
  legacy_quote_id text NOT NULL,
  cinema_quote_id text NOT NULL,
  legacy_sha256 text NOT NULL CHECK(legacy_sha256 ~ '^[0-9a-f]{64}$'),
  cinema_sha256 text NOT NULL CHECK(cinema_sha256 ~ '^[0-9a-f]{64}$'),
  approved_by text NOT NULL,
  approved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  audit_reference text NOT NULL CHECK(length(btrim(audit_reference)) BETWEEN 12 AND 160),
  request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._:-]{8,128}$'),
  PRIMARY KEY(org_id,legacy_quote_id),
  UNIQUE(org_id,cinema_quote_id),
  UNIQUE(org_id,request_id)
);
ALTER TABLE jw_dev.cinema_pg_s4_reviewed_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE jw_dev.cinema_pg_s4_reviewed_links FORCE ROW LEVEL SECURITY;
CREATE POLICY s4_review_owner ON jw_dev.cinema_pg_s4_reviewed_links FOR ALL
 TO jw_cinema_owner
 USING(org_id=jw_dev.current_org_from_session())
 WITH CHECK(org_id=jw_dev.current_org_from_session());
REVOKE ALL ON jw_dev.cinema_pg_s4_reviewed_links FROM PUBLIC,jw_cinema_writer,jw_app_dev,anon,authenticated;
CREATE TRIGGER s4_review_immutable
 BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_s4_reviewed_links
 FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_deny_change();

-- Construct canonical, server-sourced snapshots: client supplies ONLY IDs.
-- The original document numbers differ by design, so they are hashed into
-- independent source digests, never used as identity/matching evidence.
CREATE FUNCTION jw_dev.cinema_pg_s4_legacy_snapshot(p_org text,p_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog AS $s$
 SELECT jsonb_build_object(
  'org',q.org_id,'id',q.id,'document',q.doc_no,
  'business',regexp_replace(c.business_number,'[^0-9]','','g'),
  'vat',q.vat_mode,'status',q.status,
  'lines',(SELECT jsonb_agg(jsonb_build_array(li.name,li.quantity,li.unit_price)
                    ORDER BY li.name,li.quantity,li.unit_price)
           FROM jw_dev.quote_items li WHERE li.quote_id=q.id),
  'subtotal',(SELECT sum(li.quantity::numeric*li.unit_price::numeric)
              FROM jw_dev.quote_items li WHERE li.quote_id=q.id))
 FROM jw_dev.quotes q
 JOIN jw_dev.customers c ON c.id=q.customer_id AND c.org_id=q.org_id
 WHERE q.org_id=p_org AND q.id=p_id
$s$;
CREATE FUNCTION jw_dev.cinema_pg_s4_cinema_snapshot(p_org text,p_id text)
RETURNS jsonb LANGUAGE sql STABLE SET search_path=pg_catalog AS $s$
 SELECT jsonb_build_object(
  'org',q.org_id,'id',q.id,'document',q.trade_no,
  'business',p.business_number,
  'vat',q.vat_mode,'status',q.status,
  'lines',(SELECT jsonb_agg(jsonb_build_array(li.name,li.quantity,li.unit_price)
                    ORDER BY li.name,li.quantity,li.unit_price)
           FROM jw_dev.cinema_pg_quote_items li
           WHERE li.quote_id=q.id AND li.org_id=q.org_id),
  'subtotal',(SELECT sum(li.quantity::numeric*li.unit_price::numeric)
              FROM jw_dev.cinema_pg_quote_items li
              WHERE li.quote_id=q.id AND li.org_id=q.org_id))
 FROM jw_dev.cinema_pg_quotes q
 JOIN jw_dev.cinema_pg_partners p ON p.id=q.partner_id AND p.org_id=q.org_id
 WHERE q.org_id=p_org AND q.id=p_id
$s$;
REVOKE ALL ON FUNCTION jw_dev.cinema_pg_s4_legacy_snapshot(text,text),
 jw_dev.cinema_pg_s4_cinema_snapshot(text,text)
 FROM PUBLIC,jw_app_dev,jw_cinema_writer,anon,authenticated;

-- Access requires database-verified admin role, and server-computed
-- SHA-256 for BOTH source documents. No user-supplied digest/organization.
CREATE FUNCTION jw_dev.cinema_pg_s4_link_approve(
 p_request text,p_legacy text,p_cinema text,p_reference text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE a text; o text; r text; old_doc jsonb; new_doc jsonb;
 h_old text; h_new text; inserted integer; prior record; author text;
BEGIN
 SELECT actor_id,org_id,actor_role INTO a,o,r
 FROM jw_dev.stage_identity_v84();
 IF o IS NULL OR r IS DISTINCT FROM 'admin' THEN
   RAISE EXCEPTION 'verified administrator session required' USING ERRCODE='42501';
 END IF;
 IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9._:-]{8,128}$'
 OR p_legacy IS NULL OR length(p_legacy) NOT BETWEEN 1 AND 128
 OR p_cinema IS NULL OR length(p_cinema) NOT BETWEEN 1 AND 128
 OR p_reference IS NULL OR length(btrim(p_reference)) NOT BETWEEN 12 AND 160 THEN
   RAISE EXCEPTION 'invalid reconciliation request' USING ERRCODE='23514';
 END IF;
 old_doc := jw_dev.cinema_pg_s4_legacy_snapshot(o,p_legacy);
 new_doc := jw_dev.cinema_pg_s4_cinema_snapshot(o,p_cinema);
 IF old_doc IS NULL OR new_doc IS NULL THEN
   RAISE EXCEPTION 'source quote not available in caller tenant' USING ERRCODE='42501';
 END IF;
 SELECT q.created_by INTO author FROM jw_dev.cinema_pg_quotes q
 WHERE q.org_id=o AND q.id=p_cinema;
 IF author IS NULL OR author=a THEN
   RAISE EXCEPTION 'independent administrator approval required' USING ERRCODE='42501';
 END IF;
 IF old_doc->>'status' NOT IN ('approved','ordered','confirmed')
    OR new_doc->>'status' NOT IN ('approved','ordered')
    OR old_doc->>'business' !~ '^[0-9]{10}$'
    OR new_doc->>'business' !~ '^[0-9]{10}$'
    OR old_doc->>'business' IS DISTINCT FROM new_doc->>'business'
    OR old_doc->>'vat' IS DISTINCT FROM new_doc->>'vat'
    OR old_doc->'lines' IS NULL OR jsonb_typeof(old_doc->'lines') <> 'array'
    OR new_doc->'lines' IS NULL OR jsonb_typeof(new_doc->'lines') <> 'array'
    OR jsonb_array_length(old_doc->'lines') < 1
    OR old_doc->'lines' IS DISTINCT FROM new_doc->'lines'
    OR old_doc->'subtotal' IS DISTINCT FROM new_doc->'subtotal'
    OR (old_doc->>'subtotal')::numeric <= 0 THEN
   RAISE EXCEPTION 'source lines, business identity, VAT or state differ'
     USING ERRCODE='23514';
 END IF;
 h_old := encode(sha256(convert_to(old_doc::text,'UTF8')),'hex');
 h_new := encode(sha256(convert_to(new_doc::text,'UTF8')),'hex');
 INSERT INTO jw_dev.cinema_pg_s4_reviewed_links
 (org_id,legacy_quote_id,cinema_quote_id,legacy_sha256,cinema_sha256,approved_by,audit_reference,request_id)
 VALUES(o,p_legacy,p_cinema,h_old,h_new,a,p_reference,p_request)
 ON CONFLICT DO NOTHING;
 GET DIAGNOSTICS inserted = ROW_COUNT;
 IF inserted=0 THEN
   SELECT * INTO prior FROM jw_dev.cinema_pg_s4_reviewed_links x
    WHERE x.org_id=o AND x.legacy_quote_id=p_legacy;
   IF prior.legacy_quote_id IS NULL OR prior.cinema_quote_id IS DISTINCT FROM p_cinema
     OR prior.request_id IS DISTINCT FROM p_request
     OR prior.legacy_sha256 IS DISTINCT FROM h_old OR prior.cinema_sha256 IS DISTINCT FROM h_new
     OR prior.approved_by IS DISTINCT FROM a
     OR prior.audit_reference IS DISTINCT FROM p_reference THEN
      RAISE EXCEPTION 'reconciliation key has been used' USING ERRCODE='23505';
   END IF;
 END IF;
 -- Same-transaction append-only audit, actor obtained from verified session.
 -- An audit insertion failure rolls back the link as well.
 IF inserted=1 THEN
  PERFORM jw_dev.cinema_pg_audit_add(o,a,'s4_reconciliation',p_cinema,NULL,
   'historical_link_reviewed',
   jsonb_build_object('legacy',p_legacy,'legacy_sha',h_old,'cinema_sha',h_new,
                      'review_reference',p_reference),p_request);
 END IF;
 RETURN jsonb_build_object('org',o,'legacy',p_legacy,'cinema',p_cinema,
                           'approved_by',a,'replayed',inserted=0);
END $f$;

-- Never add legacy + CINEMA totals. Use CINEMA as the sole value source after
-- ALL historical links are approved, complete, unmodified and still valid.
-- This is an isolated audit calculation, not the production accounting API.
CREATE FUNCTION jw_dev.cinema_pg_s4_single_source_total()
RETURNS numeric LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $f$
DECLARE a text; o text; r text; total numeric:=0; n_old integer; n_new integer;
 n_link integer; x record; old_doc jsonb; new_doc jsonb;
BEGIN
 SELECT actor_id,org_id,actor_role INTO a,o,r FROM jw_dev.stage_identity_v84();
 IF o IS NULL OR r IS DISTINCT FROM 'admin' THEN
  RAISE EXCEPTION 'verified administrator session required' USING ERRCODE='42501';
 END IF;
 SELECT count(*) INTO n_old FROM jw_dev.quotes WHERE org_id=o;
 SELECT count(*) INTO n_new FROM jw_dev.cinema_pg_quotes WHERE org_id=o;
 SELECT count(*) INTO n_link FROM jw_dev.cinema_pg_s4_reviewed_links WHERE org_id=o;
 IF n_link=0 OR n_link<>n_old OR n_link<>n_new THEN
  RAISE EXCEPTION 'unlinked or incomplete original ledger' USING ERRCODE='23514';
 END IF;
 FOR x IN SELECT * FROM jw_dev.cinema_pg_s4_reviewed_links WHERE org_id=o LOOP
  old_doc:=jw_dev.cinema_pg_s4_legacy_snapshot(o,x.legacy_quote_id);
  new_doc:=jw_dev.cinema_pg_s4_cinema_snapshot(o,x.cinema_quote_id);
  IF old_doc IS NULL OR new_doc IS NULL
   OR encode(sha256(convert_to(old_doc::text,'UTF8')),'hex') IS DISTINCT FROM x.legacy_sha256
   OR encode(sha256(convert_to(new_doc::text,'UTF8')),'hex') IS DISTINCT FROM x.cinema_sha256 THEN
   RAISE EXCEPTION 'reconciled source changed after approval' USING ERRCODE='23514';
  END IF;
  total:=total+(new_doc->>'subtotal')::numeric;
 END LOOP;
 RETURN total;
END $f$;
REVOKE ALL ON FUNCTION jw_dev.cinema_pg_s4_link_approve(text,text,text,text),
 jw_dev.cinema_pg_s4_single_source_total()
 FROM PUBLIC,anon,authenticated,jw_app_dev;
GRANT EXECUTE ON FUNCTION jw_dev.cinema_pg_s4_link_approve(text,text,text,text),
 jw_dev.cinema_pg_s4_single_source_total() TO jw_cinema_writer;
RESET ROLE;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_cinema_owner;
REVOKE jw_cinema_owner FROM CURRENT_USER;
