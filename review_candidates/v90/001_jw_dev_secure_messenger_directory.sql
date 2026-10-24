-- V9.0 review candidate only. Apply to existing jw_dev V8.8+ staging schema.
-- Supabase dev was already migrated and tested separately on 2026-10-23.
-- This is not a standalone bootstrap migration and must not be deployed to production.
BEGIN;
CREATE OR REPLACE FUNCTION jw_dev.search_messenger_companies_v90(
  p_query text DEFAULT '', p_limit integer DEFAULT 30, p_offset integer DEFAULT 0)
RETURNS TABLE(org_id text, company_name text)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog
AS $fn$
DECLARE v_org text; v_q text; v_pattern text;
BEGIN
  v_org:=jw_dev.current_org_from_session();
  IF v_org IS NULL OR NOT EXISTS(
    SELECT 1 FROM jw_dev.messenger_companies mc WHERE mc.org_id=v_org
  ) THEN
    RAISE EXCEPTION 'Verified company session required' USING ERRCODE='42501';
  END IF;
  IF p_query IS NULL OR length(p_query)>80 OR p_limit IS NULL
     OR p_limit NOT BETWEEN 1 AND 50 OR p_offset IS NULL
     OR p_offset NOT BETWEEN 0 AND 100000 THEN
    RAISE EXCEPTION 'Invalid directory search request' USING ERRCODE='23514';
  END IF;
  v_q:=lower(btrim(p_query));
  v_pattern:='%'||replace(replace(replace(v_q,chr(92),chr(92)||chr(92)),
    '%',chr(92)||'%'),'_',chr(92)||'_')||'%';
  RETURN QUERY SELECT o.id,o.name
    FROM jw_dev.messenger_companies m
    JOIN jw_dev.organizations o ON o.id=m.org_id
    WHERE m.org_id<>v_org
      AND (v_q='' OR lower(o.name) LIKE v_pattern ESCAPE E'\\'
         OR m.business_number LIKE v_pattern ESCAPE E'\\')
    ORDER BY lower(o.name),o.id LIMIT p_limit OFFSET p_offset;
END $fn$;
REVOKE ALL ON FUNCTION jw_dev.search_messenger_companies_v90(text,integer,integer)
  FROM PUBLIC,anon,authenticated,service_role;
GRANT EXECUTE ON FUNCTION jw_dev.search_messenger_companies_v90(text,integer,integer)
  TO jw_app_dev;
COMMIT;
