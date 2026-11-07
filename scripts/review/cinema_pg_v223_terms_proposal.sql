-- V22.3 PROPOSAL (NOT APPLIED to any Supabase project): order due date, invoice pay-by date and
-- payment note, as SIDE TABLES so that no audited engine table, trigger or SECURITY DEFINER function
-- (and therefore no existing result JSON shape and no pinned blob) is changed.
--
-- Run only on a disposable database that already has scripts/review/cinema_pg_write_engine.sql
-- installed, or - after separate owner approval - on the development schema in one transaction.
-- Same privilege pattern as the engine: tables and functions owned by jw_cinema_owner,
-- SECURITY DEFINER with search_path=pg_catalog, writes only through the functions, writer role
-- has SELECT only, FORCE ROW LEVEL SECURITY keyed on the session organisation.
BEGIN;
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
GRANT CREATE ON SCHEMA jw_dev TO jw_cinema_owner;
SET LOCAL ROLE jw_cinema_owner;

-- ------------------------------------------------------------------ tables (append-only)
CREATE TABLE jw_dev.cinema_pg_order_terms(
  org_id text NOT NULL, order_id text NOT NULL,
  due_date date NOT NULL,
  set_by text NOT NULL, set_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(org_id,order_id),
  FOREIGN KEY(org_id,order_id) REFERENCES jw_dev.cinema_pg_orders(org_id,id)
);
CREATE TABLE jw_dev.cinema_pg_invoice_terms(
  org_id text NOT NULL, invoice_id text NOT NULL,
  pay_by date NOT NULL,
  set_by text NOT NULL, set_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(org_id,invoice_id),
  FOREIGN KEY(org_id,invoice_id) REFERENCES jw_dev.cinema_pg_invoices(org_id,id)
);
CREATE TABLE jw_dev.cinema_pg_payment_notes(
  org_id text NOT NULL, payment_id text NOT NULL,
  note text NOT NULL CHECK(length(btrim(note)) BETWEEN 1 AND 500),
  set_by text NOT NULL, set_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(org_id,payment_id),
  FOREIGN KEY(org_id,payment_id) REFERENCES jw_dev.cinema_pg_payments(org_id,id)
);

DO $t$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cinema_pg_order_terms','cinema_pg_invoice_terms','cinema_pg_payment_notes'] LOOP
    EXECUTE format('CREATE TRIGGER t_%s_append_only BEFORE UPDATE OR DELETE ON jw_dev.%I
                    FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_deny_change()', t, t);
    EXECUTE format('ALTER TABLE jw_dev.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE jw_dev.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON jw_dev.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY %I ON jw_dev.%I FOR ALL TO jw_cinema_owner
        USING(org_id=jw_dev.current_org_from_session())
        WITH CHECK(org_id=jw_dev.current_org_from_session())', 'p_owner_'||t, t);
    EXECUTE format('GRANT SELECT ON jw_dev.%I TO jw_cinema_writer', t);
    EXECUTE format('CREATE POLICY %I ON jw_dev.%I FOR SELECT TO jw_cinema_writer
        USING(org_id=jw_dev.current_org_from_session())', 'p_writer_'||t, t);
  END LOOP;
END $t$;

-- ------------------------------------------------------------------------- functions
-- Order delivery due date: same admin gate as cinema_pg_order_create, set once, not in the past
-- (the legacy rule), only while the order is open.
CREATE FUNCTION jw_dev.cinema_pg_order_terms_set(p_request_id text, p_order_id text, p_due_date date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; o record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'order_terms_set',
     jsonb_build_object('order',p_order_id,'due',p_due_date));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jsonb_build_object('replayed',true,'order_id',p_order_id,'due_date',p_due_date);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  IF p_due_date IS NULL OR p_due_date < current_date THEN
    RAISE EXCEPTION 'due date must be today or later' USING ERRCODE='23514';
  END IF;
  SELECT * INTO o FROM jw_dev.cinema_pg_orders WHERE org_id=c.o_org AND id=p_order_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'order not found' USING ERRCODE='P0002'; END IF;
  IF o.status<>'open' THEN
    RAISE EXCEPTION 'order is not open' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_order_terms WHERE org_id=c.o_org AND order_id=o.id;
  IF FOUND THEN
    RAISE EXCEPTION 'due date is already set for this order' USING ERRCODE='23505';
  END IF;
  INSERT INTO jw_dev.cinema_pg_order_terms(org_id,order_id,due_date,set_by)
  VALUES (c.o_org,o.id,p_due_date,c.o_actor);
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'order',o.id,o.trade_no,'due_date_set',
          jsonb_build_object('due_date',p_due_date),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'order_terms',o.id);
  RETURN jsonb_build_object('replayed',false,'order_id',o.id,'due_date',p_due_date);
END $$;

-- Invoice pay-by date (legacy "payment due"): while the invoice is still a draft or reviewed one,
-- set once, not in the past, by an administrator or the person who created the invoice.
CREATE FUNCTION jw_dev.cinema_pg_invoice_terms_set(p_request_id text, p_invoice_id text, p_pay_by date)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; i record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'invoice_terms_set',
     jsonb_build_object('invoice',p_invoice_id,'pay_by',p_pay_by));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jsonb_build_object('replayed',true,'invoice_id',p_invoice_id,'pay_by',p_pay_by);
  END IF;
  IF p_pay_by IS NULL OR p_pay_by < current_date THEN
    RAISE EXCEPTION 'pay-by date must be today or later' USING ERRCODE='23514';
  END IF;
  SELECT * INTO i FROM jw_dev.cinema_pg_invoices WHERE org_id=c.o_org AND id=p_invoice_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'invoice not found' USING ERRCODE='P0002'; END IF;
  IF c.o_role IS DISTINCT FROM 'admin' AND i.created_by IS DISTINCT FROM c.o_actor THEN
    RAISE EXCEPTION 'only an administrator or the invoice creator can set the pay-by date' USING ERRCODE='42501';
  END IF;
  IF i.status NOT IN ('draft','reviewed') THEN
    RAISE EXCEPTION 'pay-by date can only be set before the invoice is confirmed' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_invoice_terms WHERE org_id=c.o_org AND invoice_id=i.id;
  IF FOUND THEN
    RAISE EXCEPTION 'pay-by date is already set for this invoice' USING ERRCODE='23505';
  END IF;
  INSERT INTO jw_dev.cinema_pg_invoice_terms(org_id,invoice_id,pay_by,set_by)
  VALUES (c.o_org,i.id,p_pay_by,c.o_actor);
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'invoice',i.id,i.trade_no,'pay_by_set',
          jsonb_build_object('pay_by',p_pay_by),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'invoice_terms',i.id);
  RETURN jsonb_build_object('replayed',false,'invoice_id',i.id,'pay_by',p_pay_by);
END $$;

-- Payment note: only by the administrator who recorded the payment, once, and not on a reversed one.
CREATE FUNCTION jw_dev.cinema_pg_payment_note_set(p_request_id text, p_payment_id text, p_note text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; p record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'payment_note_set',
     jsonb_build_object('payment',p_payment_id,'note',p_note));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jsonb_build_object('replayed',true,'payment_id',p_payment_id);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  IF p_note IS NULL OR length(btrim(p_note)) NOT BETWEEN 1 AND 500 THEN
    RAISE EXCEPTION 'note must be 1..500 characters' USING ERRCODE='23514';
  END IF;
  SELECT * INTO p FROM jw_dev.cinema_pg_payments WHERE org_id=c.o_org AND id=p_payment_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'payment not found' USING ERRCODE='P0002'; END IF;
  IF p.recorded_by IS DISTINCT FROM c.o_actor THEN
    RAISE EXCEPTION 'only the person who recorded the payment can add its note' USING ERRCODE='42501';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_payment_reversals WHERE org_id=c.o_org AND payment_id=p.id;
  IF FOUND THEN
    RAISE EXCEPTION 'payment is already reversed' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_payment_notes WHERE org_id=c.o_org AND payment_id=p.id;
  IF FOUND THEN
    RAISE EXCEPTION 'a note is already set for this payment' USING ERRCODE='23505';
  END IF;
  INSERT INTO jw_dev.cinema_pg_payment_notes(org_id,payment_id,note,set_by)
  VALUES (c.o_org,p.id,btrim(p_note),c.o_actor);
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'payment',p.id,p.trade_no,'note_set',
          jsonb_build_object('length',length(btrim(p_note))),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'payment_notes',p.id);
  RETURN jsonb_build_object('replayed',false,'payment_id',p.id);
END $$;

-- ---------------------------------------------------------------------------- privileges
-- Important: run REVOKE as function OWNER (jw_cinema_owner), not Supabase's
-- non-superuser postgres. The former script RESET ROLE before this DO block,
-- silently retaining PUBLIC EXECUTE. Detected by live development-DB audit.
DO $g$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig, p.proname
             FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='jw_dev'
              AND p.proname IN ('cinema_pg_order_terms_set','cinema_pg_invoice_terms_set','cinema_pg_payment_note_set')
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO jw_cinema_owner, jw_cinema_writer', f.sig);
  END LOOP;
END $g$;
RESET ROLE;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_cinema_owner;
REVOKE jw_cinema_owner FROM CURRENT_USER;
DO $acl_guard$
DECLARE n integer; safe integer;
BEGIN
 SELECT count(*), count(*) FILTER (
   WHERE NOT has_function_privilege('public',p.oid,'EXECUTE')
     AND NOT has_function_privilege('anon',p.oid,'EXECUTE')
     AND NOT has_function_privilege('authenticated',p.oid,'EXECUTE')
     AND has_function_privilege('jw_cinema_writer',p.oid,'EXECUTE')
     AND pg_get_userbyid(p.proowner)='jw_cinema_owner'
     AND p.prosecdef AND p.proconfig @> ARRAY['search_path=pg_catalog'])
 INTO n,safe
 FROM pg_proc p JOIN pg_namespace ns ON ns.oid=p.pronamespace
 WHERE ns.nspname='jw_dev'
 AND p.proname IN ('cinema_pg_order_terms_set','cinema_pg_invoice_terms_set','cinema_pg_payment_note_set');
 IF n<>3 OR safe<>3 THEN
   RAISE EXCEPTION 'V22.3 B security ACL verification failed; entire terms transaction rolled back';
 END IF;
END $acl_guard$;
COMMIT;
