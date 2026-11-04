-- CINEMA PostgreSQL trade write engine (review candidate, additive only).
--
-- NEVER auto-apply to Supabase or any persistent database. Apply only to a
-- disposable/dev instance after review. Existing tables, constraints, policies
-- and data are NOT modified. Required ACL additions to EXISTING objects are
-- limited to (same precedent as v159): USAGE on schema jw_dev and EXECUTE on
-- the three identity functions, granted to the NEW roles below.
--
-- Chain: partner -> quote -> order -> delivery -> statement -> invoice -> payment
--
-- Security model
--   * jw_cinema_owner  (NOLOGIN, NOBYPASSRLS) owns every new table/function.
--     FORCE ROW LEVEL SECURITY applies to it, so SECURITY DEFINER functions are
--     still bound to the session tenant.
--   * jw_cinema_writer (NOLOGIN, NOBYPASSRLS) is the role the adapter's separate
--     login must be able to SET ROLE to. It can only SELECT tenant rows and
--     EXECUTE the public API functions; it cannot INSERT/UPDATE/DELETE directly.
--   * Tenant and actor come from jw_dev.stage_identity_v84() (session hash GUC),
--     never from arguments.
--   * All money is integer KRW. VAT = (subtotal+5)/10 for taxable, else 0
--     (identical to the existing quote/invoice-preview rule).
--
-- Honesty limits encoded in the schema
--   * A "confirmed" delivery means an admin, different from the recorder, OPENED the
--     evidence file stored on the server (re-hashed by the database, size/type/magic-byte
--     checked, tenant-scoped, append-only) and attested it. The database still cannot verify
--     that physical goods were handed over.
--   * A payment is an INTERNAL record. bank_confirmed is CHECK-pinned to false.
--
-- Error codes used by the API functions (adapter maps these):
--   42501 forbidden / no valid session     P0002 not found
--   23514 validation or illegal state      23505 conflict / reused request id
--   40001 stale version or request in flight

DO $pre$
BEGIN
  IF to_regnamespace('jw_dev') IS NULL
     OR to_regprocedure('jw_dev.stage_identity_v84()') IS NULL
     OR to_regprocedure('jw_dev.current_org_from_session()') IS NULL THEN
    RAISE EXCEPTION 'precondition failed: jw_dev schema and session identity functions are required';
  END IF;
  IF to_regclass('jw_dev.cinema_pg_requests') IS NOT NULL THEN
    RAISE EXCEPTION 'cinema_pg engine already installed; use a fresh disposable database';
  END IF;
END $pre$;

DO $roles$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='jw_cinema_owner') THEN
    CREATE ROLE jw_cinema_owner NOLOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='jw_cinema_writer') THEN
    CREATE ROLE jw_cinema_writer NOLOGIN NOINHERIT NOBYPASSRLS NOSUPERUSER;
  END IF;
END $roles$;

GRANT USAGE ON SCHEMA jw_dev TO jw_cinema_owner, jw_cinema_writer;
GRANT EXECUTE ON FUNCTION jw_dev.stage_identity_v84(), jw_dev.current_org_from_session()
  TO jw_cinema_owner, jw_cinema_writer;
-- Supabase managed Postgres is CREATEROLE but not SUPERUSER: it cannot SET
-- ROLE to a newly created owner without an explicit SET membership. Grant it
-- only inside this single migration transaction; remove it before COMMIT.
GRANT jw_cinema_owner TO CURRENT_USER WITH SET TRUE, INHERIT FALSE;
-- Temporary schema CREATE privilege is also revoked before COMMIT.
GRANT CREATE ON SCHEMA jw_dev TO jw_cinema_owner;

SET LOCAL ROLE jw_cinema_owner;

-- ---------------------------------------------------------------- tables
CREATE TABLE jw_dev.cinema_pg_requests(
  org_id text NOT NULL,
  request_id text NOT NULL CHECK(request_id ~ '^[A-Za-z0-9._:-]{8,128}$'),
  op text NOT NULL,
  payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[0-9a-f]{64}$'),
  entity_type text NOT NULL,
  entity_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(org_id,request_id)
);
CREATE TABLE jw_dev.cinema_pg_trade_counters(
  org_id text NOT NULL, day date NOT NULL, last_no integer NOT NULL CHECK(last_no>=1),
  PRIMARY KEY(org_id,day)
);
CREATE TABLE jw_dev.cinema_pg_transitions(
  entity text NOT NULL, from_status text NOT NULL, to_status text NOT NULL,
  PRIMARY KEY(entity,from_status,to_status)
);
INSERT INTO jw_dev.cinema_pg_transitions(entity,from_status,to_status) VALUES
 ('quote','draft','submitted'),('quote','submitted','approved'),
 ('quote','submitted','rejected'),('quote','rejected','draft'),
 ('quote','draft','cancelled'),('quote','submitted','cancelled'),
 ('quote','approved','cancelled'),('quote','approved','ordered'),
 ('order','open','fulfilled'),('order','open','cancelled'),('order','fulfilled','open'),
 ('delivery','recorded','confirmed'),('delivery','recorded','cancelled'),
 ('delivery','confirmed','reversed'),
 ('statement','draft','confirmed'),('statement','draft','voided'),
 ('statement','confirmed','voided'),
 ('invoice','draft','reviewed'),('invoice','reviewed','confirmed'),
 ('invoice','draft','voided'),('invoice','reviewed','voided'),
 ('invoice','confirmed','voided');

CREATE TABLE jw_dev.cinema_pg_audit(
  seq bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id text NOT NULL UNIQUE,
  org_id text NOT NULL, actor_id text NOT NULL,
  entity_type text NOT NULL, entity_id text NOT NULL, trade_no text,
  action text NOT NULL, detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  request_id text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE jw_dev.cinema_pg_partners(
  id text PRIMARY KEY, org_id text NOT NULL,
  name text NOT NULL CHECK(length(btrim(name)) BETWEEN 1 AND 120),
  business_number text NOT NULL DEFAULT '' CHECK(business_number ~ '^([0-9]{10})?$'),
  contact_name text NOT NULL DEFAULT '' CHECK(length(contact_name)<=80),
  email text NOT NULL DEFAULT '' CHECK(length(email)<=254),
  phone text NOT NULL DEFAULT '' CHECK(length(phone)<=40),
  version integer NOT NULL DEFAULT 1 CHECK(version>=1),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(org_id,id)
);
CREATE UNIQUE INDEX cinema_pg_partner_bn_uq ON jw_dev.cinema_pg_partners(org_id,business_number)
  WHERE business_number<>'';

CREATE TABLE jw_dev.cinema_pg_quotes(
  id text PRIMARY KEY, org_id text NOT NULL, trade_no text NOT NULL,
  partner_id text NOT NULL,
  title text NOT NULL CHECK(length(btrim(title)) BETWEEN 1 AND 150),
  status text NOT NULL CHECK(status IN ('draft','submitted','approved','rejected','cancelled','ordered')),
  vat_mode text NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
  version integer NOT NULL DEFAULT 1 CHECK(version>=1),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  submitted_by text, approved_by text, approved_at timestamptz,
  CHECK(status NOT IN ('approved','ordered') OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)),
  UNIQUE(org_id,id), UNIQUE(org_id,trade_no),
  FOREIGN KEY(org_id,partner_id) REFERENCES jw_dev.cinema_pg_partners(org_id,id)
);
CREATE TABLE jw_dev.cinema_pg_quote_items(
  id text PRIMARY KEY, org_id text NOT NULL, quote_id text NOT NULL,
  position integer NOT NULL CHECK(position BETWEEN 0 AND 39),
  name text NOT NULL CHECK(length(btrim(name)) BETWEEN 1 AND 150),
  quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
  unit_price bigint NOT NULL CHECK(unit_price BETWEEN 0 AND 1000000000),
  UNIQUE(org_id,id), UNIQUE(quote_id,position),
  FOREIGN KEY(org_id,quote_id) REFERENCES jw_dev.cinema_pg_quotes(org_id,id)
);

CREATE TABLE jw_dev.cinema_pg_orders(
  id text PRIMARY KEY, org_id text NOT NULL, trade_no text NOT NULL,
  quote_id text NOT NULL, partner_id text NOT NULL,
  vat_mode text NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
  status text NOT NULL CHECK(status IN ('open','fulfilled','cancelled')),
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(org_id,id), UNIQUE(org_id,quote_id), UNIQUE(org_id,trade_no),
  FOREIGN KEY(org_id,quote_id) REFERENCES jw_dev.cinema_pg_quotes(org_id,id),
  FOREIGN KEY(org_id,partner_id) REFERENCES jw_dev.cinema_pg_partners(org_id,id)
);
CREATE TABLE jw_dev.cinema_pg_order_items(
  id text PRIMARY KEY, org_id text NOT NULL, order_id text NOT NULL,
  source_quote_item_id text NOT NULL,
  position integer NOT NULL CHECK(position BETWEEN 0 AND 39),
  name text NOT NULL, quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
  unit_price bigint NOT NULL CHECK(unit_price BETWEEN 0 AND 1000000000),
  UNIQUE(org_id,id), UNIQUE(order_id,position),
  FOREIGN KEY(org_id,order_id) REFERENCES jw_dev.cinema_pg_orders(org_id,id),
  FOREIGN KEY(org_id,source_quote_item_id) REFERENCES jw_dev.cinema_pg_quote_items(org_id,id)
);

-- Delivery evidence stored by the SERVER. The hash is recomputed by PostgreSQL (CHECK), never
-- trusted from the browser. Append-only; content is not readable by the writer role directly.
CREATE TABLE jw_dev.cinema_pg_evidence_files(
  id text PRIMARY KEY, org_id text NOT NULL,
  content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[0-9a-f]{64}$'),
  size_bytes integer NOT NULL CHECK(size_bytes BETWEEN 1 AND 5242880),
  content_type text NOT NULL CHECK(content_type IN ('application/pdf','image/png','image/jpeg')),
  file_name text NOT NULL CHECK(length(btrim(file_name)) BETWEEN 1 AND 180),
  content bytea NOT NULL,
  uploaded_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(octet_length(content)=size_bytes),
  CHECK(content_sha256=encode(sha256(content),'hex')),
  CHECK((content_type='application/pdf' AND substring(content from 1 for 5)='\x255044462d'::bytea)
     OR (content_type='image/png' AND substring(content from 1 for 8)='\x89504e470d0a1a0a'::bytea)
     OR (content_type='image/jpeg' AND substring(content from 1 for 3)='\xffd8ff'::bytea)),
  UNIQUE(org_id,id), UNIQUE(org_id,content_sha256)
);

CREATE TABLE jw_dev.cinema_pg_deliveries(
  id text PRIMARY KEY, org_id text NOT NULL, order_id text NOT NULL, trade_no text NOT NULL,
  seq integer NOT NULL CHECK(seq>=1),
  status text NOT NULL CHECK(status IN ('recorded','confirmed','cancelled','reversed')),
  evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$'),
  evidence_name text NOT NULL CHECK(length(btrim(evidence_name)) BETWEEN 1 AND 180),
  recorded_by text NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  approved_by text, approved_at timestamptz, closed_reason text,
  CHECK(status NOT IN ('confirmed','reversed')
        OR (approved_by IS NOT NULL AND approved_at IS NOT NULL AND approved_by<>recorded_by)),
  CHECK(status NOT IN ('cancelled','reversed') OR length(btrim(coalesce(closed_reason,''))) BETWEEN 1 AND 300),
  UNIQUE(org_id,id), UNIQUE(order_id,seq),
  FOREIGN KEY(org_id,order_id) REFERENCES jw_dev.cinema_pg_orders(org_id,id),
  FOREIGN KEY(org_id,evidence_sha256) REFERENCES jw_dev.cinema_pg_evidence_files(org_id,content_sha256)
);
CREATE UNIQUE INDEX cinema_pg_delivery_evidence_uq ON jw_dev.cinema_pg_deliveries(org_id,evidence_sha256)
  WHERE status IN ('recorded','confirmed');
CREATE TABLE jw_dev.cinema_pg_delivery_items(
  org_id text NOT NULL, delivery_id text NOT NULL, order_item_id text NOT NULL,
  quantity bigint NOT NULL CHECK(quantity BETWEEN 1 AND 100000),
  PRIMARY KEY(delivery_id,order_item_id),
  FOREIGN KEY(org_id,delivery_id) REFERENCES jw_dev.cinema_pg_deliveries(org_id,id),
  FOREIGN KEY(org_id,order_item_id) REFERENCES jw_dev.cinema_pg_order_items(org_id,id)
);

CREATE TABLE jw_dev.cinema_pg_statements(
  id text PRIMARY KEY, org_id text NOT NULL, trade_no text NOT NULL,
  delivery_id text NOT NULL, order_id text NOT NULL,
  vat_mode text NOT NULL CHECK(vat_mode IN ('taxable','exempt')),
  subtotal_krw bigint NOT NULL CHECK(subtotal_krw>=0),
  vat_krw bigint NOT NULL CHECK(vat_krw>=0),
  total_krw bigint NOT NULL,
  source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
  status text NOT NULL CHECK(status IN ('draft','confirmed','voided')),
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  confirmed_by text, confirmed_at timestamptz, void_reason text,
  CHECK(total_krw=subtotal_krw+vat_krw),
  CHECK(status<>'confirmed' OR (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL)),
  CHECK(status<>'voided' OR length(btrim(coalesce(void_reason,''))) BETWEEN 1 AND 300),
  UNIQUE(org_id,id),
  FOREIGN KEY(org_id,delivery_id) REFERENCES jw_dev.cinema_pg_deliveries(org_id,id),
  FOREIGN KEY(org_id,order_id) REFERENCES jw_dev.cinema_pg_orders(org_id,id)
);
CREATE UNIQUE INDEX cinema_pg_statement_active_uq ON jw_dev.cinema_pg_statements(org_id,delivery_id)
  WHERE status<>'voided';
CREATE TABLE jw_dev.cinema_pg_statement_items(
  org_id text NOT NULL, statement_id text NOT NULL, position integer NOT NULL,
  order_item_id text NOT NULL, name text NOT NULL,
  quantity bigint NOT NULL CHECK(quantity>=1), unit_price bigint NOT NULL CHECK(unit_price>=0),
  line_total bigint GENERATED ALWAYS AS (quantity*unit_price) STORED,
  PRIMARY KEY(statement_id,position),
  FOREIGN KEY(org_id,statement_id) REFERENCES jw_dev.cinema_pg_statements(org_id,id)
);

CREATE TABLE jw_dev.cinema_pg_invoices(
  id text PRIMARY KEY, org_id text NOT NULL, trade_no text NOT NULL,
  statement_id text NOT NULL, order_id text NOT NULL, invoice_no text NOT NULL,
  subtotal_krw bigint NOT NULL CHECK(subtotal_krw>0),
  vat_krw bigint NOT NULL CHECK(vat_krw>=0),
  total_krw bigint NOT NULL,
  status text NOT NULL CHECK(status IN ('draft','reviewed','confirmed','voided')),
  created_by text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  reviewed_by text, reviewed_at timestamptz, confirmed_by text, confirmed_at timestamptz,
  void_reason text,
  CHECK(total_krw=subtotal_krw+vat_krw),
  CHECK(status NOT IN ('reviewed','confirmed') OR (reviewed_by IS NOT NULL AND reviewed_at IS NOT NULL)),
  CHECK(status<>'confirmed' OR (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL)),
  CHECK(status<>'voided' OR length(btrim(coalesce(void_reason,''))) BETWEEN 1 AND 300),
  UNIQUE(org_id,id), UNIQUE(org_id,invoice_no),
  FOREIGN KEY(org_id,statement_id) REFERENCES jw_dev.cinema_pg_statements(org_id,id),
  FOREIGN KEY(org_id,order_id) REFERENCES jw_dev.cinema_pg_orders(org_id,id)
);
CREATE UNIQUE INDEX cinema_pg_invoice_active_uq ON jw_dev.cinema_pg_invoices(org_id,statement_id)
  WHERE status<>'voided';

CREATE TABLE jw_dev.cinema_pg_payments(
  id text PRIMARY KEY, org_id text NOT NULL, invoice_id text NOT NULL, trade_no text NOT NULL,
  amount_krw bigint NOT NULL CHECK(amount_krw>0),
  paid_on date NOT NULL,
  reference text NOT NULL CHECK(length(btrim(reference)) BETWEEN 1 AND 80),
  recorded_by text NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  bank_confirmed boolean NOT NULL DEFAULT false CHECK(bank_confirmed=false),
  UNIQUE(org_id,id), UNIQUE(org_id,invoice_id,reference),
  FOREIGN KEY(org_id,invoice_id) REFERENCES jw_dev.cinema_pg_invoices(org_id,id)
);
CREATE TABLE jw_dev.cinema_pg_payment_reversals(
  org_id text NOT NULL, payment_id text PRIMARY KEY,
  reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 1 AND 300),
  reversed_by text NOT NULL, reversed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(org_id,payment_id) REFERENCES jw_dev.cinema_pg_payments(org_id,id)
);

-- ------------------------------------------------------ immutability triggers
-- Append-only tables: no UPDATE, no DELETE, ever.
CREATE FUNCTION jw_dev.cinema_pg_deny_change() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  RAISE EXCEPTION '% is append-only', TG_TABLE_NAME USING ERRCODE='23514';
END $$;

-- Status tables: only listed columns may change, and status must follow the
-- transition table. TG_ARGV[0]=entity, TG_ARGV[1]=comma separated mutable columns.
CREATE FUNCTION jw_dev.cinema_pg_guard_update() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE cols text[] := string_to_array(TG_ARGV[1], ',');
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION '% rows cannot be deleted', TG_TABLE_NAME USING ERRCODE='23514';
  END IF;
  IF (to_jsonb(OLD) - cols) IS DISTINCT FROM (to_jsonb(NEW) - cols) THEN
    RAISE EXCEPTION 'immutable column changed on %', TG_TABLE_NAME USING ERRCODE='23514';
  END IF;
  IF TG_ARGV[0] <> '' AND to_jsonb(OLD)->>'status' IS DISTINCT FROM to_jsonb(NEW)->>'status' THEN
    IF NOT EXISTS (SELECT 1 FROM jw_dev.cinema_pg_transitions t
                   WHERE t.entity=TG_ARGV[0] AND t.from_status=to_jsonb(OLD)->>'status'
                     AND t.to_status=to_jsonb(NEW)->>'status') THEN
      RAISE EXCEPTION 'illegal % transition % -> %', TG_ARGV[0],
        to_jsonb(OLD)->>'status', to_jsonb(NEW)->>'status' USING ERRCODE='23514';
    END IF;
  END IF;
  RETURN NEW;
END $$;

-- Quote content may change only while the quote is a draft.
CREATE FUNCTION jw_dev.cinema_pg_quote_content_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF OLD.status<>'draft' AND (NEW.title IS DISTINCT FROM OLD.title
     OR NEW.partner_id IS DISTINCT FROM OLD.partner_id
     OR NEW.vat_mode IS DISTINCT FROM OLD.vat_mode) THEN
    RAISE EXCEPTION 'quote content is frozen once it leaves draft' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION jw_dev.cinema_pg_quote_item_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE s text; v_org text; v_quote text;
BEGIN
  IF TG_OP='DELETE' THEN v_org := OLD.org_id; v_quote := OLD.quote_id;
  ELSE v_org := NEW.org_id; v_quote := NEW.quote_id; END IF;
  SELECT status INTO s FROM jw_dev.cinema_pg_quotes WHERE org_id=v_org AND id=v_quote;
  IF s IS DISTINCT FROM 'draft' THEN
    RAISE EXCEPTION 'quote items are frozen once the quote leaves draft' USING ERRCODE='23514';
  END IF;
  IF TG_OP='UPDATE' THEN
    RAISE EXCEPTION 'quote items are replaced, never edited in place' USING ERRCODE='23514';
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER t_partners_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_partners
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('','name,business_number,contact_name,email,phone,version,updated_at');
CREATE TRIGGER t_quotes_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_quotes
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('quote','status,title,partner_id,vat_mode,version,updated_at,submitted_by,approved_by,approved_at');
CREATE TRIGGER t_quotes_content BEFORE UPDATE ON jw_dev.cinema_pg_quotes
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_quote_content_guard();
CREATE TRIGGER t_quote_items_guard BEFORE INSERT OR UPDATE OR DELETE ON jw_dev.cinema_pg_quote_items
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_quote_item_guard();
CREATE TRIGGER t_orders_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_orders
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('order','status,updated_at');
CREATE TRIGGER t_deliveries_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_deliveries
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('delivery','status,approved_by,approved_at,closed_reason');
CREATE TRIGGER t_statements_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_statements
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('statement','status,confirmed_by,confirmed_at,void_reason');
CREATE TRIGGER t_invoices_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_invoices
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('invoice','status,reviewed_by,reviewed_at,confirmed_by,confirmed_at,void_reason');
CREATE TRIGGER t_requests_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_requests
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('','entity_type,entity_id');
CREATE TRIGGER t_counters_guard BEFORE UPDATE OR DELETE ON jw_dev.cinema_pg_trade_counters
  FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_guard_update('','last_no');
DO $ap$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cinema_pg_audit','cinema_pg_order_items','cinema_pg_delivery_items',
      'cinema_pg_statement_items','cinema_pg_payments','cinema_pg_payment_reversals','cinema_pg_transitions',
      'cinema_pg_evidence_files'] LOOP
    EXECUTE format('CREATE TRIGGER t_%s_append_only BEFORE UPDATE OR DELETE ON jw_dev.%I
                    FOR EACH ROW EXECUTE FUNCTION jw_dev.cinema_pg_deny_change()', t, t);
  END LOOP;
END $ap$;

-- ------------------------------------------------------------------- RLS
DO $rls$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['cinema_pg_requests','cinema_pg_trade_counters','cinema_pg_audit',
      'cinema_pg_partners','cinema_pg_quotes','cinema_pg_quote_items','cinema_pg_orders',
      'cinema_pg_order_items','cinema_pg_deliveries','cinema_pg_delivery_items',
      'cinema_pg_statements','cinema_pg_statement_items','cinema_pg_invoices',
      'cinema_pg_payments','cinema_pg_payment_reversals','cinema_pg_evidence_files'] LOOP
    EXECUTE format('ALTER TABLE jw_dev.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE jw_dev.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('REVOKE ALL ON jw_dev.%I FROM PUBLIC', t);
    EXECUTE format('CREATE POLICY %I ON jw_dev.%I FOR ALL TO jw_cinema_owner
        USING(org_id=jw_dev.current_org_from_session())
        WITH CHECK(org_id=jw_dev.current_org_from_session())', 'p_owner_'||t, t);
    IF t NOT IN ('cinema_pg_requests','cinema_pg_trade_counters') THEN
      IF t='cinema_pg_evidence_files' THEN   -- metadata only: the file bytes are never granted
        GRANT SELECT (id,org_id,content_sha256,size_bytes,content_type,file_name,uploaded_by,created_at)
          ON jw_dev.cinema_pg_evidence_files TO jw_cinema_writer;
      ELSE
        EXECUTE format('GRANT SELECT ON jw_dev.%I TO jw_cinema_writer', t);
      END IF;
      EXECUTE format('CREATE POLICY %I ON jw_dev.%I FOR SELECT TO jw_cinema_writer
          USING(org_id=jw_dev.current_org_from_session())', 'p_writer_'||t, t);
    END IF;
  END LOOP;
END $rls$;
-- transitions is global reference data (no org_id); only the owner reads it.
REVOKE ALL ON jw_dev.cinema_pg_transitions FROM PUBLIC, jw_cinema_writer;

-- ------------------------------------------------------ internal helpers
-- Everything below is SECURITY DEFINER owned by jw_cinema_owner, fixed
-- search_path, schema-qualified names only.
CREATE FUNCTION jw_dev.cinema_pg_new_id() RETURNS text
LANGUAGE sql VOLATILE SET search_path=pg_catalog AS
$$ SELECT replace(gen_random_uuid()::text,'-','') $$;

CREATE FUNCTION jw_dev.cinema_pg_begin(p_request text, p_op text, p_payload jsonb,
  OUT o_actor text, OUT o_org text, OUT o_role text,
  OUT o_replay_type text, OUT o_replay_id text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_hash text; v_n integer; r record;
BEGIN
  SELECT i.actor_id,i.org_id,i.actor_role INTO o_actor,o_org,o_role
    FROM jw_dev.stage_identity_v84() i;
  IF o_org IS NULL THEN
    RAISE EXCEPTION 'valid session required' USING ERRCODE='42501';
  END IF;
  IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9._:-]{8,128}$' THEN
    RAISE EXCEPTION 'invalid request id' USING ERRCODE='23514';
  END IF;
  v_hash := encode(sha256(convert_to(
      jsonb_build_object('op',p_op,'payload',p_payload)::text,'UTF8')),'hex');
  -- Reserve first: a concurrent identical request blocks here until we commit.
  INSERT INTO jw_dev.cinema_pg_requests(org_id,request_id,op,payload_sha256,entity_type,entity_id)
  VALUES (o_org,p_request,p_op,v_hash,'','')
  ON CONFLICT (org_id,request_id) DO NOTHING;
  GET DIAGNOSTICS v_n = ROW_COUNT;
  IF v_n = 0 THEN
    SELECT * INTO r FROM jw_dev.cinema_pg_requests WHERE org_id=o_org AND request_id=p_request;
    IF r.op IS DISTINCT FROM p_op OR r.payload_sha256 IS DISTINCT FROM v_hash THEN
      RAISE EXCEPTION 'request id was already used for a different request' USING ERRCODE='23505';
    END IF;
    IF r.entity_id = '' THEN
      RAISE EXCEPTION 'request is still in progress' USING ERRCODE='40001';
    END IF;
    o_replay_type := r.entity_type; o_replay_id := r.entity_id;
  END IF;
END $$;

CREATE FUNCTION jw_dev.cinema_pg_finish(p_org text, p_request text, p_type text, p_id text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  UPDATE jw_dev.cinema_pg_requests SET entity_type=p_type, entity_id=p_id
   WHERE org_id=p_org AND request_id=p_request AND entity_id='' $$;

CREATE FUNCTION jw_dev.cinema_pg_audit_add(p_org text, p_actor text, p_type text, p_id text,
   p_trade text, p_action text, p_detail jsonb, p_request text)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
  INSERT INTO jw_dev.cinema_pg_audit(id,org_id,actor_id,entity_type,entity_id,trade_no,action,detail,request_id)
  VALUES (jw_dev.cinema_pg_new_id(),p_org,p_actor,p_type,p_id,p_trade,p_action,
          coalesce(p_detail,'{}'::jsonb),p_request) $$;

CREATE FUNCTION jw_dev.cinema_pg_require_admin(p_role text) RETURNS void
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
  IF p_role IS DISTINCT FROM 'admin' THEN
    RAISE EXCEPTION 'administrator approval role required' USING ERRCODE='42501';
  END IF;
END $$;

CREATE FUNCTION jw_dev.cinema_pg_vat(p_subtotal bigint, p_mode text) RETURNS bigint
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
  SELECT CASE WHEN p_mode='taxable' THEN (p_subtotal+5)/10 ELSE 0::bigint END $$;

CREATE FUNCTION jw_dev.cinema_pg_next_trade_no(p_org text) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer; d date := current_date;
BEGIN
  INSERT INTO jw_dev.cinema_pg_trade_counters(org_id,day,last_no) VALUES (p_org,d,1)
  ON CONFLICT (org_id,day) DO UPDATE SET last_no=jw_dev.cinema_pg_trade_counters.last_no+1
  RETURNING last_no INTO n;
  RETURN 'T'||to_char(d,'YYMMDD')||'-'||to_char(n,'FM0000');
END $$;

CREATE FUNCTION jw_dev.cinema_pg_parse_lines(p_items jsonb)
RETURNS TABLE(pos integer, name text, quantity bigint, unit_price bigint)
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE e jsonb; i integer := 0; q numeric; p numeric; n text;
BEGIN
  IF p_items IS NULL OR jsonb_typeof(p_items) IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'items must be an array' USING ERRCODE='23514';
  END IF;
  IF jsonb_array_length(p_items) NOT BETWEEN 1 AND 40 THEN
    RAISE EXCEPTION 'items must contain 1..40 lines' USING ERRCODE='23514';
  END IF;
  FOR e IN SELECT value FROM jsonb_array_elements(p_items) LOOP
    IF jsonb_typeof(e) IS DISTINCT FROM 'object'
       OR jsonb_typeof(e->'name') IS DISTINCT FROM 'string'
       OR jsonb_typeof(e->'quantity') IS DISTINCT FROM 'number'
       OR jsonb_typeof(e->'unit_price') IS DISTINCT FROM 'number' THEN
      RAISE EXCEPTION 'line % is malformed', i USING ERRCODE='23514';
    END IF;
    n := btrim(e->>'name'); q := (e->>'quantity')::numeric; p := (e->>'unit_price')::numeric;
    IF length(n) NOT BETWEEN 1 AND 150 OR q <> trunc(q) OR p <> trunc(p)
       OR q NOT BETWEEN 1 AND 100000 OR p NOT BETWEEN 0 AND 1000000000 THEN
      RAISE EXCEPTION 'line % has an invalid name, quantity or integer KRW price', i USING ERRCODE='23514';
    END IF;
    pos := i; name := n; quantity := q::bigint; unit_price := p::bigint; i := i+1;
    RETURN NEXT;
  END LOOP;
END $$;

-- Recompute a statement's money from confirmed delivery lines (source of truth).
CREATE FUNCTION jw_dev.cinema_pg_statement_source(p_org text, p_delivery text,
   OUT o_subtotal bigint, OUT o_vat bigint, OUT o_hash text, OUT o_vat_mode text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_lines text;
BEGIN
  SELECT o.vat_mode INTO o_vat_mode
    FROM jw_dev.cinema_pg_deliveries d JOIN jw_dev.cinema_pg_orders o ON o.org_id=d.org_id AND o.id=d.order_id
   WHERE d.org_id=p_org AND d.id=p_delivery AND d.status='confirmed';
  IF o_vat_mode IS NULL THEN
    RAISE EXCEPTION 'delivery is not confirmed' USING ERRCODE='23514';
  END IF;
  SELECT coalesce(sum(di.quantity*oi.unit_price),0),
         string_agg(oi.id||':'||di.quantity||':'||oi.unit_price, ',' ORDER BY oi.position)
    INTO o_subtotal, v_lines
    FROM jw_dev.cinema_pg_delivery_items di
    JOIN jw_dev.cinema_pg_order_items oi ON oi.org_id=di.org_id AND oi.id=di.order_item_id
   WHERE di.org_id=p_org AND di.delivery_id=p_delivery;
  IF v_lines IS NULL THEN
    RAISE EXCEPTION 'delivery has no lines' USING ERRCODE='23514';
  END IF;
  o_vat := jw_dev.cinema_pg_vat(o_subtotal,o_vat_mode);
  o_hash := encode(sha256(convert_to(o_vat_mode||'|'||v_lines,'UTF8')),'hex');
END $$;

CREATE FUNCTION jw_dev.cinema_pg_result(p_type text, p_id text, p_replayed boolean) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v jsonb;
BEGIN
  v := CASE p_type
   WHEN 'partner' THEN (SELECT to_jsonb(x) FROM jw_dev.cinema_pg_partners x WHERE x.id=p_id)
   WHEN 'quote' THEN (SELECT to_jsonb(x) || jsonb_build_object('items',
        (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.position),'[]'::jsonb)
           FROM jw_dev.cinema_pg_quote_items i WHERE i.org_id=x.org_id AND i.quote_id=x.id))
      FROM jw_dev.cinema_pg_quotes x WHERE x.id=p_id)
   WHEN 'order' THEN (SELECT to_jsonb(x) || jsonb_build_object('items',
        (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.position),'[]'::jsonb)
           FROM jw_dev.cinema_pg_order_items i WHERE i.org_id=x.org_id AND i.order_id=x.id))
      FROM jw_dev.cinema_pg_orders x WHERE x.id=p_id)
   WHEN 'delivery' THEN (SELECT to_jsonb(x) || jsonb_build_object('items',
        (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.order_item_id),'[]'::jsonb)
           FROM jw_dev.cinema_pg_delivery_items i WHERE i.org_id=x.org_id AND i.delivery_id=x.id))
      FROM jw_dev.cinema_pg_deliveries x WHERE x.id=p_id)
   WHEN 'statement' THEN (SELECT to_jsonb(x) || jsonb_build_object('items',
        (SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY i.position),'[]'::jsonb)
           FROM jw_dev.cinema_pg_statement_items i WHERE i.org_id=x.org_id AND i.statement_id=x.id))
      FROM jw_dev.cinema_pg_statements x WHERE x.id=p_id)
   WHEN 'invoice' THEN (SELECT to_jsonb(x) || jsonb_build_object('paid_krw',
        (SELECT coalesce(sum(p.amount_krw),0) FROM jw_dev.cinema_pg_payments p
          WHERE p.org_id=x.org_id AND p.invoice_id=x.id
            AND NOT EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r
                            WHERE r.org_id=p.org_id AND r.payment_id=p.id)))
      FROM jw_dev.cinema_pg_invoices x WHERE x.id=p_id)
   WHEN 'evidence' THEN (SELECT jsonb_build_object('id',x.id,'content_sha256',x.content_sha256,'size_bytes',x.size_bytes,
        'content_type',x.content_type,'file_name',x.file_name,'uploaded_by',x.uploaded_by,'created_at',x.created_at)
      FROM jw_dev.cinema_pg_evidence_files x WHERE x.id=p_id)
   WHEN 'payment' THEN (SELECT to_jsonb(x) || jsonb_build_object('reversed',
        EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r WHERE r.org_id=x.org_id AND r.payment_id=x.id))
      FROM jw_dev.cinema_pg_payments x WHERE x.id=p_id)
  END;
  IF v IS NULL THEN
    RAISE EXCEPTION '% not found', p_type USING ERRCODE='P0002';
  END IF;
  RETURN jsonb_build_object('replayed',p_replayed,'entity_type',p_type,'entity',v);
END $$;

-- ------------------------------------------------------------ public API
-- 1. Partner (거래처) create / update with optimistic versioning.
CREATE FUNCTION jw_dev.cinema_pg_partner_upsert(p_request_id text, p_partner_id text,
   p_name text, p_business_number text, p_contact_name text, p_email text, p_phone text,
   p_expected_version integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; v_id text; v_bn text; v_old record;
BEGIN
  v_bn := regexp_replace(coalesce(p_business_number,''),'[^0-9]','','g');
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'partner_upsert',
     jsonb_build_object('id',p_partner_id,'name',p_name,'bn',v_bn,'contact',p_contact_name,
        'email',p_email,'phone',p_phone,'v',p_expected_version));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  IF p_partner_id IS NULL THEN
    v_id := jw_dev.cinema_pg_new_id();
    INSERT INTO jw_dev.cinema_pg_partners(id,org_id,name,business_number,contact_name,email,phone,created_by)
    VALUES (v_id,c.o_org,btrim(coalesce(p_name,'')),v_bn,coalesce(p_contact_name,''),
            coalesce(p_email,''),coalesce(p_phone,''),c.o_actor);
    PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'partner',v_id,NULL,'create',
            jsonb_build_object('name',btrim(p_name)),p_request_id);
  ELSE
    SELECT * INTO v_old FROM jw_dev.cinema_pg_partners
     WHERE org_id=c.o_org AND id=p_partner_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'partner not found' USING ERRCODE='P0002'; END IF;
    IF p_expected_version IS DISTINCT FROM v_old.version THEN
      RAISE EXCEPTION 'partner version is stale' USING ERRCODE='40001';
    END IF;
    v_id := p_partner_id;
    UPDATE jw_dev.cinema_pg_partners SET name=btrim(coalesce(p_name,'')), business_number=v_bn,
        contact_name=coalesce(p_contact_name,''), email=coalesce(p_email,''),
        phone=coalesce(p_phone,''), version=version+1, updated_at=clock_timestamp()
     WHERE org_id=c.o_org AND id=v_id;
    PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'partner',v_id,NULL,'update',
            jsonb_build_object('from_version',v_old.version,'previous_name',v_old.name,
                               'previous_business_number',v_old.business_number),p_request_id);
  END IF;
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'partner',v_id);
  RETURN jw_dev.cinema_pg_result('partner',v_id,false);
END $$;

-- 2a. Quote create (draft).
CREATE FUNCTION jw_dev.cinema_pg_quote_create(p_request_id text, p_partner_id text,
   p_title text, p_vat_mode text, p_items jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; v_id text; v_trade text;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'quote_create',
     jsonb_build_object('partner',p_partner_id,'title',p_title,'vat',p_vat_mode,'items',p_items));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  IF p_vat_mode IS NULL OR p_vat_mode NOT IN ('taxable','exempt') THEN
    RAISE EXCEPTION 'vat_mode must be taxable or exempt' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_partners WHERE org_id=c.o_org AND id=p_partner_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'partner not found' USING ERRCODE='P0002'; END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_parse_lines(p_items);   -- validate before any write
  v_id := jw_dev.cinema_pg_new_id();
  v_trade := jw_dev.cinema_pg_next_trade_no(c.o_org);
  INSERT INTO jw_dev.cinema_pg_quotes(id,org_id,trade_no,partner_id,title,status,vat_mode,created_by)
  VALUES (v_id,c.o_org,v_trade,p_partner_id,btrim(coalesce(p_title,'')),'draft',p_vat_mode,c.o_actor);
  INSERT INTO jw_dev.cinema_pg_quote_items(id,org_id,quote_id,position,name,quantity,unit_price)
  SELECT jw_dev.cinema_pg_new_id(),c.o_org,v_id,l.pos,l.name,l.quantity,l.unit_price
    FROM jw_dev.cinema_pg_parse_lines(p_items) l;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'quote',v_id,v_trade,'create',
          jsonb_build_object('lines',jsonb_array_length(p_items)),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'quote',v_id);
  RETURN jw_dev.cinema_pg_result('quote',v_id,false);
END $$;

-- 2b. Quote update (draft only; items are replaced, previous lines kept in audit).
CREATE FUNCTION jw_dev.cinema_pg_quote_update(p_request_id text, p_quote_id text,
   p_expected_version integer, p_title text, p_items jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; q record; v_prev jsonb;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'quote_update',
     jsonb_build_object('quote',p_quote_id,'v',p_expected_version,'title',p_title,'items',p_items));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  SELECT * INTO q FROM jw_dev.cinema_pg_quotes WHERE org_id=c.o_org AND id=p_quote_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'quote not found' USING ERRCODE='P0002'; END IF;
  IF q.status<>'draft' THEN
    RAISE EXCEPTION 'only draft quotes can be edited' USING ERRCODE='23514';
  END IF;
  IF p_expected_version IS DISTINCT FROM q.version THEN
    RAISE EXCEPTION 'quote version is stale' USING ERRCODE='40001';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_parse_lines(p_items);
  SELECT coalesce(jsonb_agg(jsonb_build_object('name',name,'quantity',quantity,'unit_price',unit_price)
                            ORDER BY position),'[]'::jsonb) INTO v_prev
    FROM jw_dev.cinema_pg_quote_items WHERE org_id=c.o_org AND quote_id=p_quote_id;
  DELETE FROM jw_dev.cinema_pg_quote_items WHERE org_id=c.o_org AND quote_id=p_quote_id;
  INSERT INTO jw_dev.cinema_pg_quote_items(id,org_id,quote_id,position,name,quantity,unit_price)
  SELECT jw_dev.cinema_pg_new_id(),c.o_org,p_quote_id,l.pos,l.name,l.quantity,l.unit_price
    FROM jw_dev.cinema_pg_parse_lines(p_items) l;
  UPDATE jw_dev.cinema_pg_quotes SET title=btrim(coalesce(p_title,'')), version=version+1,
         updated_at=clock_timestamp() WHERE org_id=c.o_org AND id=p_quote_id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'quote',p_quote_id,q.trade_no,'update',
          jsonb_build_object('from_version',q.version,'previous_title',q.title,'previous_items',v_prev),
          p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'quote',p_quote_id);
  RETURN jw_dev.cinema_pg_result('quote',p_quote_id,false);
END $$;

-- 2c. Quote status change / approval.
CREATE FUNCTION jw_dev.cinema_pg_quote_transition(p_request_id text, p_quote_id text,
   p_expected_version integer, p_to text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; q record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'quote_transition',
     jsonb_build_object('quote',p_quote_id,'v',p_expected_version,'to',p_to));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  IF p_to IS NULL OR p_to NOT IN ('draft','submitted','approved','rejected','cancelled') THEN
    RAISE EXCEPTION 'unsupported target status' USING ERRCODE='23514';
  END IF;
  IF p_to IN ('approved','rejected','cancelled') THEN
    PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  END IF;
  SELECT * INTO q FROM jw_dev.cinema_pg_quotes WHERE org_id=c.o_org AND id=p_quote_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'quote not found' USING ERRCODE='P0002'; END IF;
  IF p_expected_version IS DISTINCT FROM q.version THEN
    RAISE EXCEPTION 'quote version is stale' USING ERRCODE='40001';
  END IF;
  IF p_to='submitted' THEN
    PERFORM 1 FROM jw_dev.cinema_pg_quote_items WHERE org_id=c.o_org AND quote_id=p_quote_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'quote has no lines' USING ERRCODE='23514'; END IF;
  END IF;
  UPDATE jw_dev.cinema_pg_quotes SET status=p_to, version=version+1, updated_at=clock_timestamp(),
     submitted_by=CASE WHEN p_to='submitted' THEN c.o_actor ELSE submitted_by END,
     approved_by=CASE WHEN p_to='approved' THEN c.o_actor ELSE approved_by END,
     approved_at=CASE WHEN p_to='approved' THEN clock_timestamp() ELSE approved_at END
   WHERE org_id=c.o_org AND id=p_quote_id;       -- illegal moves are rejected by trigger
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'quote',p_quote_id,q.trade_no,
          'status:'||p_to,jsonb_build_object('from',q.status,'to',p_to),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'quote',p_quote_id);
  RETURN jw_dev.cinema_pg_result('quote',p_quote_id,false);
END $$;

-- 3/4. Order from an APPROVED quote; inherits the trade number.
CREATE FUNCTION jw_dev.cinema_pg_order_create(p_request_id text, p_quote_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; q record; v_id text;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'order_create',
     jsonb_build_object('quote',p_quote_id));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO q FROM jw_dev.cinema_pg_quotes WHERE org_id=c.o_org AND id=p_quote_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'quote not found' USING ERRCODE='P0002'; END IF;
  IF q.status<>'approved' THEN
    RAISE EXCEPTION 'only an approved quote can become an order' USING ERRCODE='23514';
  END IF;
  v_id := jw_dev.cinema_pg_new_id();
  INSERT INTO jw_dev.cinema_pg_orders(id,org_id,trade_no,quote_id,partner_id,vat_mode,status,created_by)
  VALUES (v_id,c.o_org,q.trade_no,q.id,q.partner_id,q.vat_mode,'open',c.o_actor);
  INSERT INTO jw_dev.cinema_pg_order_items(id,org_id,order_id,source_quote_item_id,position,name,quantity,unit_price)
  SELECT jw_dev.cinema_pg_new_id(),c.o_org,v_id,i.id,i.position,i.name,i.quantity,i.unit_price
    FROM jw_dev.cinema_pg_quote_items i WHERE i.org_id=c.o_org AND i.quote_id=q.id;
  UPDATE jw_dev.cinema_pg_quotes SET status='ordered', version=version+1, updated_at=clock_timestamp()
   WHERE org_id=c.o_org AND id=q.id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'order',v_id,q.trade_no,'create',
          jsonb_build_object('quote_id',q.id),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'order',v_id);
  RETURN jw_dev.cinema_pg_result('order',v_id,false);
END $$;

-- 5. Record a (partial) delivery with an evidence hash. Quantity is RESERVED
--    against remaining stock while pending, so concurrent records cannot oversell.
CREATE FUNCTION jw_dev.cinema_pg_delivery_record(p_request_id text, p_order_id text,
   p_lines jsonb, p_evidence_sha256 text, p_evidence_name text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; o record; v_id text; e jsonb; v_seen text[] := '{}'; v_item text; v_qty numeric;
        v_remaining bigint; v_seq integer; ef record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'delivery_record',
     jsonb_build_object('order',p_order_id,'lines',p_lines,'sha',p_evidence_sha256,'name',p_evidence_name));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  IF p_evidence_sha256 IS NULL OR p_evidence_sha256 !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'delivery evidence SHA-256 is required' USING ERRCODE='23514';
  END IF;
  IF p_lines IS NULL OR jsonb_typeof(p_lines) IS DISTINCT FROM 'array'
     OR jsonb_array_length(p_lines) NOT BETWEEN 1 AND 40 THEN
    RAISE EXCEPTION 'delivery lines must be an array of 1..40' USING ERRCODE='23514';
  END IF;
  -- The evidence must already be stored on the server (hash recomputed there) by this same person.
  SELECT * INTO ef FROM jw_dev.cinema_pg_evidence_files WHERE org_id=c.o_org AND content_sha256=p_evidence_sha256;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'delivery evidence file must be uploaded to the server first' USING ERRCODE='23514';
  END IF;
  IF ef.uploaded_by <> c.o_actor THEN
    RAISE EXCEPTION 'delivery evidence must be uploaded by the person recording the delivery' USING ERRCODE='23514';
  END IF;
  SELECT * INTO o FROM jw_dev.cinema_pg_orders WHERE org_id=c.o_org AND id=p_order_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'order not found' USING ERRCODE='P0002'; END IF;
  IF o.status<>'open' THEN
    RAISE EXCEPTION 'order is not open for delivery' USING ERRCODE='23514';
  END IF;
  v_id := jw_dev.cinema_pg_new_id();
  SELECT coalesce(max(seq),0)+1 INTO v_seq FROM jw_dev.cinema_pg_deliveries
   WHERE org_id=c.o_org AND order_id=p_order_id;
  INSERT INTO jw_dev.cinema_pg_deliveries(id,org_id,order_id,trade_no,seq,status,evidence_sha256,evidence_name,recorded_by)
  VALUES (v_id,c.o_org,p_order_id,o.trade_no,v_seq,'recorded',p_evidence_sha256,ef.file_name,c.o_actor);
  FOR e IN SELECT value FROM jsonb_array_elements(p_lines) LOOP
    IF jsonb_typeof(e) IS DISTINCT FROM 'object'
       OR jsonb_typeof(e->'order_item_id') IS DISTINCT FROM 'string'
       OR jsonb_typeof(e->'quantity') IS DISTINCT FROM 'number' THEN
      RAISE EXCEPTION 'malformed delivery line' USING ERRCODE='23514';
    END IF;
    v_item := e->>'order_item_id'; v_qty := (e->>'quantity')::numeric;
    IF v_qty <> trunc(v_qty) OR v_qty NOT BETWEEN 1 AND 100000 THEN
      RAISE EXCEPTION 'delivery quantity must be an integer between 1 and 100000' USING ERRCODE='23514';
    END IF;
    IF v_item = ANY(v_seen) THEN
      RAISE EXCEPTION 'duplicate order item in one delivery' USING ERRCODE='23514';
    END IF;
    v_seen := v_seen || v_item;
    SELECT oi.quantity - coalesce((SELECT sum(di.quantity)
              FROM jw_dev.cinema_pg_delivery_items di
              JOIN jw_dev.cinema_pg_deliveries d ON d.org_id=di.org_id AND d.id=di.delivery_id
             WHERE di.org_id=oi.org_id AND di.order_item_id=oi.id
               AND d.status IN ('recorded','confirmed') AND d.id<>v_id),0)
      INTO v_remaining
      FROM jw_dev.cinema_pg_order_items oi
     WHERE oi.org_id=c.o_org AND oi.order_id=p_order_id AND oi.id=v_item;
    IF v_remaining IS NULL THEN
      RAISE EXCEPTION 'order item does not belong to this order' USING ERRCODE='P0002';
    END IF;
    IF v_qty > v_remaining THEN
      RAISE EXCEPTION 'delivery quantity exceeds remaining quantity (%)', v_remaining USING ERRCODE='23514';
    END IF;
    INSERT INTO jw_dev.cinema_pg_delivery_items(org_id,delivery_id,order_item_id,quantity)
    VALUES (c.o_org,v_id,v_item,v_qty::bigint);
  END LOOP;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'delivery',v_id,o.trade_no,'record',
          jsonb_build_object('seq',v_seq,'evidence_sha256',p_evidence_sha256),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'delivery',v_id);
  RETURN jw_dev.cinema_pg_result('delivery',v_id,false);
END $$;

-- 5a. Store delivery evidence on the server. The database recomputes SHA-256, enforces size
--     (1 byte..5 MB), type allow-list (pdf/png/jpeg) and the matching magic bytes, and
--     de-duplicates identical content per tenant. Same request id + same file replays.
CREATE FUNCTION jw_dev.cinema_pg_evidence_put(p_request_id text, p_name text, p_content_type text, p_content bytea)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; v_sha text; v_id text; v_new boolean := false;
BEGIN
  IF p_content IS NULL OR octet_length(p_content) NOT BETWEEN 1 AND 5242880 THEN
    RAISE EXCEPTION 'evidence file must be between 1 byte and 5 MB' USING ERRCODE='23514';
  END IF;
  v_sha := encode(sha256(p_content),'hex');
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'evidence_put',
     jsonb_build_object('sha',v_sha,'name',p_name,'type',p_content_type));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  IF p_name IS NULL OR length(btrim(p_name)) NOT BETWEEN 1 AND 180 THEN
    RAISE EXCEPTION 'evidence file name is required' USING ERRCODE='23514';
  END IF;
  IF p_content_type IS NULL OR p_content_type NOT IN ('application/pdf','image/png','image/jpeg') THEN
    RAISE EXCEPTION 'evidence type must be pdf, png or jpeg' USING ERRCODE='23514';
  END IF;
  IF NOT ((p_content_type='application/pdf' AND substring(p_content from 1 for 5)='\x255044462d'::bytea)
       OR (p_content_type='image/png' AND substring(p_content from 1 for 8)='\x89504e470d0a1a0a'::bytea)
       OR (p_content_type='image/jpeg' AND substring(p_content from 1 for 3)='\xffd8ff'::bytea)) THEN
    RAISE EXCEPTION 'evidence content does not match its declared type' USING ERRCODE='23514';
  END IF;
  SELECT id INTO v_id FROM jw_dev.cinema_pg_evidence_files WHERE org_id=c.o_org AND content_sha256=v_sha;
  IF NOT FOUND THEN
    v_id := jw_dev.cinema_pg_new_id(); v_new := true;
    INSERT INTO jw_dev.cinema_pg_evidence_files(id,org_id,content_sha256,size_bytes,content_type,file_name,content,uploaded_by)
    VALUES (v_id,c.o_org,v_sha,octet_length(p_content),p_content_type,btrim(p_name),p_content,c.o_actor);
    PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'evidence',v_id,NULL,'evidence_upload',
            jsonb_build_object('sha256',v_sha,'size',octet_length(p_content)),p_request_id);
  END IF;
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'evidence',v_id);
  RETURN jw_dev.cinema_pg_result('evidence',v_id,false) || jsonb_build_object('duplicate_content',NOT v_new);
END $$;

-- 5b. Open a stored evidence file (administrator or the uploader, same tenant only). Every open is
--     audited; delivery confirmation requires that THIS administrator opened THIS evidence.
CREATE FUNCTION jw_dev.cinema_pg_evidence_open(p_request_id text, p_evidence_id text)
RETURNS TABLE(o_file_name text, o_content_type text, o_size_bytes integer, o_sha256 text, o_content bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; ef record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'evidence_open',jsonb_build_object('evidence',p_evidence_id));
  SELECT * INTO ef FROM jw_dev.cinema_pg_evidence_files WHERE org_id=c.o_org AND id=p_evidence_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'evidence not found' USING ERRCODE='P0002'; END IF;
  IF c.o_role IS DISTINCT FROM 'admin' AND ef.uploaded_by IS DISTINCT FROM c.o_actor THEN
    RAISE EXCEPTION 'only an administrator or the uploader can open this evidence' USING ERRCODE='42501';
  END IF;
  IF c.o_replay_id IS NULL THEN
    PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'evidence',ef.id,NULL,'evidence_open',
            jsonb_build_object('sha256',ef.content_sha256),p_request_id);
    PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'evidence',ef.id);
  END IF;
  o_file_name := ef.file_name; o_content_type := ef.content_type; o_size_bytes := ef.size_bytes;
  o_sha256 := ef.content_sha256; o_content := ef.content;
  RETURN NEXT;
END $$;

-- 6. Confirm a delivery: admin, different from the recorder, evidence present.
CREATE FUNCTION jw_dev.cinema_pg_delivery_confirm(p_request_id text, p_delivery_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; d record; o record; v_open bigint;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'delivery_confirm',
     jsonb_build_object('delivery',p_delivery_id));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT order_id INTO o FROM jw_dev.cinema_pg_deliveries WHERE org_id=c.o_org AND id=p_delivery_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'delivery not found' USING ERRCODE='P0002'; END IF;
  SELECT * INTO o FROM jw_dev.cinema_pg_orders WHERE org_id=c.o_org AND id=o.order_id FOR UPDATE;
  SELECT * INTO d FROM jw_dev.cinema_pg_deliveries WHERE org_id=c.o_org AND id=p_delivery_id FOR UPDATE;
  IF d.status<>'recorded' THEN
    RAISE EXCEPTION 'only a recorded delivery can be confirmed' USING ERRCODE='23514';
  END IF;
  IF d.recorded_by = c.o_actor THEN
    RAISE EXCEPTION 'approver must differ from the person who recorded the delivery' USING ERRCODE='42501';
  END IF;
  IF o.status<>'open' THEN
    RAISE EXCEPTION 'order is not open' USING ERRCODE='23514';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM jw_dev.cinema_pg_audit a
                   JOIN jw_dev.cinema_pg_evidence_files ef ON ef.org_id=a.org_id AND ef.id=a.entity_id
                  WHERE a.org_id=c.o_org AND a.actor_id=c.o_actor AND a.entity_type='evidence'
                    AND a.action='evidence_open' AND ef.content_sha256=d.evidence_sha256
                    AND a.created_at >= d.recorded_at) THEN
    RAISE EXCEPTION 'administrator must open the stored evidence file before confirming' USING ERRCODE='23514';
  END IF;
  UPDATE jw_dev.cinema_pg_deliveries SET status='confirmed', approved_by=c.o_actor,
         approved_at=clock_timestamp() WHERE org_id=c.o_org AND id=p_delivery_id;
  SELECT coalesce(sum(oi.quantity - coalesce((
            SELECT sum(di.quantity) FROM jw_dev.cinema_pg_delivery_items di
              JOIN jw_dev.cinema_pg_deliveries dd ON dd.org_id=di.org_id AND dd.id=di.delivery_id
             WHERE di.org_id=oi.org_id AND di.order_item_id=oi.id AND dd.status='confirmed'),0)),0)
    INTO v_open FROM jw_dev.cinema_pg_order_items oi
   WHERE oi.org_id=c.o_org AND oi.order_id=o.id;
  IF v_open < 0 THEN
    RAISE EXCEPTION 'confirmed quantity exceeds ordered quantity' USING ERRCODE='23514';
  END IF;
  IF v_open = 0 THEN
    UPDATE jw_dev.cinema_pg_orders SET status='fulfilled', updated_at=clock_timestamp()
     WHERE org_id=c.o_org AND id=o.id;
  END IF;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'delivery',p_delivery_id,d.trade_no,'confirm',
          jsonb_build_object('order_fulfilled',v_open=0,'attestation','human_admin_after_server_evidence_open'),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'delivery',p_delivery_id);
  RETURN jw_dev.cinema_pg_result('delivery',p_delivery_id,false);
END $$;

CREATE FUNCTION jw_dev.cinema_pg_delivery_cancel(p_request_id text, p_delivery_id text, p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; d record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'delivery_cancel',
     jsonb_build_object('delivery',p_delivery_id,'reason',p_reason));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  SELECT * INTO d FROM jw_dev.cinema_pg_deliveries WHERE org_id=c.o_org AND id=p_delivery_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'delivery not found' USING ERRCODE='P0002'; END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_orders WHERE org_id=c.o_org AND id=d.order_id FOR UPDATE;
  SELECT * INTO d FROM jw_dev.cinema_pg_deliveries WHERE org_id=c.o_org AND id=p_delivery_id FOR UPDATE;
  IF d.status<>'recorded' THEN
    RAISE EXCEPTION 'only a pending delivery can be cancelled; reverse a confirmed one' USING ERRCODE='23514';
  END IF;
  IF d.recorded_by<>c.o_actor THEN PERFORM jw_dev.cinema_pg_require_admin(c.o_role); END IF;
  UPDATE jw_dev.cinema_pg_deliveries SET status='cancelled', closed_reason=btrim(coalesce(p_reason,''))
   WHERE org_id=c.o_org AND id=p_delivery_id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'delivery',p_delivery_id,d.trade_no,'cancel',
          jsonb_build_object('reason',p_reason),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'delivery',p_delivery_id);
  RETURN jw_dev.cinema_pg_result('delivery',p_delivery_id,false);
END $$;

-- Reversal of a confirmed delivery keeps the row and its audit trail.
CREATE FUNCTION jw_dev.cinema_pg_delivery_reverse(p_request_id text, p_delivery_id text, p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; d record; o record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'delivery_reverse',
     jsonb_build_object('delivery',p_delivery_id,'reason',p_reason));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO d FROM jw_dev.cinema_pg_deliveries WHERE org_id=c.o_org AND id=p_delivery_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'delivery not found' USING ERRCODE='P0002'; END IF;
  SELECT * INTO o FROM jw_dev.cinema_pg_orders WHERE org_id=c.o_org AND id=d.order_id FOR UPDATE;
  SELECT * INTO d FROM jw_dev.cinema_pg_deliveries WHERE org_id=c.o_org AND id=p_delivery_id FOR UPDATE;
  IF d.status<>'confirmed' THEN
    RAISE EXCEPTION 'only a confirmed delivery can be reversed' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_statements
   WHERE org_id=c.o_org AND delivery_id=p_delivery_id AND status<>'voided';
  IF FOUND THEN
    RAISE EXCEPTION 'void the statement for this delivery first' USING ERRCODE='23514';
  END IF;
  UPDATE jw_dev.cinema_pg_deliveries SET status='reversed', closed_reason=btrim(coalesce(p_reason,''))
   WHERE org_id=c.o_org AND id=p_delivery_id;
  IF o.status='fulfilled' THEN
    UPDATE jw_dev.cinema_pg_orders SET status='open', updated_at=clock_timestamp()
     WHERE org_id=c.o_org AND id=o.id;
  END IF;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'delivery',p_delivery_id,d.trade_no,'reverse',
          jsonb_build_object('reason',p_reason),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'delivery',p_delivery_id);
  RETURN jw_dev.cinema_pg_result('delivery',p_delivery_id,false);
END $$;

-- 7. Statement (거래명세서) drafted from CONFIRMED delivery lines only.
CREATE FUNCTION jw_dev.cinema_pg_statement_create(p_request_id text, p_delivery_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; d record; s record; v_id text;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'statement_create',
     jsonb_build_object('delivery',p_delivery_id));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  SELECT * INTO d FROM jw_dev.cinema_pg_deliveries WHERE org_id=c.o_org AND id=p_delivery_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'delivery not found' USING ERRCODE='P0002'; END IF;
  IF d.status<>'confirmed' THEN
    RAISE EXCEPTION 'statements require a confirmed delivery' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_statements
   WHERE org_id=c.o_org AND delivery_id=p_delivery_id AND status<>'voided';
  IF FOUND THEN
    RAISE EXCEPTION 'an active statement already exists for this delivery' USING ERRCODE='23505';
  END IF;
  SELECT * INTO s FROM jw_dev.cinema_pg_statement_source(c.o_org,p_delivery_id);
  v_id := jw_dev.cinema_pg_new_id();
  INSERT INTO jw_dev.cinema_pg_statements(id,org_id,trade_no,delivery_id,order_id,vat_mode,
         subtotal_krw,vat_krw,total_krw,source_sha256,status,created_by)
  VALUES (v_id,c.o_org,d.trade_no,d.id,d.order_id,s.o_vat_mode,s.o_subtotal,s.o_vat,
          s.o_subtotal+s.o_vat,s.o_hash,'draft',c.o_actor);
  INSERT INTO jw_dev.cinema_pg_statement_items(org_id,statement_id,position,order_item_id,name,quantity,unit_price)
  SELECT c.o_org,v_id,(row_number() OVER (ORDER BY oi.position))::integer-1,oi.id,oi.name,di.quantity,oi.unit_price
    FROM jw_dev.cinema_pg_delivery_items di
    JOIN jw_dev.cinema_pg_order_items oi ON oi.org_id=di.org_id AND oi.id=di.order_item_id
   WHERE di.org_id=c.o_org AND di.delivery_id=p_delivery_id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'statement',v_id,d.trade_no,'create',
          jsonb_build_object('delivery_id',d.id,'total_krw',s.o_subtotal+s.o_vat),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'statement',v_id);
  RETURN jw_dev.cinema_pg_result('statement',v_id,false);
END $$;

CREATE FUNCTION jw_dev.cinema_pg_statement_confirm(p_request_id text, p_statement_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; st record; s record; v_item_sum bigint;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'statement_confirm',
     jsonb_build_object('statement',p_statement_id));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO st FROM jw_dev.cinema_pg_statements WHERE org_id=c.o_org AND id=p_statement_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'statement not found' USING ERRCODE='P0002'; END IF;
  IF st.status<>'draft' THEN
    RAISE EXCEPTION 'only a draft statement can be confirmed' USING ERRCODE='23514';
  END IF;
  SELECT * INTO s FROM jw_dev.cinema_pg_statement_source(c.o_org,st.delivery_id);
  SELECT coalesce(sum(line_total),0) INTO v_item_sum FROM jw_dev.cinema_pg_statement_items
   WHERE org_id=c.o_org AND statement_id=st.id;
  IF s.o_subtotal<>st.subtotal_krw OR s.o_vat<>st.vat_krw OR s.o_hash<>st.source_sha256
     OR v_item_sum<>st.subtotal_krw THEN
    RAISE EXCEPTION 'statement does not match its confirmed delivery source' USING ERRCODE='23514';
  END IF;
  UPDATE jw_dev.cinema_pg_statements SET status='confirmed', confirmed_by=c.o_actor,
         confirmed_at=clock_timestamp() WHERE org_id=c.o_org AND id=st.id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'statement',st.id,st.trade_no,'confirm',
          jsonb_build_object('total_krw',st.total_krw),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'statement',st.id);
  RETURN jw_dev.cinema_pg_result('statement',st.id,false);
END $$;

CREATE FUNCTION jw_dev.cinema_pg_statement_void(p_request_id text, p_statement_id text, p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; st record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'statement_void',
     jsonb_build_object('statement',p_statement_id,'reason',p_reason));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO st FROM jw_dev.cinema_pg_statements WHERE org_id=c.o_org AND id=p_statement_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'statement not found' USING ERRCODE='P0002'; END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_invoices
   WHERE org_id=c.o_org AND statement_id=st.id AND status<>'voided';
  IF FOUND THEN
    RAISE EXCEPTION 'void the invoice for this statement first' USING ERRCODE='23514';
  END IF;
  UPDATE jw_dev.cinema_pg_statements SET status='voided', void_reason=btrim(coalesce(p_reason,''))
   WHERE org_id=c.o_org AND id=st.id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'statement',st.id,st.trade_no,'void',
          jsonb_build_object('reason',p_reason),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'statement',st.id);
  RETURN jw_dev.cinema_pg_result('statement',st.id,false);
END $$;

-- 8. Invoice (청구서): create from a confirmed statement, review, confirm, void.
CREATE FUNCTION jw_dev.cinema_pg_invoice_create(p_request_id text, p_statement_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; st record; v_id text; v_no text; v_n integer; v_item_sum bigint;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'invoice_create',
     jsonb_build_object('statement',p_statement_id));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  SELECT * INTO st FROM jw_dev.cinema_pg_statements WHERE org_id=c.o_org AND id=p_statement_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'statement not found' USING ERRCODE='P0002'; END IF;
  IF st.status<>'confirmed' THEN
    RAISE EXCEPTION 'invoices require a confirmed statement' USING ERRCODE='23514';
  END IF;
  IF st.subtotal_krw<=0 THEN
    RAISE EXCEPTION 'a zero-value statement cannot be invoiced' USING ERRCODE='23514';
  END IF;
  SELECT coalesce(sum(line_total),0) INTO v_item_sum FROM jw_dev.cinema_pg_statement_items
   WHERE org_id=c.o_org AND statement_id=st.id;
  IF v_item_sum<>st.subtotal_krw OR jw_dev.cinema_pg_vat(v_item_sum,st.vat_mode)<>st.vat_krw THEN
    RAISE EXCEPTION 'statement lines do not reconcile with statement totals' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_invoices
   WHERE org_id=c.o_org AND statement_id=st.id AND status<>'voided';
  IF FOUND THEN
    RAISE EXCEPTION 'an active invoice already exists for this statement' USING ERRCODE='23505';
  END IF;
  SELECT count(*)+1 INTO v_n FROM jw_dev.cinema_pg_invoices WHERE org_id=c.o_org AND trade_no=st.trade_no;
  v_no := 'INV-'||st.trade_no||'-'||to_char(v_n,'FM00');
  v_id := jw_dev.cinema_pg_new_id();
  INSERT INTO jw_dev.cinema_pg_invoices(id,org_id,trade_no,statement_id,order_id,invoice_no,
         subtotal_krw,vat_krw,total_krw,status,created_by)
  VALUES (v_id,c.o_org,st.trade_no,st.id,st.order_id,v_no,st.subtotal_krw,st.vat_krw,st.total_krw,'draft',c.o_actor);
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'invoice',v_id,st.trade_no,'create',
          jsonb_build_object('statement_id',st.id,'total_krw',st.total_krw),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'invoice',v_id);
  RETURN jw_dev.cinema_pg_result('invoice',v_id,false);
END $$;

CREATE FUNCTION jw_dev.cinema_pg_invoice_review(p_request_id text, p_invoice_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; i record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'invoice_review',
     jsonb_build_object('invoice',p_invoice_id));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO i FROM jw_dev.cinema_pg_invoices WHERE org_id=c.o_org AND id=p_invoice_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'invoice not found' USING ERRCODE='P0002'; END IF;
  IF i.status<>'draft' THEN
    RAISE EXCEPTION 'only a draft invoice can be reviewed' USING ERRCODE='23514';
  END IF;
  UPDATE jw_dev.cinema_pg_invoices SET status='reviewed', reviewed_by=c.o_actor,
         reviewed_at=clock_timestamp() WHERE org_id=c.o_org AND id=i.id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'invoice',i.id,i.trade_no,'review','{}'::jsonb,p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'invoice',i.id);
  RETURN jw_dev.cinema_pg_result('invoice',i.id,false);
END $$;

CREATE FUNCTION jw_dev.cinema_pg_invoice_confirm(p_request_id text, p_invoice_id text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; i record; st record; v_item_sum bigint;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'invoice_confirm',
     jsonb_build_object('invoice',p_invoice_id));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO i FROM jw_dev.cinema_pg_invoices WHERE org_id=c.o_org AND id=p_invoice_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'invoice not found' USING ERRCODE='P0002'; END IF;
  IF i.status<>'reviewed' THEN
    RAISE EXCEPTION 'only a reviewed invoice can be confirmed' USING ERRCODE='23514';
  END IF;
  SELECT * INTO st FROM jw_dev.cinema_pg_statements WHERE org_id=c.o_org AND id=i.statement_id;
  SELECT coalesce(sum(line_total),0) INTO v_item_sum FROM jw_dev.cinema_pg_statement_items
   WHERE org_id=c.o_org AND statement_id=st.id;
  IF st.status<>'confirmed' OR st.total_krw<>i.total_krw OR st.subtotal_krw<>i.subtotal_krw
     OR st.vat_krw<>i.vat_krw OR v_item_sum<>i.subtotal_krw THEN
    RAISE EXCEPTION 'invoice does not match its confirmed statement' USING ERRCODE='23514';
  END IF;
  UPDATE jw_dev.cinema_pg_invoices SET status='confirmed', confirmed_by=c.o_actor,
         confirmed_at=clock_timestamp() WHERE org_id=c.o_org AND id=i.id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'invoice',i.id,i.trade_no,'confirm',
          jsonb_build_object('total_krw',i.total_krw),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'invoice',i.id);
  RETURN jw_dev.cinema_pg_result('invoice',i.id,false);
END $$;

CREATE FUNCTION jw_dev.cinema_pg_invoice_void(p_request_id text, p_invoice_id text, p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; i record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'invoice_void',
     jsonb_build_object('invoice',p_invoice_id,'reason',p_reason));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO i FROM jw_dev.cinema_pg_invoices WHERE org_id=c.o_org AND id=p_invoice_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'invoice not found' USING ERRCODE='P0002'; END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_payments p
   WHERE p.org_id=c.o_org AND p.invoice_id=i.id
     AND NOT EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r WHERE r.org_id=p.org_id AND r.payment_id=p.id);
  IF FOUND THEN
    RAISE EXCEPTION 'reverse active payments before voiding the invoice' USING ERRCODE='23514';
  END IF;
  UPDATE jw_dev.cinema_pg_invoices SET status='voided', void_reason=btrim(coalesce(p_reason,''))
   WHERE org_id=c.o_org AND id=i.id;
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'invoice',i.id,i.trade_no,'void',
          jsonb_build_object('reason',p_reason),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'invoice',i.id);
  RETURN jw_dev.cinema_pg_result('invoice',i.id,false);
END $$;

-- 9. Internal payment record. Locks the invoice row so concurrent payments
--    cannot jointly overpay. NOT a bank settlement (bank_confirmed pinned false).
CREATE FUNCTION jw_dev.cinema_pg_payment_record(p_request_id text, p_invoice_id text,
   p_amount_krw bigint, p_paid_on date, p_reference text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; i record; v_paid bigint; v_id text;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'payment_record',
     jsonb_build_object('invoice',p_invoice_id,'amount',p_amount_krw,'paid_on',p_paid_on,'ref',p_reference));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  IF p_amount_krw IS NULL OR p_amount_krw<=0 THEN
    RAISE EXCEPTION 'payment amount must be a positive integer KRW' USING ERRCODE='23514';
  END IF;
  IF p_paid_on IS NULL OR p_paid_on>current_date THEN
    RAISE EXCEPTION 'paid_on must be a date that is not in the future' USING ERRCODE='23514';
  END IF;
  SELECT * INTO i FROM jw_dev.cinema_pg_invoices WHERE org_id=c.o_org AND id=p_invoice_id FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'invoice not found' USING ERRCODE='P0002'; END IF;
  IF i.status<>'confirmed' THEN
    RAISE EXCEPTION 'payments require a confirmed invoice' USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_payments
   WHERE org_id=c.o_org AND invoice_id=i.id AND reference=btrim(coalesce(p_reference,''));
  IF FOUND THEN
    RAISE EXCEPTION 'duplicate payment reference for this invoice' USING ERRCODE='23505';
  END IF;
  SELECT coalesce(sum(p.amount_krw),0) INTO v_paid FROM jw_dev.cinema_pg_payments p
   WHERE p.org_id=c.o_org AND p.invoice_id=i.id
     AND NOT EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r WHERE r.org_id=p.org_id AND r.payment_id=p.id);
  IF v_paid + p_amount_krw > i.total_krw THEN
    RAISE EXCEPTION 'overpayment blocked: balance is % KRW', i.total_krw-v_paid USING ERRCODE='23514';
  END IF;
  v_id := jw_dev.cinema_pg_new_id();
  INSERT INTO jw_dev.cinema_pg_payments(id,org_id,invoice_id,trade_no,amount_krw,paid_on,reference,recorded_by)
  VALUES (v_id,c.o_org,i.id,i.trade_no,p_amount_krw,p_paid_on,btrim(coalesce(p_reference,'')),c.o_actor);
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'payment',v_id,i.trade_no,'record',
          jsonb_build_object('invoice_id',i.id,'amount_krw',p_amount_krw,'basis','internal_record_only'),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'payment',v_id);
  RETURN jw_dev.cinema_pg_result('payment',v_id,false);
END $$;

CREATE FUNCTION jw_dev.cinema_pg_payment_reverse(p_request_id text, p_payment_id text, p_reason text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c record; p record;
BEGIN
  SELECT * INTO c FROM jw_dev.cinema_pg_begin(p_request_id,'payment_reverse',
     jsonb_build_object('payment',p_payment_id,'reason',p_reason));
  IF c.o_replay_id IS NOT NULL THEN
    RETURN jw_dev.cinema_pg_result(c.o_replay_type,c.o_replay_id,true);
  END IF;
  PERFORM jw_dev.cinema_pg_require_admin(c.o_role);
  SELECT * INTO p FROM jw_dev.cinema_pg_payments WHERE org_id=c.o_org AND id=p_payment_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'payment not found' USING ERRCODE='P0002'; END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_invoices WHERE org_id=c.o_org AND id=p.invoice_id FOR UPDATE;
  PERFORM 1 FROM jw_dev.cinema_pg_payment_reversals WHERE org_id=c.o_org AND payment_id=p.id;
  IF FOUND THEN
    RAISE EXCEPTION 'payment is already reversed' USING ERRCODE='23505';
  END IF;
  INSERT INTO jw_dev.cinema_pg_payment_reversals(org_id,payment_id,reason,reversed_by)
  VALUES (c.o_org,p.id,btrim(coalesce(p_reason,'')),c.o_actor);
  PERFORM jw_dev.cinema_pg_audit_add(c.o_org,c.o_actor,'payment',p.id,p.trade_no,'reverse',
          jsonb_build_object('reason',p_reason,'amount_krw',p.amount_krw),p_request_id);
  PERFORM jw_dev.cinema_pg_finish(c.o_org,p_request_id,'payment',p.id);
  RETURN jw_dev.cinema_pg_result('payment',p.id,false);
END $$;

-- 11. Trade-number trace: every document in the chain with measured timestamps.
CREATE FUNCTION jw_dev.cinema_pg_trade_trace(p_trade_no text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_org text; v_actor text; v_role text; v jsonb;
BEGIN
  SELECT i.actor_id,i.org_id,i.actor_role INTO v_actor,v_org,v_role FROM jw_dev.stage_identity_v84() i;
  IF v_org IS NULL THEN RAISE EXCEPTION 'valid session required' USING ERRCODE='42501'; END IF;
  PERFORM 1 FROM jw_dev.cinema_pg_quotes WHERE org_id=v_org AND trade_no=p_trade_no;
  IF NOT FOUND THEN RAISE EXCEPTION 'trade not found' USING ERRCODE='P0002'; END IF;
  SELECT jsonb_build_object(
    'trade_no',p_trade_no,
    'quotes',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM jw_dev.cinema_pg_quotes x WHERE x.org_id=v_org AND x.trade_no=p_trade_no),
    'orders',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM jw_dev.cinema_pg_orders x WHERE x.org_id=v_org AND x.trade_no=p_trade_no),
    'deliveries',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.seq),'[]'::jsonb) FROM jw_dev.cinema_pg_deliveries x WHERE x.org_id=v_org AND x.trade_no=p_trade_no),
    'statements',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM jw_dev.cinema_pg_statements x WHERE x.org_id=v_org AND x.trade_no=p_trade_no),
    'invoices',(SELECT coalesce(jsonb_agg(to_jsonb(x) || jsonb_build_object(
        'paid_krw',(SELECT coalesce(sum(p.amount_krw),0) FROM jw_dev.cinema_pg_payments p
                     WHERE p.org_id=x.org_id AND p.invoice_id=x.id
                       AND NOT EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r WHERE r.org_id=p.org_id AND r.payment_id=p.id)),
        'balance_krw',x.total_krw-(SELECT coalesce(sum(p.amount_krw),0) FROM jw_dev.cinema_pg_payments p
                     WHERE p.org_id=x.org_id AND p.invoice_id=x.id
                       AND NOT EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r WHERE r.org_id=p.org_id AND r.payment_id=p.id)))),
        '[]'::jsonb) FROM jw_dev.cinema_pg_invoices x WHERE x.org_id=v_org AND x.trade_no=p_trade_no AND x.status<>'voided'),
    'payments',(SELECT coalesce(jsonb_agg(to_jsonb(x) || jsonb_build_object('reversed',
        EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r WHERE r.org_id=x.org_id AND r.payment_id=x.id))
        ORDER BY x.recorded_at),'[]'::jsonb) FROM jw_dev.cinema_pg_payments x WHERE x.org_id=v_org AND x.trade_no=p_trade_no),
    'measured_seconds',(SELECT coalesce(jsonb_agg(jsonb_build_object('delivery_id',d.id,
        'record_to_confirm',extract(epoch FROM (d.approved_at-d.recorded_at)))),'[]'::jsonb)
        FROM jw_dev.cinema_pg_deliveries d WHERE d.org_id=v_org AND d.trade_no=p_trade_no AND d.approved_at IS NOT NULL),
    'audit',(SELECT coalesce(jsonb_agg(jsonb_build_object('at',a.created_at,'actor',a.actor_id,
        'entity',a.entity_type,'entity_id',a.entity_id,'action',a.action) ORDER BY a.seq),'[]'::jsonb)
        FROM jw_dev.cinema_pg_audit a WHERE a.org_id=v_org AND a.trade_no=p_trade_no),
    'flags',jsonb_build_object('bank_settlement_confirmed',false,
        'payment_basis','internal_record_only',
        'delivery_basis','human_admin_attested_evidence_hash',
        'evidence_basis','server_stored_and_rehashed',
        'release_ready',false)
  ) INTO v;
  RETURN v;
END $$;

-- Read-only integrity audit for the caller's tenant. A healthy tenant returns no rows.
CREATE FUNCTION jw_dev.cinema_pg_integrity_check()
RETURNS TABLE(check_name text, entity_id text, detail text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE v_org text;
BEGIN
  SELECT i.org_id INTO v_org FROM jw_dev.stage_identity_v84() i;
  IF v_org IS NULL THEN RAISE EXCEPTION 'valid session required' USING ERRCODE='42501'; END IF;
  RETURN QUERY
  SELECT 'delivered_exceeds_ordered', oi.id, 'ordered '||oi.quantity||' confirmed+pending '||s.q
    FROM jw_dev.cinema_pg_order_items oi
    JOIN LATERAL (SELECT coalesce(sum(di.quantity),0) q FROM jw_dev.cinema_pg_delivery_items di
                    JOIN jw_dev.cinema_pg_deliveries d ON d.org_id=di.org_id AND d.id=di.delivery_id
                   WHERE di.org_id=oi.org_id AND di.order_item_id=oi.id AND d.status IN ('recorded','confirmed')) s ON true
   WHERE oi.org_id=v_org AND s.q>oi.quantity;
  RETURN QUERY
  SELECT 'statement_total_mismatch', st.id, 'stored '||st.subtotal_krw||' lines '||l.q
    FROM jw_dev.cinema_pg_statements st
    JOIN LATERAL (SELECT coalesce(sum(line_total),0) q FROM jw_dev.cinema_pg_statement_items i
                   WHERE i.org_id=st.org_id AND i.statement_id=st.id) l ON true
   WHERE st.org_id=v_org AND st.status<>'voided' AND l.q<>st.subtotal_krw;
  RETURN QUERY
  SELECT 'statement_vat_mismatch', st.id, 'vat '||st.vat_krw||' expected '||jw_dev.cinema_pg_vat(st.subtotal_krw,st.vat_mode)
    FROM jw_dev.cinema_pg_statements st
   WHERE st.org_id=v_org AND st.vat_krw<>jw_dev.cinema_pg_vat(st.subtotal_krw,st.vat_mode);
  RETURN QUERY
  SELECT 'invoice_statement_mismatch', iv.id, 'invoice '||iv.total_krw||' statement '||st.total_krw
    FROM jw_dev.cinema_pg_invoices iv JOIN jw_dev.cinema_pg_statements st
      ON st.org_id=iv.org_id AND st.id=iv.statement_id
   WHERE iv.org_id=v_org AND iv.status<>'voided' AND iv.total_krw<>st.total_krw;
  RETURN QUERY
  SELECT 'overpaid_invoice', iv.id, 'paid '||p.q||' total '||iv.total_krw
    FROM jw_dev.cinema_pg_invoices iv
    JOIN LATERAL (SELECT coalesce(sum(x.amount_krw),0) q FROM jw_dev.cinema_pg_payments x
                   WHERE x.org_id=iv.org_id AND x.invoice_id=iv.id
                     AND NOT EXISTS(SELECT 1 FROM jw_dev.cinema_pg_payment_reversals r WHERE r.org_id=x.org_id AND r.payment_id=x.id)) p ON true
   WHERE iv.org_id=v_org AND p.q>iv.total_krw;
  RETURN QUERY
  SELECT 'confirmed_delivery_without_evidence', d.id, 'missing evidence hash or approver'
    FROM jw_dev.cinema_pg_deliveries d
   WHERE d.org_id=v_org AND d.status IN ('confirmed','reversed')
     AND (d.evidence_sha256 !~ '^[0-9a-f]{64}$' OR d.approved_by IS NULL OR d.approved_by=d.recorded_by);
  RETURN QUERY
  SELECT 'order_status_vs_deliveries', o.id, 'order '||o.status
    FROM jw_dev.cinema_pg_orders o
   WHERE o.org_id=v_org AND o.status IN ('open','fulfilled') AND (o.status='fulfilled') <>
        (NOT EXISTS (SELECT 1 FROM jw_dev.cinema_pg_order_items oi
                      WHERE oi.org_id=o.org_id AND oi.order_id=o.id
                        AND oi.quantity > coalesce((SELECT sum(di.quantity)
                              FROM jw_dev.cinema_pg_delivery_items di
                              JOIN jw_dev.cinema_pg_deliveries d ON d.org_id=di.org_id AND d.id=di.delivery_id
                             WHERE di.org_id=oi.org_id AND di.order_item_id=oi.id AND d.status='confirmed'),0)));
END $$;

-- --------------------------------------------------------- privileges
RESET ROLE;
REVOKE CREATE ON SCHEMA jw_dev FROM jw_cinema_owner;
REVOKE jw_cinema_owner FROM CURRENT_USER;

DO $grants$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig, p.proname
             FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname='jw_dev' AND p.proname LIKE 'cinema\_pg\_%' ESCAPE '\'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f.sig);
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO jw_cinema_owner', f.sig);
    IF f.proname IN ('cinema_pg_partner_upsert','cinema_pg_quote_create','cinema_pg_quote_update',
        'cinema_pg_evidence_put','cinema_pg_evidence_open','cinema_pg_quote_transition','cinema_pg_order_create','cinema_pg_delivery_record',
        'cinema_pg_delivery_confirm','cinema_pg_delivery_cancel','cinema_pg_delivery_reverse',
        'cinema_pg_statement_create','cinema_pg_statement_confirm','cinema_pg_statement_void',
        'cinema_pg_invoice_create','cinema_pg_invoice_review','cinema_pg_invoice_confirm',
        'cinema_pg_invoice_void','cinema_pg_payment_record','cinema_pg_payment_reverse',
        'cinema_pg_trade_trace','cinema_pg_integrity_check') THEN
      EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO jw_cinema_writer', f.sig);
    END IF;
  END LOOP;
END $grants$;
