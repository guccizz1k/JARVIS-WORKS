-- Disposable PG17 accounting review only; no statutory or production posting.
DO $$ BEGIN
 IF current_database()<>'postgres' OR current_setting('server_version_num')::int NOT BETWEEN 170000 AND 179999
 OR session_user<>'postgres' OR current_setting('naruv.accounting_ci',true) IS DISTINCT FROM 'DISPOSABLE_ONLY'
 THEN RAISE EXCEPTION 'NARUV_ACCOUNTING_DISPOSABLE_ONLY'; END IF;
 IF EXISTS(SELECT 1 FROM naruv_finance.events) THEN
  RAISE EXCEPTION 'ACCT_NONEMPTY_BASELINE';
 END IF;
END $$;
CREATE SCHEMA naruv_accounting AUTHORIZATION naruv_native_owner;
REVOKE ALL ON SCHEMA naruv_accounting FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT USAGE ON SCHEMA naruv_accounting TO jw_app_dev;
SET ROLE naruv_native_owner;
CREATE TABLE naruv_accounting.periods(
 org_id text NOT NULL,period_start date NOT NULL CHECK(extract(day FROM period_start)=1),
 closed_at timestamptz,closed_by text,
 PRIMARY KEY(org_id,period_start),CHECK((closed_at IS NULL)=(closed_by IS NULL))
);
CREATE TABLE naruv_accounting.journals(
 org_id text NOT NULL,event_id text NOT NULL,bill_id text NOT NULL,period_start date NOT NULL,
 actor_id text NOT NULL,action text NOT NULL CHECK(action IN ('bill','pay','reverse','credit')),
 posted_at timestamptz NOT NULL,reversal_of text,
 PRIMARY KEY(org_id,event_id),UNIQUE(org_id,reversal_of),
 FOREIGN KEY(org_id,event_id) REFERENCES naruv_finance.events(org_id,request_id),
 FOREIGN KEY(org_id,bill_id) REFERENCES naruv_finance.bills,
 FOREIGN KEY(org_id,period_start) REFERENCES naruv_accounting.periods,
 FOREIGN KEY(org_id,reversal_of) REFERENCES naruv_accounting.journals(org_id,event_id),
 CHECK((action='reverse')=(reversal_of IS NOT NULL))
);
CREATE TABLE naruv_accounting.lines(
 org_id text NOT NULL,event_id text NOT NULL,line_no smallint NOT NULL CHECK(line_no BETWEEN 1 AND 3),
 account text NOT NULL CHECK(account IN ('AR','AP','SALES','PURCHASE_CLEARING','VAT_OUTPUT','VAT_INPUT','CASH_CLEARING')),
 debit bigint NOT NULL CHECK(debit BETWEEN 0 AND 110000000000000),
 credit bigint NOT NULL CHECK(credit BETWEEN 0 AND 110000000000000),
 PRIMARY KEY(org_id,event_id,line_no),FOREIGN KEY(org_id,event_id) REFERENCES naruv_accounting.journals,
 CHECK((debit>0 AND credit=0) OR (credit>0 AND debit=0))
);
CREATE INDEX journal_bill ON naruv_accounting.journals(org_id,bill_id);
DO $$ DECLARE t text; BEGIN
 FOREACH t IN ARRAY ARRAY['periods','journals','lines'] LOOP
  EXECUTE format('ALTER TABLE naruv_accounting.%I ENABLE ROW LEVEL SECURITY',t);
  EXECUTE format('ALTER TABLE naruv_accounting.%I FORCE ROW LEVEL SECURITY',t);
  EXECUTE format('CREATE POLICY accounting_scope ON naruv_accounting.%I TO naruv_native_owner USING (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin'')) WITH CHECK (org_id=(SELECT i.org_id FROM jw_dev.stage_identity_v84() i WHERE i.actor_role=''admin''))',t);
  EXECUTE format('REVOKE ALL ON naruv_accounting.%I FROM PUBLIC,jw_app_dev,naruv_native_stage',t);
 END LOOP;
END $$;
CREATE TRIGGER journals_immutable BEFORE UPDATE OR DELETE ON naruv_accounting.journals
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE TRIGGER lines_immutable BEFORE UPDATE OR DELETE ON naruv_accounting.lines
 FOR EACH ROW EXECUTE FUNCTION naruv_native_review.immutable();
CREATE FUNCTION naruv_accounting.period_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'ACCT_PERIOD_IMMUTABLE'; END IF;
 IF OLD.closed_at IS NOT NULL OR (OLD.org_id,OLD.period_start) IS DISTINCT FROM (NEW.org_id,NEW.period_start)
 OR NEW.closed_at IS NULL OR NEW.closed_by IS NULL THEN RAISE EXCEPTION 'ACCT_PERIOD_IMMUTABLE'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER period_guard BEFORE UPDATE OR DELETE ON naruv_accounting.periods
 FOR EACH ROW EXECUTE FUNCTION naruv_accounting.period_guard();
CREATE FUNCTION naruv_accounting.validate_journal() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE expected bigint; dr numeric; cr numeric; cnt bigint;
BEGIN
 SELECT CASE WHEN e.action='bill' THEN b.total ELSE e.amount END INTO expected
 FROM naruv_finance.events e JOIN naruv_finance.bills b ON (b.org_id,b.bill_id)=(e.org_id,e.bill_id)
 WHERE e.org_id=NEW.org_id AND e.request_id=NEW.event_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
 SELECT coalesce(sum(l.debit),0),coalesce(sum(l.credit),0),count(*) INTO dr,cr,cnt
 FROM naruv_accounting.lines l WHERE l.org_id=NEW.org_id AND l.event_id=NEW.event_id;
 IF dr<>expected OR cr<>expected OR (expected>0 AND cnt NOT BETWEEN 2 AND 3)
 OR (expected=0 AND cnt<>0) THEN RAISE EXCEPTION 'ACCT_UNBALANCED'; END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER journal_balance AFTER INSERT ON naruv_accounting.journals
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_accounting.validate_journal();
CREATE CONSTRAINT TRIGGER line_balance AFTER INSERT ON naruv_accounting.lines
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION naruv_accounting.validate_journal();
CREATE FUNCTION naruv_accounting.post_finance() RETURNS trigger
 LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
DECLARE b naruv_finance.bills; p naruv_accounting.periods; a record; month_start date;
BEGIN
 IF current_user<>'naruv_native_owner' THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT i.actor_id,i.org_id,i.actor_role INTO a FROM jw_dev.stage_identity_v84() i;
 IF NOT FOUND OR (a.actor_id,a.org_id,a.actor_role) IS DISTINCT FROM (NEW.actor_id,NEW.org_id,'admin'::text)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 month_start:=date_trunc('month',NEW.created_at AT TIME ZONE 'Asia/Seoul')::date;
 SELECT * INTO p FROM naruv_accounting.periods x WHERE x.org_id=NEW.org_id AND x.period_start=month_start FOR UPDATE;
 IF NOT FOUND OR p.closed_at IS NOT NULL THEN RAISE EXCEPTION 'ACCT_PERIOD_CLOSED'; END IF;
 SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=NEW.org_id AND x.bill_id=NEW.bill_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
 INSERT INTO naruv_accounting.journals VALUES(NEW.org_id,NEW.request_id,NEW.bill_id,month_start,NEW.actor_id,NEW.action,NEW.created_at,NEW.reversal_of);
 IF NEW.action='bill' THEN
  IF b.total=0 THEN RETURN NEW; END IF;
  IF b.kind='sale' THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AR',b.total,0);
   IF b.subtotal>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,2,'SALES',0,b.subtotal); END IF;
   IF b.vat>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,3,'VAT_OUTPUT',0,b.vat); END IF;
  ELSE
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AP',0,b.total);
   IF b.subtotal>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,2,'PURCHASE_CLEARING',b.subtotal,0); END IF;
   IF b.vat>0 THEN INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,3,'VAT_INPUT',b.vat,0); END IF;
  END IF;
 ELSIF NEW.action='pay' THEN
  IF b.kind='sale' THEN
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'CASH_CLEARING',NEW.amount,0),(NEW.org_id,NEW.request_id,2,'AR',0,NEW.amount);
  ELSE
   INSERT INTO naruv_accounting.lines VALUES(NEW.org_id,NEW.request_id,1,'AP',NEW.amount,0),(NEW.org_id,NEW.request_id,2,'CASH_CLEARING',0,NEW.amount);
  END IF;
 ELSIF NEW.action='credit' THEN
  IF NEW.amount<>b.total OR naruv_finance.paid(NEW.org_id,NEW.bill_id)<>0 THEN RAISE EXCEPTION 'ACCT_RECONCILIATION'; END IF;
  IF NOT EXISTS(SELECT 1 FROM naruv_accounting.journals j WHERE j.org_id=NEW.org_id AND j.bill_id=NEW.bill_id AND j.action='bill')
  THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
  INSERT INTO naruv_accounting.lines
   SELECT NEW.org_id,NEW.request_id,l.line_no,l.account,l.credit,l.debit
   FROM naruv_accounting.lines l JOIN naruv_accounting.journals j USING(org_id,event_id)
   WHERE j.org_id=NEW.org_id AND j.bill_id=NEW.bill_id AND j.action='bill';
 ELSE
  IF NOT EXISTS(SELECT 1 FROM naruv_accounting.journals j WHERE j.org_id=NEW.org_id AND j.event_id=NEW.reversal_of AND j.bill_id=NEW.bill_id AND j.action='pay')
  THEN RAISE EXCEPTION 'ACCT_SOURCE_MISSING'; END IF;
  INSERT INTO naruv_accounting.lines SELECT NEW.org_id,NEW.request_id,l.line_no,l.account,l.credit,l.debit
   FROM naruv_accounting.lines l WHERE l.org_id=NEW.org_id AND l.event_id=NEW.reversal_of;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER accounting_post AFTER INSERT ON naruv_finance.events
 FOR EACH ROW EXECUTE FUNCTION naruv_accounting.post_finance();
CREATE FUNCTION naruv_accounting.close_period(p_month text,p_confirm boolean,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; a2 record; p naruv_accounting.periods; m date;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 IF p_confirm IS DISTINCT FROM true OR p_month IS NULL OR p_month !~ '^[0-9]{4}-(0[1-9]|1[0-2])-01$' OR left(p_month,4)='0000'
 THEN RAISE EXCEPTION 'ACCT_INPUT'; END IF;
 m:=p_month::date;
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO a2 FROM naruv_native_review.guard(p_csrf,'business');
 IF (a.actor_id,a.org_id,a.auth_epoch,a.session_binding_sha256) IS DISTINCT FROM (a2.actor_id,a2.org_id,a2.auth_epoch,a2.session_binding_sha256)
 THEN RAISE EXCEPTION 'NARUV_PERMISSION_DENIED' USING ERRCODE='42501'; END IF;
 SELECT * INTO p FROM naruv_accounting.periods x WHERE x.org_id=a.org_id AND x.period_start=m FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_NOT_FOUND'; END IF;
 IF p.closed_at IS NULL THEN
  UPDATE naruv_accounting.periods x SET closed_at=clock_timestamp(),closed_by=a.actor_id
   WHERE x.org_id=a.org_id AND x.period_start=m RETURNING * INTO p;
 END IF;
 RETURN jsonb_build_object('period_start',p.period_start,'state','CLOSED','closed_at',p.closed_at,'production_authorized',false);
END $$;
CREATE FUNCTION naruv_accounting.inspect_bill(p_bill text,p_csrf text) RETURNS jsonb
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE a record; b naruv_finance.bills; paid_amt bigint; ar numeric; ap numeric; dr numeric; cr numeric; entries jsonb; n bigint; jn bigint; due bigint;
BEGIN
 SELECT * INTO a FROM naruv_native_review.guard(p_csrf,'business');
 PERFORM pg_advisory_xact_lock(hashtextextended('naruv-inventory-v1:'||a.org_id,0));
 SELECT * INTO b FROM naruv_finance.bills x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 IF NOT FOUND THEN RAISE EXCEPTION 'ACCT_NOT_FOUND'; END IF;
 paid_amt:=naruv_finance.paid(a.org_id,p_bill);
 SELECT count(*) INTO n FROM naruv_finance.events x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 SELECT count(*) INTO jn FROM naruv_accounting.journals x WHERE x.org_id=a.org_id AND x.bill_id=p_bill;
 SELECT coalesce(sum(l.debit),0),coalesce(sum(l.credit),0),
 coalesce(sum(l.debit-l.credit) FILTER(WHERE l.account='AR'),0),
 coalesce(sum(l.credit-l.debit) FILTER(WHERE l.account='AP'),0)
 INTO dr,cr,ar,ap FROM naruv_accounting.lines l JOIN naruv_accounting.journals j USING(org_id,event_id)
 WHERE j.org_id=a.org_id AND j.bill_id=p_bill;
 due:=CASE WHEN naruv_finance.credited(a.org_id,p_bill) THEN 0 ELSE b.total-paid_amt END;
 IF (naruv_finance.credited(a.org_id,p_bill) AND paid_amt<>0) OR n<>jn OR n=0 OR dr<>cr OR paid_amt<0 OR paid_amt>b.total
 OR ar<>(CASE WHEN b.kind='sale' THEN due ELSE 0 END)
 OR ap<>(CASE WHEN b.kind='purchase' THEN due ELSE 0 END) THEN RAISE EXCEPTION 'ACCT_RECONCILIATION'; END IF;
 SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY x.account),'[]'::jsonb) INTO entries FROM (
  SELECT l.account,sum(l.debit) AS debit,sum(l.credit) AS credit FROM naruv_accounting.lines l
  JOIN naruv_accounting.journals j USING(org_id,event_id) WHERE j.org_id=a.org_id AND j.bill_id=p_bill GROUP BY l.account
 ) x;
 RETURN jsonb_build_object('bill_id',p_bill,'journal_count',jn,'debit',dr,'credit',cr,'ar',ar,'ap',ap,
 'outstanding',due,'accounts',entries,'production_authorized',false);
END $$;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA naruv_accounting FROM PUBLIC,jw_app_dev,naruv_native_stage;
GRANT EXECUTE ON FUNCTION naruv_accounting.close_period(text,boolean,text),naruv_accounting.inspect_bill(text,text) TO jw_app_dev;
RESET ROLE;
INSERT INTO naruv_accounting.periods(org_id,period_start) SELECT id,date_trunc('month',clock_timestamp() AT TIME ZONE 'Asia/Seoul')::date
 FROM jw_dev.organizations WHERE id IN ('ci-a','ci-b');
