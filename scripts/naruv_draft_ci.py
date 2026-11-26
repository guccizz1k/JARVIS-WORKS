"""CI-only server-owned draft data; no real people or documents."""
import hashlib
import json
import os
import psycopg

def seed(c):
    for org,rate in (("ci-a",12000),("ci-b",18000)):
        raw=("synthetic document "+org).encode()
        obs=[dict(field=k,value=v,page=1) for k,v in (
            ("document_kind","invoice"),("counterparty_id","fixture-customer"),
            ("document_date","2026-11-25"),("reference_number","fixture-ref"),
            ("subtotal",100),("vat",10),("gross_amount",110))]
        c.execute("INSERT INTO naruv_draft.documents VALUES(%s,'shared','rev-1',%s,%s,%s::jsonb,true)",
                  (org,raw,hashlib.sha256(raw).hexdigest(),json.dumps(obs)))
        n=c.execute("""INSERT INTO naruv_draft.document_admissions(org_id,document_id,request_id,actor_id,format,source_sha256,observation_sha256)
          SELECT org_id,document_id,revision,'fixture-seed','pdf',original_sha256,encode(sha256(convert_to(observations::text,'UTF8')),'hex')
          FROM naruv_draft.documents WHERE org_id=%s AND document_id='shared'""",(org,)).rowcount
        if n!=1:raise RuntimeError("DOC_FIXTURE_PROOF_COUNT")
        c.execute("INSERT INTO naruv_draft.staff VALUES(%s,'worker-1',true)",(org,))
        c.execute("INSERT INTO naruv_draft.pay_periods VALUES(%s,'worker-1','2026-11','policy-1',%s,15000,true)",(org,rate))
        c.execute("INSERT INTO naruv_draft.attendance VALUES(%s,'worker-1','2026-11','2026-11-25',480,60)",(org,))
        c.execute("INSERT INTO naruv_draft.pay_periods VALUES(%s,'worker-1','2026-10','policy-1',%s,15000,false)",(org,rate))
        for period in ("2026-08","2026-09"):
            c.execute("INSERT INTO naruv_draft.pay_periods VALUES(%s,'worker-1',%s,'policy-1',%s,15000,false)",(org,period,rate))

def seed_confirmation_proofs(c):
    # Only fixture root on the already verified disposable CI cluster.
    # Existing confirmed November synthetic fixture receives explicit proof.
    n=c.execute("""INSERT INTO naruv_draft.period_confirmations(org_id,worker_id,period,request_id,actor_id,review_sha256)
       SELECT p.org_id,p.worker_id,p.period,'fixture-nov-confirm','fixture-seed',
         naruv_draft.period_digest(p.org_id,p.worker_id,p.period,p.revision,p.hourly_krw,p.additional_bps,
           (SELECT jsonb_agg(jsonb_build_array(to_char(d.work_day,'YYYY-MM-DD'),d.regular,d.additional) ORDER BY d.work_day)
            FROM naruv_draft.attendance d WHERE (d.org_id,d.worker_id,d.period)=(p.org_id,p.worker_id,p.period)))
       FROM naruv_draft.pay_periods p WHERE p.period='2026-11' AND p.confirmed AND p.worker_id='worker-1' AND p.org_id IN ('ci-a','ci-b')""").rowcount
    if n!=2:raise RuntimeError("HR_FIXTURE_CONFIRMATION_COUNT")
