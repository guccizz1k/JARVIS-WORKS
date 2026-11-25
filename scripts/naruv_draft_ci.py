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
        c.execute("INSERT INTO naruv_draft.staff VALUES(%s,'worker-1',true)",(org,))
        c.execute("INSERT INTO naruv_draft.pay_periods VALUES(%s,'worker-1','2026-11','policy-1',%s,15000,true)",(org,rate))
        c.execute("INSERT INTO naruv_draft.attendance VALUES(%s,'worker-1','2026-11','2026-11-25',480,60)",(org,))
        c.execute("INSERT INTO naruv_draft.pay_periods VALUES(%s,'worker-1','2026-10','policy-1',%s,15000,false)",(org,rate))
