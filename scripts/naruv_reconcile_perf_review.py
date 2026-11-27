"""Concurrent native ERP workload against exact review source in disposable PG17.
No hosted DB, source rows, real credentials, production SLA or production posting.
"""
import importlib.util
import json
import os
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from threading import Barrier
import time
from statistics import median
import psycopg
from psycopg.types.json import Jsonb

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owner',HERE/'naruv_auth_owner_review.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
t=o.t;v=o.v;s=o.s;b=o.b;base=o.base;need=b.need
WORKERS=4
BATCHES=10
TENANTS={'A':('ci-a','ci-ua','source-a',105),'B':('ci-b','ci-ub','source-b',205)}
def measure_candidate(fixture,trade_dsn,tokens,expected):
    source=base.ROOT/'db/review/naruv_valuation_ci.sql'
    old=b.pin(source,'0351c73151be51612d563afd7c4e8e8af7bbdf36')
    candidate=b.pin(HERE.parent/'db/review/naruv_reconcile_bill_aggregate_candidate.sql','07fc6dd4ae72e27ed005b27143e1087437d6adf9')
    def body(s):
        start=s.index('FUNCTION naruv_valuation.reconcile_bill(')
        start=s.index('AS $$',start)+5
        return s[start:s.index('$$;',start)]
    before=body(old); after=body(candidate)
    sig='naruv_valuation.reconcile_bill(text,text)'
    def meta(c):
        return c.execute("SELECT proowner,proacl::text,prosecdef,provolatile,proconfig,prosrc FROM pg_proc WHERE oid=%s::regprocedure",(sig,)).fetchone()
    def apply(expected,replacement):
        base.preflight()
        with psycopg.connect(fixture.root_dsn) as c:
            # Docker NAT changes the server-side address; verify the actual
            # client endpoint and the pinned disposable fixture instead.
            need(c.info.host=='127.0.0.1' and c.info.port==5432 and c.execute("SELECT current_database(),session_user,current_setting('server_version_num')::int BETWEEN 170000 AND 179999").fetchone()==('postgres','postgres',True),'LOCAL_SCOPE')
            m=meta(c)
            need(m[2:5]==(True,'v',['search_path=pg_catalog']) and m[5]==expected,'CANDIDATE_SOURCE')
            definition=c.execute('SELECT pg_get_functiondef(%s::regprocedure)',(sig,)).fetchone()[0]
            need(definition.count(expected)==1,'DEFINITION_BOUNDARY')
            c.execute(definition.replace(expected,replacement))
            n=meta(c)
            need(n[:5]==m[:5] and n[5]==replacement,'CANDIDATE_ACL_OR_BODY')
    results=[]
    def sample():
        readings=[]
        for who in TENANTS:
            csrf=fixture.CSRF[who]
            bill='load-'+str(0 if who=='A' else 1)+'-0-bill'
            with psycopg.connect(trade_dsn,autocommit=True) as c:
                c.execute("SET statement_timeout='30s'")
                for i in range(6):
                    with c.transaction():
                        b.bind(c,tokens[who])
                        start=time.perf_counter()
                        receipt=b.rpc(c,'naruv_valuation.reconcile_bill',bill,csrf)
                        single=(time.perf_counter()-start)*1000
                        start=time.perf_counter()
                        ledger=b.rpc(c,'naruv_valuation.audit_ledger',csrf)
                        full=(time.perf_counter()-start)*1000
                        need(ledger==expected[who],'AUDIT_RESULT_DRIFT')
                    # First pair is a warmup; measured values still checked.
                    readings.append((who,i,receipt,ledger,single,full))
        return readings
    active=before
    reference=None
    try:
        for arm in ('baseline','candidate','candidate','baseline'):
            target=before if arm=='baseline' else after
            if target!=active:
                apply(active,target)
                active=target
            rows=sample()
            state=[(who,i,receipt,ledger) for who,i,receipt,ledger,_,_ in rows]
            if reference is None: reference=state
            need(state==reference,'BENCH_RESULT_DRIFT')
            selected=[r for r in rows if r[1]>0]
            need(len(selected)==10,'SAMPLE_COUNT')
            row=dict(arm=arm,samples=len(selected),
                bill_median_ms=round(median(r[4] for r in selected),3),
                ledger_median_ms=round(median(r[5] for r in selected),3))
            results.append(row)
            print('RECONCILE_PERF_ARM',json.dumps(row),flush=True)
    finally:
        if active!=before: apply(active,before)
    with psycopg.connect(fixture.root_dsn) as c:
        need(meta(c)[5]==before,'ORIGINAL_NOT_RESTORED')
    summary={arm:{k:median(r[k] for r in results if r['arm']==arm)
        for k in ('bill_median_ms','ledger_median_ms')} for arm in ('baseline','candidate')}
    print('RECONCILE_PERF_RESULT',json.dumps(summary,sort_keys=True),flush=True)
    print('RECONCILE_PERF_EQUIVALENCE_PASS 40_BILL_40_LEDGER_SAMPLES',flush=True)
def main():
    base.preflight()
    b.pin(HERE/'naruv_native_auth_bridge_review.py','af21613738e407bfe5bb17be1a9c164c90bac1c2')
    b.pin(HERE/'naruv_auth_owner_review.py','6b382d88591c9b198ce54fadc1765dbf09948d9a')
    fixture,_=base.setup()
    b.install(fixture);s.install(fixture)
    auth_dsn,_,_,_,digest=v.install(fixture)
    o.install(fixture)
    cert=Path(os.environ['NARUV_TLS_CA']).resolve(strict=True)
    auth_dsn=t.tls(auth_dsn,cert)
    trade_dsn=t.tls(fixture.TRADE_DSN,cert)
    t.assert_tls(auth_dsn,'naruv_v85_cutover_ci')
    t.assert_tls(trade_dsn,'jw_ci_trade')
    from scripts.naruv_native_write_review_ci import NativeWrite
    native=NativeWrite('test_csv_full_flow_and_exact_retry')
    tokens={who:base.session_hash(fixture,who) for who in TENANTS}
    with psycopg.connect(auth_dsn,autocommit=True) as a:
        a.execute('SET ROLE jw_auth_stage_v85')
        for who,(_,actor,_,_) in TENANTS.items():
            result=a.execute('SELECT jw_dev.v85_auth_issue_session(%s,%s,%s,NULL,%s)',
                             (actor,tokens[who],fixture.CSRF[who],digest if who=='B' else None)).fetchone()
            need(bool(result[0]),'WORKLOAD_SESSION')
    for who,(org,actor,source,price) in TENANTS.items():
        csrf=fixture.CSRF[who]
        d=native.stage('load-items',b'sku,item_name,unit\n002,Bolt,EA\n003,Assembly,EA\n',source,'item','csv',who)
        native.check(native.approve(d,'load-items',who),200)
        native.check(native.commit(d,'load-items','load-items-commit',who),200)
        with psycopg.connect(trade_dsn) as c:
            b.bind(c,tokens[who])
            for item in ('001','002'):
                b.rpc(c,'naruv_valuation.receive',item,'load-opening-'+item,
                      Jsonb(dict(source_id=source,warehouse_id='W1',quantity=100,unit_cost=price)),True,csrf)
            b.cmd(c,'naruv_production','load-bom','load-bom-define','define',
                  dict(source_id=source,product_id='003',lines=[dict(material_id='001',per_unit=1),dict(material_id='002',per_unit=1)]),csrf)
    print('NATIVE_WORKLOAD_SEED_PASS tenants=2 items_per_tenant=3 opening_quantity=200',flush=True)
    barrier=Barrier(WORKERS)
    def worker(i):
        who='AB'[i%2]
        org,actor,source,price=TENANTS[who];csrf=fixture.CSRF[who]
        times=[]
        with psycopg.connect(trade_dsn,autocommit=True) as c:
            need(c.execute("SELECT session_user,ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()==('jw_ci_trade',True),'WORKLOAD_DIRECT_TLS')
            c.execute("SET statement_timeout='30s'")
            c.execute("SET lock_timeout='10s'")
            barrier.wait(timeout=20)
            for j in range(BATCHES):
                key='load-'+str(i)+'-'+str(j)
                start=time.perf_counter()
                with c.transaction():
                    b.bind(c,tokens[who])
                    payload=dict(kind='purchase',counterparty_id='ci-customer-'+who.lower(),
                        source_id=source,item_id='001',warehouse_id='W1',quantity=2,unit_price=price,vat_mode='taxable')
                    first=b.cmd(c,'naruv_trade',key+'-purchase',key+'-open','open',payload,csrf)
                    need(b.cmd(c,'naruv_trade',key+'-purchase',key+'-open','open',payload,csrf)==first,'WORKLOAD_REPLAY')
                    b.cmd(c,'naruv_trade',key+'-purchase',key+'-fulfill','fulfill',dict(quantity=2),csrf)
                    b.cmd(c,'naruv_finance',key+'-bill',key+'-bill-request','bill',dict(doc_id=key+'-purchase',fulfillment_id=key+'-fulfill'),csrf)
                    b.cmd(c,'naruv_production',key+'-job',key+'-job-open','open',dict(bom_id='load-bom',warehouse_id='W1',quantity=1),csrf)
                    b.cmd(c,'naruv_production',key+'-job',key+'-complete','complete',dict(quantity=1),csrf)
                    journal=b.rpc(c,'naruv_accounting.inspect_bill',key+'-bill',csrf)
                    need(journal['debit']==journal['credit'] and journal['journal_count']==1,'WORKLOAD_JOURNAL')
                times.append((time.perf_counter()-start)*1000)
        return times
    started=time.perf_counter()
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        times=sorted(x for batch in pool.map(worker,range(WORKERS)) for x in batch)
    elapsed=time.perf_counter()-started
    count=WORKERS*BATCHES
    need(len(times)==count,'WORKLOAD_COMMIT_COUNT')
    per_tenant=count//2
    final={}
    expected_ledgers={}
    for who,(org,actor,source,price) in TENANTS.items():
        csrf=fixture.CSRF[who]
        with psycopg.connect(trade_dsn) as c:
            b.bind(c,tokens[who])
            expected={'001':100+per_tenant,'002':100-per_tenant,'003':per_tenant}
            quantities={}
            for item,qty in expected.items():
                stock=b.rpc(c,'naruv_valuation.inspect',source,item,'W1',csrf)
                need(int(stock['quantity'])==qty,'WORKLOAD_STOCK_'+who+'_'+item)
                need(Decimal(stock['value_krw'])==Decimal(qty*price*(2 if item=='003' else 1)),'WORKLOAD_VALUE_'+who+'_'+item)
                quantities[item]=qty
            ledger=b.rpc(c,'naruv_valuation.audit_ledger',csrf)
            expected_value=Decimal((200+2*per_tenant)*price)
            need(ledger['status']=='RECONCILED' and Decimal(ledger['inventory_krw'])==expected_value
                 and Decimal(ledger['journal_inventory_krw'])==expected_value and Decimal(ledger['wip_krw'])==0,'WORKLOAD_LEDGER_'+who)
            final[who]={'quantities':quantities,'inventory_krw':int(expected_value)}
            expected_ledgers[who]=ledger
    with psycopg.connect(fixture.root_dsn) as c:
        for who,(org,_,_,_) in TENANTS.items():
            for table in ('naruv_trade.documents','naruv_finance.bills','naruv_production.orders'):
                need(c.execute('SELECT count(*) FROM '+table+' WHERE org_id=%s',(org,)).fetchone()==(per_tenant,),'WORKLOAD_ROW_COUNT_'+table)
    measure_candidate(fixture,trade_dsn,tokens,expected_ledgers)
    print('RECONCILE_PERF_REVIEW_PASS production_authorized=false hosted_load=false',flush=True)
if __name__=='__main__':main()
