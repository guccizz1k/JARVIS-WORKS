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
import io
from openpyxl import Workbook
import psycopg
from psycopg.types.json import Jsonb

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owner',HERE/'naruv_auth_owner_review.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
t=o.t;v=o.v;s=o.s;b=o.b;base=o.base;need=b.need
WORKERS=4
BATCHES=10
TENANTS={'A':('ci-a','ci-ua','source-a',105),'B':('ci-b','ci-ub','source-b',205)}
def activate_reconciliation(fixture):
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
    apply(before,after)
    return lambda: apply(after,before)
def main():
    base.preflight()
    b.pin(HERE/'naruv_native_auth_bridge_review.py','af21613738e407bfe5bb17be1a9c164c90bac1c2')
    b.pin(HERE/'naruv_auth_owner_review.py','6b382d88591c9b198ce54fadc1765dbf09948d9a')
    from app import naruv_native_write_review as mod
    need('Fresh restricted transaction' in __import__('inspect').getsource(mod._stage),'SPLIT_MODULE_NOT_LOADED')
    fixture,_=base.setup()
    b.install(fixture);s.install(fixture)
    auth_dsn,_,_,_,digest=v.install(fixture)
    o.install(fixture)
    restore=activate_reconciliation(fixture)
    try:
        exercise(fixture,auth_dsn,digest)
    finally:
        restore()
    print('COMBINED_CANDIDATE_REVIEW_PASS production_authorized=false hosted_load=false',flush=True)
def exercise(fixture,auth_dsn,digest):
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
        raw=b'sku,item_name,unit\n002,Bolt,EA\n003,Assembly,EA\n'
        fmt='csv'
        if who=='B':
            workbook=Workbook()
            workbook.active.append(['sku','item_name','unit'])
            workbook.active.append(['002','Bolt','EA'])
            workbook.active.append(['003','Assembly','EA'])
            buf=io.BytesIO();workbook.save(buf);workbook.close()
            raw=buf.getvalue();fmt='xlsx'
        d=native.stage('load-items',raw,source,'item',fmt,who)
        native.check(native.approve(d,'load-items',who),200)
        first=native.check(native.commit(d,'load-items','load-items-commit',who),200)
        need(first['status']=='REVIEW_COMMITTED' and first['row_import_authorized'] is False,'IMPORT_COMMIT')
        need(native.check(native.commit(d,'load-items','load-items-commit',who),200)==first,'IMPORT_EXACT_RETRY')
        need(native.check(native.req('/stages/load-items/receipt/load-items-commit',who),200)==first,'IMPORT_RECEIPT')
        print('COMBINED_IMPORT_COMMIT_PASS',who,fmt,flush=True)
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
    with psycopg.connect(fixture.root_dsn) as c:
        for who,(org,_,_,_) in TENANTS.items():
            for table in ('naruv_trade.documents','naruv_finance.bills','naruv_production.orders'):
                need(c.execute('SELECT count(*) FROM '+table+' WHERE org_id=%s',(org,)).fetchone()==(per_tenant,),'WORKLOAD_ROW_COUNT_'+table)
    print('COMBINED_ERP_PASS '+json.dumps(dict(committed_batches=count,business_rpc_calls=count*7,exact_replays=count,balanced_journals=count,stock_checks=6,valuation_checks=6,ledger_checks=2,final=final,p95_ms=round(times[(95*count+99)//100-1],3),elapsed_s=round(elapsed,3)),sort_keys=True),flush=True)
if __name__=='__main__':main()
