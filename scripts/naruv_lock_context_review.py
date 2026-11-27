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
import psycopg
from psycopg.types.json import Jsonb

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owner',HERE/'naruv_auth_owner_review.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
t=o.t;v=o.v;s=o.s;b=o.b;base=o.base;need=b.need
WORKERS=4
BATCHES=1
TENANTS={'A':('ci-a','ci-ua','source-a',105),'B':('ci-b','ci-ub','source-b',205)}
def diagnose(fixture,trade_dsn,tokens):
    base.preflight()
    # Read-only business RPC, intentionally short transaction-local lock timeout.
    # Exact root context must identify a known protected table or advisory fence.
    # Never print full PostgreSQL error context, which may contain bound values.
    import re
    from contextlib import closing
    with closing(psycopg.connect(trade_dsn)) as holder:
        b.bind(holder,tokens['A'])
        holder_pid=holder.info.backend_pid
        bill='load-0-0-bill'
        baseline=b.rpc(holder,'naruv_valuation.reconcile_bill',bill,fixture.CSRF['A'])
        def probe():
            with psycopg.connect(trade_dsn,application_name='naruv-lock-context-probe') as c:
                c.execute("SET LOCAL statement_timeout='10s'")
                c.execute("SET LOCAL lock_timeout='2s'")
                b.bind(c,tokens['A'])
                try:
                    b.rpc(c,'naruv_valuation.reconcile_bill',bill,fixture.CSRF['A'])
                except psycopg.Error as e:
                    need(e.sqlstate=='55P03','EXPECTED_LOCK_TIMEOUT')
                    context=e.diag.context or ''
                    # Fixed identifiers only, no raw context or tokens.
                    rel=re.search(r'in relation "([a-z_]+)"',context)
                    stmt=re.search(r'SQL statement "([^"]+)"',context)
                    q=stmt.group(1) if stmt else ''
                    table=None
                    for candidate in ('naruv_hosted_identity_review.users','naruv_hosted_identity_review.sessions','jw_dev.users','jw_dev.sessions'):
                        if re.search(r'(?<![a-z_])'+re.escape(candidate)+r'(?![a-z_])',q) and re.search(r'FOR (?:NO KEY )?UPDATE|FOR (?:KEY )?SHARE',q,re.I):
                            need(table is None,'AMBIGUOUS_LOCK_SQL')
                            table=candidate
                    if table is not None:
                        need(rel is not None and rel.group(1)==table.split('.')[1],'RELATION_CONTEXT_MISMATCH')
                        return ('row',table)
                    if 'pg_advisory_xact_lock' in q:
                        return ('advisory','actor_or_tenant_fence')
                    return ('unattributed','unknown')
                raise AssertionError('LOCK_TIMEOUT_NOT_OBSERVED')
        observed=None
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(probe)
            try:
                with psycopg.connect(fixture.root_dsn,autocommit=True) as obs:
                    end=time.monotonic()+1.7
                    while time.monotonic()<end:
                        observed=obs.execute("""SELECT a.wait_event,l.locktype
                            FROM pg_stat_activity a JOIN pg_locks l ON l.pid=a.pid
                            WHERE a.datname=current_database()
                            AND a.application_name='naruv-lock-context-probe'
                            AND a.wait_event_type='Lock' AND NOT l.granted
                            AND %s=ANY(pg_blocking_pids(a.pid)) LIMIT 1""",(holder_pid,)).fetchone()
                        if observed or future.done(): break
                        time.sleep(.025)
                need(observed is not None,'BLOCKER_NOT_OBSERVED')
                kind,target=future.result(timeout=8)
                need(kind!='unattributed','LOCK_CONTEXT_UNATTRIBUTED')
                print('LOCK_CONTEXT_ATTRIBUTED',json.dumps(dict(kind=kind,target=target,wait_event=observed[0],lock_type=observed[1],exact_blocker=True)),flush=True)
            finally:
                holder.rollback()
        with psycopg.connect(trade_dsn) as c:
            b.bind(c,tokens['A'])
            need(b.rpc(c,'naruv_valuation.reconcile_bill',bill,fixture.CSRF['A'])==baseline,'POST_TIMEOUT_DRIFT')
    print('LOCK_CONTEXT_DIAGNOSTIC_PASS',flush=True)
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
    diagnose(fixture,trade_dsn,tokens)
if __name__=='__main__':main()
