"""Disposable PG17-only HTTP ingest transaction split acceptance."""
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from threading import Event
import time
from unittest.mock import patch
import psycopg
from openpyxl import Workbook

HERE=Path(__file__).resolve().parent
spec=importlib.util.spec_from_file_location('owner',HERE/'naruv_auth_owner_review.py')
o=importlib.util.module_from_spec(spec);spec.loader.exec_module(o)
t=o.t;v=o.v;s=o.s;b=o.b;base=o.base;need=b.need
def main():
    base.preflight()
    b.pin(HERE/'naruv_native_auth_bridge_review.py','af21613738e407bfe5bb17be1a9c164c90bac1c2')
    b.pin(HERE/'naruv_auth_owner_review.py','6b382d88591c9b198ce54fadc1765dbf09948d9a')
    source=base.ROOT/'app/naruv_native_write_review.py'
    b.pin(source,'6ee3164ea1101cf318ed7769942c82ebee7c8240')
    code=b.pin(HERE.parent/'docs/review/ingest-short-transaction/candidate.py','d631b1ef84a7307c91006ca6f9f6e04dcaccb29b')
    from app import naruv_native_write_review as mod
    from scripts.naruv_native_write_review_ci import NativeWrite
    original=mod._stage
    need(Path(inspect.getsourcefile(original)).resolve()==source.resolve(),'ORIGINAL_MODULE')
    fixture,ingest=base.setup()
    b.install(fixture);s.install(fixture)
    auth,_,_,_,digest=v.install(fixture);o.install(fixture)
    cert=Path(os.environ['NARUV_TLS_CA']).resolve(strict=True)
    auth=t.tls(auth,cert);ingest=t.tls(ingest,cert)
    t.assert_tls(auth,'naruv_v85_cutover_ci');t.assert_tls(ingest,'naruv_ci_ingest')
    tokens={who:base.session_hash(fixture,who) for who in ('A','B')}
    with psycopg.connect(auth,autocommit=True) as a:
        a.execute('SET ROLE jw_auth_stage_v85')
        for who,actor in [('A','ci-ua'),('B','ci-ub')]:
            need(bool(a.execute('SELECT jw_dev.v85_auth_issue_session(%s,%s,%s,NULL,%s)',(actor,tokens[who],fixture.CSRF[who],digest if who=='B' else None)).fetchone()[0]),'SESSION_ISSUE')
    ns=dict(mod.__dict__);exec(compile(code,'pinned_candidate.py','exec'),ns)
    # Use the module namespace, so instrumentation covers both variants.
    import types
    candidate=types.FunctionType(ns['_stage'].__code__,mod.__dict__,'_stage')
    native=NativeWrite('test_csv_full_flow_and_exact_retry')
    raw=b'sku,item_name,unit\n002,Widget,EA\n'
    def request(sid,who,raw,d,fmt='csv'):
        return native.req('/sources/source-'+who.lower()+'/item/'+fmt+'/stages/'+sid,who,raw,fmt,d)
    def stages():
        with psycopg.connect(fixture.root_dsn) as c:
            return c.execute('SELECT org_id,stage_id,stage_sha256,canonical_sha256,snapshot_sha256 FROM naruv_native_review.stages ORDER BY org_id,stage_id').fetchall()
    def observe_probe():
        with psycopg.connect(ingest,application_name='naruv-ingest-probe',autocommit=True) as c,c.transaction():
            c.execute("SET LOCAL lock_timeout='1s'")
            c.execute("SET LOCAL ROLE naruv_native_stage")
            c.execute("SELECT set_config('jw.session_hash',%s,true)",(tokens['A'],))
            try:
                row=c.execute("SELECT * FROM naruv_native_review.read_source(%s,'item',%s)",('source-a',fixture.CSRF['A'])).fetchone()
                need(row is not None,'PROBE_NO_ROW')
                return 'ok'
            except psycopg.Error as e:
                need(e.sqlstate=='55P03','PROBE_ERROR')
                return 'blocked'
    def paused(fn,sid,who,action,expected):
        d=native.review(raw,source='source-'+who.lower(),who=who)
        started=Event();release=Event()
        parser=mod.prepare_file_stage
        def hold(*args,**kwargs):
            started.set()
            need(release.wait(15),'PARSE_RELEASE_TIMEOUT')
            return parser(*args,**kwargs)
        with patch.object(mod,'_stage',fn),patch.object(mod,'prepare_file_stage',hold):
            with ThreadPoolExecutor(max_workers=2) as pool:
                pending=pool.submit(request,sid,who,raw,d)
                try:
                    need(started.wait(8),'PARSE_NOT_REACHED')
                    result=action(pool)
                    need(not pending.done(),'PARSE_NOT_HELD')
                finally:release.set()
                response=pending.result(timeout=15)
                need(response.status_code in expected,'UNEXPECTED_HTTP_'+str(response.status_code))
                return result,response
    def baseline_probe(pool):
        future=pool.submit(observe_probe)
        found=False
        with psycopg.connect(fixture.root_dsn,autocommit=True) as c:
            until=time.monotonic()+.85
            while time.monotonic()<until:
                found=c.execute("""SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
                    JOIN pg_stat_activity h ON h.pid=ANY(pg_blocking_pids(a.pid))
                    WHERE a.application_name='naruv-ingest-probe' AND h.application_name='naruv-ingest-request'
                    AND a.wait_event_type='Lock')""").fetchone()[0]
                if found or future.done():break
                time.sleep(.02)
        need(found and future.result(timeout=5)=='blocked','ORIGINAL_BLOCKING_NOT_PROVEN')
        return 'blocked'
    def split_probe(pool):
        need(pool.submit(observe_probe).result(timeout=5)=='ok','SPLIT_STILL_BLOCKS')
        return 'released'
    with patch.object(mod,'_ingest_connect',lambda:psycopg.connect(ingest,application_name='naruv-ingest-request')):
        # Same source snapshot, actual HTTP handlers, no DB writes except fixture stages.
        a,r1=paused(original,'txn-original','A',baseline_probe,(200,))
        z,r2=paused(candidate,'txn-split','A',split_probe,(200,))
        need(a=='blocked' and z=='released','LOCK_RELEASE')
        one,two=r1.json(),r2.json()
        need({k:v for k,v in one.items() if k!='stage_id'}=={k:v for k,v in two.items() if k!='stage_id'},'STAGE_RECEIPT_DRIFT')
        with patch.object(mod,'_stage',candidate):
            d=native.review(raw,source='source-a',who='A')
            need(request('txn-split','A',raw,d).json()['status']=='ALREADY_STAGED','STAGE_REPLAY')
            bad=native.req('/sources/source-a/item/csv/stages/txn-other','B',raw,'csv',d)
            need(bad.status_code in (403,404,409),'CROSS_TENANT')
            wb=Workbook();wb.active.append(['sku','item_name','unit']);wb.active.append(['003','XLSX fixture','EA'])
            buf=io.BytesIO();wb.save(buf);wb.close();x=buf.getvalue()
            xd=native.review(x,source='source-a',who='A',fmt='xlsx')
            need(request('txn-xlsx','A',x,xd,'xlsx').status_code==200,'XLSX_STAGE')
        before=stages()
        def drift(pool):
            with psycopg.connect(fixture.root_dsn) as c:
                c.execute("SET LOCAL lock_timeout='2s'")
                old=c.execute("SELECT revision FROM jw_dev.naruv_review_sources WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'").fetchone()[0]
                c.execute("UPDATE jw_dev.naruv_review_sources SET revision='txn-drift-fixture' WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'")
            return old
        old,r=paused(candidate,'txn-drift','A',drift,(409,))
        need(stages()==before,'DRIFT_PERSISTED_STAGE')
        with psycopg.connect(fixture.root_dsn) as c:
            c.execute("UPDATE jw_dev.naruv_review_sources SET revision=%s WHERE org_id='ci-a' AND source_id='source-a' AND entity='item'",(old,))
        def revoke(pool):
            with psycopg.connect(auth) as c:
                c.execute("SET LOCAL ROLE jw_auth_stage_v85")
                c.execute("SET LOCAL lock_timeout='2s'")
                need(c.execute('SELECT jw_dev.v85_auth_revoke_session(%s)',(tokens['B'],)).fetchone()==(True,),'REVOKE_FAILED')
            return True
        _,r=paused(candidate,'txn-revoked','B',revoke,(401,403))
        need(stages()==before,'REVOKED_PERSISTED_STAGE')
        print('INGEST_SPLIT_RACE_PASS baseline_blocked=true split_released=true snapshot_drift_denied=true revoked_denied=true',flush=True)
        print('INGEST_SPLIT_HTTP_PASS csv=true xlsx=true replay=true tenant_denial=true exact_receipt=true',flush=True)
    need(mod._stage is original,'ORIGINAL_NOT_RESTORED')
    print('INGEST_SPLIT_REVIEW_PASS production_authorized=false hosted_load=false',flush=True)
if __name__=='__main__':main()
