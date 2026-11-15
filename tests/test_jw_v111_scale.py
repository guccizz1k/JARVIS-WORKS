"""JARVIS-WORKS V11.1 bounded 100k forecast, financial/RLS evidence and local probe.

Synthetic tests do not validate actual production throughput. No paid service
or external endpoint can be invoked from these test functions.
"""
from __future__ import annotations

import math
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from scripts.jw_v111_capacity import Scenario, Measurement, assess_scale, model_default
from scripts.jw_v111_local_load import probe, validate_target
from scripts.jw_v111_readiness import evaluate, STAGES


def standard(**updates):
    data=dict(source='AUTHENTICATED_ISOLATED_STAGING',sample_count=1000,
              measured_p95_ms=180.0,http_error_fraction=.001,cpu_fraction=.44,
              memory_fraction=.5,db_waiting=0,pending_jobs=8,instance_count=1,
              db_max_connections=100,connections_per_instance=10,
              includes_trade_document_writes=True,
              includes_multi_tenant_security_checks=True)
    data.update(updates)
    return Measurement(**data)


def test_100k_registered_is_not_measured_capacity():
    result=model_default()
    assert result['target_registered_accounts']==100000
    assert result['one_account_per_company_policy_unchanged'] is True
    assert [r['active_connections'] for r in result['scenarios']]==[1000,5000,10000,100000]
    assert result['scenarios'][0]['estimated_websocket_db_poll_qps']>5000
    assert all(r['production_capacity_verified'] is False for r in result['scenarios'])


@pytest.mark.parametrize('change',[
 {'registered_accounts':True},{'registered_accounts':100001},
 {'concurrent_fraction':-.01},{'concurrent_fraction':float('nan')},
 {'websocket_fraction':1.01},{'websocket_poll_seconds':0},
 {'db_queries_per_poll':False},{'request_per_active_per_minute':float('inf')}
])
def test_bad_forecast_values_are_rejected(change):
    baseline={'registered_accounts':100000,'concurrent_fraction':.05,
              'websocket_fraction':.8,'request_per_active_per_minute':.6}
    baseline.update(change)
    with pytest.raises(ValueError):
        Scenario(**baseline)


@pytest.mark.parametrize('change',[
 {'sample_count':True},{'measured_p95_ms':float('nan')},
 {'http_error_fraction':True},{'db_max_connections':0},
 {'includes_trade_document_writes':1},{'cpu_fraction':2},
 {'source':'SELF_REPORTED_LOCAL_HEALTH'}
])
def test_fake_or_invalid_measured_evidence_rejected(change):
    with pytest.raises(ValueError):
        standard(**change)


def test_scale_even_with_healthy_metrics_needs_explicit_budget():
    denied=assess_scale(standard(),requested_instances=2,
                        budget_approved=False,rollout_approved=True)
    assert denied['status']=='BLOCKED'
    allowed=assess_scale(standard(),requested_instances=2,
                         budget_approved=True,rollout_approved=True)
    assert allowed['status']=='REVIEW_ELIGIBLE'
    assert allowed['deployment_authorized'] is False
    assert allowed['autoscaling_enabled'] is False
    assert allowed['action']=='NO_CLOUD_CHANGES'


@pytest.mark.parametrize('change,reason',[
 ({'sample_count':999},'INSUFFICIENT_INDEPENDENT_STAGING_EVIDENCE'),
 ({'includes_trade_document_writes':False},'BUSINESS_AND_SECURITY_E2E_NOT_MEASURED'),
 ({'includes_multi_tenant_security_checks':False},'BUSINESS_AND_SECURITY_E2E_NOT_MEASURED'),
 ({'measured_p95_ms':501},'ERROR_OR_P95_SLO_NOT_MET'),
 ({'http_error_fraction':.01},'ERROR_OR_P95_SLO_NOT_MET'),
 ({'db_waiting':1},'DB_OR_WORKER_QUEUE_SATURATED'),
 ({'pending_jobs':101},'DB_OR_WORKER_QUEUE_SATURATED'),
 ({'db_max_connections':21},'PG_CONNECTION_BUDGET_EXCEEDED'),
])
def test_bad_business_capacity_evidence_blocks_scale(change,reason):
    verdict=assess_scale(standard(**change),requested_instances=2,
                         budget_approved=True,rollout_approved=True)
    assert verdict['status']=='BLOCKED'
    assert verdict['reason']==reason


@pytest.mark.parametrize('count',[0,True,101,4,-1])
def test_instance_cap_cannot_be_bypassed(count):
    result=assess_scale(standard(),requested_instances=count,
                        budget_approved=True,rollout_approved=True)
    assert result['status']=='BLOCKED'


@pytest.mark.parametrize('bad',['true',1,[],None])
def test_boolean_approval_must_be_real_bool(bad):
    result=assess_scale(standard(),requested_instances=2,
                        budget_approved=bad,rollout_approved=True)
    assert result['status']=='BLOCKED'


@pytest.mark.parametrize('url',[
 'https://render.com/healthz','http://localhost:8765/healthz',
 'http://127.0.0.2:8765/healthz','http://[::1]:8765/healthz',
 'http://127.0.0.1:80/healthz','http://127.0.0.1:8765/api/login',
 'http://127.0.0.1:8765/healthz?x=1','http://u:p@127.0.0.1:8765/healthz',
 'http://127.0.0.1:8765/healthz#x','file:///etc/passwd'
])
def test_loopback_load_probe_refuses_external_or_business_destinations(url):
    with pytest.raises(ValueError):validate_target(url)


def test_local_probe_runs_get_only_and_never_claims_business_load(monkeypatch):
    class Health(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{}')
        def log_message(self,*args):
            pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Health)
    bg=threading.Thread(target=server.serve_forever,daemon=True)
    bg.start()
    try:
        url='http://127.0.0.1:'+str(server.server_port)+'/healthz'
        monkeypatch.setenv('JW_ENV','review')
        with pytest.raises(RuntimeError):
            probe(url,requests=12,concurrency=3)
        monkeypatch.setenv('JW_SCALE_ALLOW_LOCAL_PROBE','YES_LOOPBACK_ONLY')
        out=probe(url,requests=12,concurrency=3)
        assert out['http_successes']==12
        assert out['evidence']=='LOCALHOST_HEALTH_ENDPOINT_ONLY'
        assert 0<=out['p50_ms']<=out['p95_ms']<=out['p99_ms']
        assert not out['100k_capacity_verified']
        assert not out['business_write_load_measured']
        monkeypatch.setenv('JW_ENV','production')
        with pytest.raises(RuntimeError):probe(url,requests=12,concurrency=3)
    finally:
        server.shutdown()
        server.server_close()
        bg.join(timeout=2)


def test_high_volume_and_boolean_concurrency_denied(monkeypatch):
    monkeypatch.setenv('JW_ENV','review')
    monkeypatch.setenv('JW_SCALE_ALLOW_LOCAL_PROBE','YES_LOOPBACK_ONLY')
    url='http://127.0.0.1:8765/healthz'
    for settings in ({'requests':501},{'requests':True},
                     {'concurrency':17},{'concurrency':True},
                     {'requests':2,'concurrency':3}):
        with pytest.raises(ValueError):probe(url,**settings)


def test_four_stage_gate_never_auto_approves_release():
    out=evaluate({},current_sha='f'*40)
    assert out['status']==out['release']=='BLOCKED'
    assert [s['stage'] for s in out['stages']]==[1,2,3,4]
    assert all(s['status']=='BLOCKED' for s in out['stages'])
    assert evaluate({},current_sha='bad')['reason']=='EXACT_COMMIT_SHA_REQUIRED'
    receipt={k:{name:True for name in controls} for k,(_,controls) in STAGES.items()}
    r=evaluate(receipt,current_sha='f'*40)
    assert all(s['status']=='REVIEW_REQUIRED' for s in r['stages'])
    assert not r['production_deployed'] and not r['autoscaling_enabled']
    receipt['1']['shared_session_store']=1
    assert evaluate(receipt,current_sha='f'*40)['stages'][0]['status']=='BLOCKED'
