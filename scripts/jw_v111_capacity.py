"""V11.1 offline capacity model and manual-scale safety gate.

Synthetic forecasts are not production measurements. This module has no
network, database, money-transfer or Render mutation capabilities.
"""
from __future__ import annotations
import json
import math
from dataclasses import dataclass
from typing import Any

REGISTERED_TARGET = 100_000


@dataclass(frozen=True)
class Scenario:
    registered_accounts: int
    concurrent_fraction: float
    websocket_fraction: float
    request_per_active_per_minute: float
    websocket_poll_seconds: float = 0.3
    db_queries_per_poll: int = 2

    def __post_init__(self):
        if type(self.registered_accounts) is not int or not 1 <= self.registered_accounts <= REGISTERED_TARGET:
            raise ValueError('registered_accounts outside model limits')
        for name in ('concurrent_fraction', 'websocket_fraction'):
            value = getattr(self,name)
            if type(value) not in (int,float) or not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError('invalid synthetic concurrency fraction')
        if (type(self.request_per_active_per_minute) not in (int,float)
            or not math.isfinite(self.request_per_active_per_minute)
            or not 0 <= self.request_per_active_per_minute <= 60):
            raise ValueError('invalid synthetic request rate')
        if (type(self.websocket_poll_seconds) not in (int,float)
            or not math.isfinite(self.websocket_poll_seconds)
            or not 0.02 <= self.websocket_poll_seconds <= 60):
            raise ValueError('invalid synthetic polling interval')
        if type(self.db_queries_per_poll) is not int or not 1 <= self.db_queries_per_poll <= 10:
            raise ValueError('invalid synthetic DB poll fanout')

    def estimate(self) -> dict[str,Any]:
        active = math.ceil(self.registered_accounts * self.concurrent_fraction)
        connected = math.ceil(active * self.websocket_fraction)
        return {
            'evidence':'SYNTHETIC_MODEL_ONLY',
            'registered_accounts':self.registered_accounts,
            'active_connections':active,
            'websocket_connections':connected,
            'estimated_http_rps':round(active*self.request_per_active_per_minute/60,2),
            'estimated_websocket_db_poll_qps':round(
                connected*self.db_queries_per_poll/self.websocket_poll_seconds,2),
            'websocket_broadcast_backend':'NOT_IMPLEMENTED',
            'ocr_worker_queue':'NOT_IMPLEMENTED',
            'production_capacity_verified':False}


@dataclass(frozen=True)
class Measurement:
    source: str
    sample_count: int
    measured_p95_ms: float
    http_error_fraction: float
    cpu_fraction: float
    memory_fraction: float
    db_waiting: int
    pending_jobs: int
    instance_count: int
    db_max_connections: int
    connections_per_instance: int
    includes_trade_document_writes: bool = False
    includes_multi_tenant_security_checks: bool = False

    def __post_init__(self):
        if self.source != 'AUTHENTICATED_ISOLATED_STAGING':
            raise ValueError('requires independently assessed staging metrics')
        for key in ('sample_count','db_waiting','pending_jobs','instance_count',
                    'db_max_connections','connections_per_instance'):
            n = getattr(self,key)
            if type(n) is not int or n < (1 if key in ('sample_count','instance_count',
                    'db_max_connections','connections_per_instance') else 0):
                raise ValueError('invalid integer measurement: '+key)
        for key in ('measured_p95_ms','http_error_fraction','cpu_fraction','memory_fraction'):
            value=getattr(self,key)
            if type(value) not in (int,float) or not math.isfinite(value) or value < 0:
                raise ValueError('invalid metric: '+key)
        if not all(0 <= getattr(self,k) <= 1 for k in
                   ('http_error_fraction','cpu_fraction','memory_fraction')):
            raise ValueError('fraction outside 0..1')
        for key in ('includes_trade_document_writes','includes_multi_tenant_security_checks'):
            if type(getattr(self,key)) is not bool:
                raise ValueError('measurement evidence flag must be bool')


def assess_scale(metrics: Measurement | None, *, requested_instances: int,
                 budget_approved: bool, rollout_approved: bool,
                 max_instances: int = 3) -> dict[str,Any]:
    """Never returns a direct deploy authorization or auto-scale action."""
    verdict={'status':'BLOCKED','action':'NO_CLOUD_CHANGES',
             'autoscaling_enabled':False,'measured_production_capacity':False}
    if (type(requested_instances) is not int or type(max_instances) is not int
        or not 1 <= requested_instances <= max_instances <= 100):
        return {**verdict,'reason':'INSTANCE_BOUNDARY'}
    if type(budget_approved) is not bool or type(rollout_approved) is not bool or not (budget_approved and rollout_approved):
        return {**verdict,'reason':'BUDGET_OR_OWNER_APPROVAL_MISSING'}
    if not isinstance(metrics,Measurement) or metrics.sample_count < 1000:
        return {**verdict,'reason':'INSUFFICIENT_INDEPENDENT_STAGING_EVIDENCE'}
    if not (metrics.includes_trade_document_writes and metrics.includes_multi_tenant_security_checks):
        return {**verdict,'reason':'BUSINESS_AND_SECURITY_E2E_NOT_MEASURED'}
    if requested_instances > 1 and metrics.db_max_connections-20 < requested_instances*metrics.connections_per_instance:
        return {**verdict,'reason':'PG_CONNECTION_BUDGET_EXCEEDED'}
    if metrics.http_error_fraction > .005 or metrics.measured_p95_ms > 500:
        return {**verdict,'reason':'ERROR_OR_P95_SLO_NOT_MET'}
    if metrics.db_waiting > 0 or metrics.pending_jobs > 100:
        return {**verdict,'reason':'DB_OR_WORKER_QUEUE_SATURATED'}
    return {**verdict,'status':'REVIEW_ELIGIBLE','reason':'METRICS_REVIEW_REQUIRED',
            'proposed_instances':requested_instances,
            'expected_extra_db_connections':requested_instances*metrics.connections_per_instance,
            'deployment_authorized':False}


def model_default() -> dict:
    cases=[Scenario(REGISTERED_TARGET,f,0.8,0.6).estimate()
           for f in (0.01,0.05,0.1,1.0)]
    return {'kind':'CAPACITY_FORECAST_NOT_A_LOAD_TEST',
            'target_registered_accounts':REGISTERED_TARGET,
            'one_account_per_company_policy_unchanged':True,
            'full_prod_10k_to_100k_concurrent_not_proven':True,
            'scenarios':cases}


if __name__=='__main__':
    print(json.dumps(model_default(),ensure_ascii=False,indent=2))
