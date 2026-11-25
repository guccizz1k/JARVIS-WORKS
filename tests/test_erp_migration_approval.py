import concurrent.futures
from dataclasses import replace
import os
import random
import threading
import unittest
from unittest.mock import patch

from app.erp_migration_mapping import MappingBlocked
from app.erp_migration_review import prepare_header_review
from app.erp_migration_preflight import make_target_snapshot, prepare_row_preflight
from app.erp_migration_approval import ActorContext, ApprovalLab, MAX_TTL

ORG="org-a"
SOURCE="erp-1"
H=("sku","item_name")
ROWS=(("001","부품"),)
APPROVER=ActorContext(ORG,"reviewer","perm-1",True,True,False)
EXECUTOR=ActorContext(ORG,"executor","perm-1",True,False,True)

class ApprovalLabTests(unittest.TestCase):
    def setUp(self):
        self.now=10000
        self.lab=ApprovalLab(clock=lambda:self.now)
        self.review,self.preflight,self.args=self.fixture()

    def fixture(self,org=ORG,source=SOURCE,rows=ROWS,revision="rev-1"):
        review=prepare_header_review(org,source,"item",H)
        args=dict(organization_id=org,source_id=source,entity="item",
                  headers=H,rows=rows,target=make_target_snapshot(org,source,"item",revision,()))
        return review,prepare_row_preflight(review,**args),args

    def issue(self,approval_id="approval-1",**changes):
        args=dict(approver=APPROVER,executor=EXECUTOR,confirmed=True,ttl_seconds=60,**self.args)
        args.update(changes)
        return self.lab.issue(approval_id,self.preflight,self.review,**args)

    def reserve(self,reservation_id="request-1",approval_id="approval-1",**changes):
        args=dict(approver=APPROVER,executor=EXECUTOR,**self.args)
        args.update(changes)
        return self.lab.reserve(approval_id,reservation_id,self.preflight,self.review,**args)

    def reject(self,reason,fn,*args,**kwargs):
        with self.assertRaisesRegex(MappingBlocked,"^"+reason+"$"):
            fn(*args,**kwargs)

    def test_happy_path_and_terminal_state(self):
        p=self.issue()
        self.assertEqual(p.status,"APPROVED")
        self.assertFalse(p.row_import_authorized)
        q=self.reserve()
        self.assertEqual(q.status,"RESERVED")
        self.assertFalse(q.row_import_authorized)
        self.reject("APPROVAL_TERMINAL",self.reserve)
        self.reject("APPROVAL_TERMINAL",self.issue)
        self.reject("APPROVAL_TERMINAL",self.lab.revoke,"approval-1",approver=APPROVER)

    def test_explicit_confirmation_and_ttl(self):
        for value in (False,0,1,None,"true"):
            self.reject("APPROVAL_EXPLICIT_CONFIRMATION_REQUIRED",self.issue,confirmed=value)
        for ttl in (False,0,-1,MAX_TTL+1,1.5,None):
            self.reject("APPROVAL_TTL",self.issue,ttl_seconds=ttl)
        self.assertEqual(self.issue(ttl_seconds=MAX_TTL).expires_at,self.now+MAX_TTL)

    def test_exact_repeat_never_renews(self):
        a=self.issue()
        self.now+=30
        self.assertEqual(a,self.issue())
        self.reject("APPROVAL_ID_CONFLICT",self.issue,ttl_seconds=61)
        self.now=a.expires_at
        self.reject("APPROVAL_EXPIRED",self.issue)
        self.reject("APPROVAL_EXPIRED",self.reserve)

    def test_expiry_boundary(self):
        p=self.issue(ttl_seconds=1)
        self.now=p.expires_at
        self.reject("APPROVAL_EXPIRED",self.reserve)

    def test_clock_rollback_and_invalid_time(self):
        self.issue()
        self.now-=1
        self.reject("APPROVAL_CLOCK_ROLLBACK",self.reserve)
        self.now=True
        self.reject("APPROVAL_CLOCK_INVALID",self.reserve)

    def test_roles_and_inactive_principals(self):
        for value in (None,{},True):
            self.reject("APPROVAL_ACTOR_TYPE",self.issue,approver=value)
        self.reject("APPROVAL_PERMISSION_DENIED",self.issue,approver=replace(APPROVER,active=False))
        self.reject("APPROVAL_PERMISSION_DENIED",self.issue,executor=replace(EXECUTOR,can_reserve=False))
        self.reject("APPROVAL_PERMISSION_TYPE",self.issue,approver=replace(APPROVER,can_approve=1))
        self.reject("APPROVAL_SCOPE",self.issue,approver=replace(APPROVER,organization_id="org-b"))
        self.issue()
        self.reject("APPROVAL_PERMISSION_DENIED",self.reserve,approver=replace(APPROVER,can_approve=False))
        self.reject("APPROVAL_PERMISSION_DENIED",self.reserve,executor=replace(EXECUTOR,active=False))

    def test_actor_and_permission_revision_changes(self):
        self.issue()
        for change in (dict(approver=replace(APPROVER,permission_revision="perm-2")),
                       dict(executor=replace(EXECUTOR,permission_revision="perm-2")),
                       dict(executor=replace(EXECUTOR,actor_id="different")),
                       dict(approver=replace(APPROVER,actor_id="different"))):
            self.reject("APPROVAL_ACTOR_CHANGED",self.reserve,**change)
        self.assertEqual(self.reserve().status,"RESERVED")

    def test_single_account_policy_without_inconsistent_context(self):
        actor=ActorContext(ORG,"one-account","perm-1",True,True,True)
        self.reject("APPROVAL_CONTEXT_INCONSISTENT",self.issue,approver=actor,
                    executor=replace(actor,permission_revision="perm-2"))
        self.issue(approver=actor,executor=actor)
        self.assertEqual(self.reserve(approver=actor,executor=actor).status,"RESERVED")

    def test_changed_source_data_and_forged_flag(self):
        self.issue()
        self.reject("PREFLIGHT_STALE_OR_CHANGED",self.reserve,rows=(("001","changed"),))
        self.reject("PREFLIGHT_STALE_OR_CHANGED",self.reserve,target=make_target_snapshot(ORG,SOURCE,"item","rev-2",()))
        self.reject("APPROVAL_IMMUTABLE_INPUT_REQUIRED",self.reserve,rows=list(ROWS))
        self.reject("APPROVAL_IMMUTABLE_INPUT_REQUIRED",self.reserve,headers=list(H))
        self.reject("PREFLIGHT_IMPORT_FORBIDDEN",self.lab.reserve,"approval-1","request-1",
            replace(self.preflight,row_import_authorized=True),self.review,
            approver=APPROVER,executor=EXECUTOR,**self.args)
        self.assertEqual(self.reserve().status,"RESERVED")

    def test_recomputed_preflight_cannot_reuse_approval(self):
        self.issue()
        r,p,args=self.fixture(rows=(("002","other"),))
        self.reject("APPROVAL_BINDING_CHANGED",self.lab.reserve,"approval-1","request-1",
                    p,r,approver=APPROVER,executor=EXECUTOR,**args)
        self.assertEqual(self.reserve().status,"RESERVED")

    def test_duplicate_content_and_id_conflict(self):
        self.issue()
        self.reject("APPROVAL_CONTENT_ALREADY_REGISTERED",self.issue,"approval-2")
        r,p,args=self.fixture(rows=(("002","other"),))
        self.reject("APPROVAL_ID_CONFLICT",self.lab.issue,"approval-1",p,r,
                    approver=APPROVER,executor=EXECUTOR,confirmed=True,ttl_seconds=60,**args)
        self.assertEqual(self.reserve().status,"RESERVED")

    def test_reservation_id_uniqueness_per_org(self):
        self.issue()
        self.reserve()
        r,p,args=self.fixture(rows=(("002","other"),))
        self.lab.issue("approval-2",p,r,approver=APPROVER,executor=EXECUTOR,
                       confirmed=True,ttl_seconds=60,**args)
        self.reject("APPROVAL_RESERVATION_ID_CONFLICT",self.lab.reserve,"approval-2","request-1",
                    p,r,approver=APPROVER,executor=EXECUTOR,**args)
        self.assertEqual(self.lab.reserve("approval-2","request-2",p,r,
                         approver=APPROVER,executor=EXECUTOR,**args).status,"RESERVED")

    def test_cross_org_scope_even_with_same_ids(self):
        self.issue()
        org="org-b"
        r,p,args=self.fixture(org=org)
        a,b=replace(APPROVER,organization_id=org),replace(EXECUTOR,organization_id=org)
        self.reject("APPROVAL_NOT_FOUND",self.lab.reserve,"approval-1","request-1",p,r,
                    approver=a,executor=b,**args)
        self.lab.issue("approval-1",p,r,approver=a,executor=b,confirmed=True,ttl_seconds=60,**args)
        self.assertEqual(self.lab.reserve("approval-1","request-1",p,r,approver=a,executor=b,**args).organization_id,org)
        self.assertEqual(self.reserve().organization_id,ORG)

    def test_revocation_terminal(self):
        self.issue()
        self.reject("APPROVAL_ACTOR_CHANGED",self.lab.revoke,"approval-1",
                    approver=replace(APPROVER,actor_id="other"))
        self.assertEqual(self.lab.revoke("approval-1",approver=APPROVER).status,"REVOKED")
        self.reject("APPROVAL_TERMINAL",self.reserve)
        self.reject("APPROVAL_CONTENT_ALREADY_REGISTERED",self.issue,"approval-2")

    def test_capacity_no_eviction(self):
        self.issue()
        r,p,args=self.fixture(rows=(("002","other"),))
        with patch("app.erp_migration_approval.MAX_APPROVALS",1):
            self.reject("APPROVAL_CAPACITY",self.lab.issue,"approval-2",p,r,
                        approver=APPROVER,executor=EXECUTOR,confirmed=True,ttl_seconds=60,**args)
        self.assertEqual(self.reserve().status,"RESERVED")

    def test_simultaneous_claim_exactly_one(self):
        self.issue()
        barrier=threading.Barrier(16)
        def run(i):
            barrier.wait(timeout=5)
            try:return self.reserve(f"request-{i}").status
            except MappingBlocked as exc:return str(exc)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            results=list(pool.map(run,range(16)))
        self.assertEqual(results.count("RESERVED"),1)
        self.assertEqual(results.count("APPROVAL_TERMINAL"),15)

    def test_revoke_reserve_race_one_terminal_winner(self):
        barrier=threading.Barrier(2)
        self.issue()
        def reserve():
            barrier.wait(timeout=5)
            try:return self.reserve().status
            except MappingBlocked as exc:return str(exc)
        def revoke():
            barrier.wait(timeout=5)
            try:return self.lab.revoke("approval-1",approver=APPROVER).status
            except MappingBlocked as exc:return str(exc)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            a,b=pool.submit(reserve),pool.submit(revoke)
            results=[a.result(),b.result()]
        self.assertEqual(results.count("APPROVAL_TERMINAL"),1)
        self.assertEqual(sum(x in ("RESERVED","REVOKED") for x in results),1)

    def test_varied_expiry_scope_and_duplicate_controls(self):
        rng=random.Random(int(os.environ.get("NARUV_TEST_SEED","1")))
        for i in range(100):
            org=f"org-{i}"
            r,p,args=self.fixture(org=org,rows=((f"{i:06d}","부품"),))
            a,b=replace(APPROVER,organization_id=org),replace(EXECUTOR,organization_id=org)
            self.now=10000+i*1000
            ttl=rng.randrange(1,MAX_TTL+1)
            record=self.lab.issue("approval",p,r,approver=a,executor=b,confirmed=True,ttl_seconds=ttl,**args)
            self.assertFalse(record.row_import_authorized)
            self.reject("APPROVAL_SCOPE",self.lab.reserve,"approval","reservation",p,r,
                        approver=APPROVER,executor=b,**args)
            self.reject("APPROVAL_CONTENT_ALREADY_REGISTERED",self.lab.issue,"new",p,r,
                        approver=a,executor=b,confirmed=True,ttl_seconds=ttl,**args)
            self.now=record.expires_at
            self.reject("APPROVAL_EXPIRED",self.lab.reserve,"approval","reservation",p,r,
                        approver=a,executor=b,**args)
