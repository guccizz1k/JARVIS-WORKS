"""Controlled crash/restart test of the dedicated CI PostgreSQL 17 service.

No external DSN or arbitrary container selector; fixed CI fixture roles.
The service ID must be supplied by the workflow and checked before every
destructive test action. Neither production nor a developer DB is touched.
"""
import json
import os
import re
import subprocess
import sys
import time
import unittest

import psycopg

from app.erp_migration_recovery import result
from scripts.naruv_approval_pg17_lab import root,actor,inspect,reserve
from scripts.naruv_atomic_fixture_pg17_lab import AtomicFixtureTests,commit_fixture,receipt

CID=os.environ.get("NARUV_RECOVERY_SERVICE_ID","")
ALLOW="ONLY_DISPOSABLE_CI"
LABEL="naruv_approval_ci"
EXPECTED_ENV={"POSTGRES_USER":"postgres","POSTGRES_DB":LABEL,
              "POSTGRES_PASSWORD":"naruv-ci-root-fixture"}

def require(ok,reason):
    if not ok:
        raise RuntimeError(reason)

def docker(*args):
    return subprocess.run(["docker",*args],check=True,capture_output=True,
                          text=True,timeout=20).stdout

def guarded_container(*,running):
    require(os.environ.get("NARUV_APPROVAL_PG_ALLOW")==ALLOW
            and os.environ.get("NARUV_RECOVERY_ALLOW")=="ONLY_JOB_POSTGRES_SERVICE"
            and os.environ.get("GITHUB_ACTIONS")=="true","RECOVERY_CI_SCOPE")
    require(re.fullmatch(r"[a-f0-9]{64}",CID) is not None,"RECOVERY_SERVICE_ID")
    rows=json.loads(docker("inspect",CID))
    require(type(rows) is list and len(rows)==1,"RECOVERY_SERVICE_LOOKUP")
    c=rows[0]
    cfg=c["Config"]
    env=dict(s.split("=",1) for s in cfg.get("Env",[]) if "=" in s)
    require(c["Id"]==CID and cfg["Image"]=="postgres:17"
            and all(env.get(k)==v for k,v in EXPECTED_ENV.items()),
            "RECOVERY_WRONG_CONTAINER")
    bindings=c["HostConfig"]["PortBindings"].get("5432/tcp")
    require(type(bindings) is list and any(b.get("HostPort")=="5432" for b in bindings),
            "RECOVERY_WRONG_PORT")
    require(c["State"]["Running"] is running,"RECOVERY_WRONG_STATE")
    return c

def db_identity():
    with root() as c:
        system,start,fsync,fpw,sync=c.execute("""SELECT system_identifier::text,
            pg_postmaster_start_time(),current_setting('fsync'),
            current_setting('full_page_writes'),current_setting('synchronous_commit')
            FROM pg_control_system()""").fetchone()
        require(fsync=="on" and fpw=="on" and sync=="on","RECOVERY_DURABILITY_SETTINGS")
        return system,start

def crash_and_restart():
    guarded_container(running=True)
    before=db_identity()
    docker("kill","--signal=KILL",CID)
    guarded_container(running=False)
    docker("start",CID)
    deadline=time.monotonic()+30
    last=None
    while time.monotonic()<deadline:
        try:
            last=db_identity()
        except (psycopg.OperationalError,psycopg.InterfaceError):
            time.sleep(.25)
            continue
        if last[0]==before[0] and last[1]>before[1]:
            guarded_container(running=True)
            return
        raise RuntimeError("RECOVERY_CLUSTER_ID_OR_RESTART_MISMATCH")
    raise RuntimeError("RECOVERY_STARTUP_TIMEOUT")

def reconcile(org="org-a",aid="approval-1",rid="request-1"):
    # Both lookups take the existing actor row lock in one transaction.
    # A communication/permission failure means unknown, never not committed.
    try:
        with actor(org) as c:
            value=result(inspect(c,org,id=aid),receipt(c,org,aid,rid),rid)
        return value
    except psycopg.Error:
        return {"outcome":"UNKNOWN","automatic_retry":False,
                "production_import_authorized":False}

def lost_ack_child():
    # Deliberately discard all application output. Exit code is identical for
    # success and error, so the caller must inspect persistent state.
    try:
        with actor("org-a") as c:
            commit_fixture(c)
    finally:
        os._exit(71)

class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        guarded_container(running=True)
        db_identity()
        AtomicFixtureTests.setUpClass()

    def setUp(self):
        self.f=AtomicFixtureTests("test_commit_and_receipt_after_reconnect")
        self.f.setUp()

    def verify_committed(self,target):
        self.assertEqual(self.f.state(),(("001","002"),1,target.snapshot_sha256))
        with root() as c:
            rows=c.execute("""SELECT source_item_id,name FROM naruv_approval_lab.fixture_items
                WHERE organization_id='org-a' ORDER BY source_item_id""").fetchall()
            self.assertEqual(rows,[("001","품목 A"),("002","품목 B")])
            n=c.execute("""SELECT count(*) FROM naruv_approval_lab.fixture_receipts r
                JOIN naruv_approval_lab.approvals a USING(organization_id,approval_id)
                JOIN naruv_approval_lab.targets t ON t.organization_id=a.organization_id
                    AND t.source_id=a.source_id AND t.entity=a.entity
                WHERE r.organization_id='org-a' AND r.reservation_id='request-1'
                AND a.status='RESERVED' AND a.reservation_id=r.reservation_id
                AND a.preflight_sha256=r.preflight_sha256 AND a.rows_sha256=r.rows_sha256
                AND t.snapshot_sha256=r.next_snapshot_sha256
                AND r.row_count=2 AND NOT r.row_import_authorized
                AND NOT a.row_import_authorized""").fetchone()[0]
            self.assertEqual(n,1)
        self.assertEqual(reconcile()["outcome"],"COMMITTED_RECEIPT_PRESENT")
        self.assertFalse(reconcile()["automatic_retry"])
        self.assertEqual(self.f.state("org-b"),((),0,self.f.targets["org-b"].snapshot_sha256))

    def test_kill_before_commit_rolls_back(self):
        self.f.stage()
        c=actor("org-a")
        try:
            self.assertEqual(commit_fixture(c),"FIXTURE_COMMITTED")
            # Changes are visible inside this transaction but not another.
            self.assertEqual(self.f.state(),((),0,self.f.targets["org-a"].snapshot_sha256))
            crash_and_restart()
        finally:
            c.close()
        self.f.assert_unwritten()
        self.assertEqual(reconcile()["outcome"],"NOT_COMMITTED_AT_CHECK")
        self.assertFalse(reconcile()["automatic_retry"])

    def test_kill_after_commit_preserves_full_state(self):
        target=self.f.stage()
        with actor("org-a") as c:self.assertEqual(commit_fixture(c),"FIXTURE_COMMITTED")
        crash_and_restart()
        self.verify_committed(target)
        self.f.rejected("org-a","APPROVAL_TARGET_CHANGED",commit_fixture)
        self.verify_committed(target)

    def test_worker_exit_without_ack_reconcile_only(self):
        target=self.f.stage()
        p=subprocess.run([sys.executable,"-m","scripts.naruv_recovery_pg17_lab","--lost-ack-child"],
                         capture_output=True,timeout=20)
        self.assertEqual(p.returncode,71)
        self.assertEqual(p.stdout,b"")
        self.verify_committed(target)

    def test_reservation_without_receipt_is_not_success(self):
        self.f.stage()
        with root() as c:
            p=c.execute("""SELECT organization_id,approval_id,source_id,entity,
                 preflight_sha256,rows_sha256,snapshot_sha256 FROM naruv_approval_lab.fixture_stage
                 WHERE organization_id='org-a'""").fetchone()
        with actor("org-a") as c:
            self.assertEqual(c.execute("SELECT naruv_approval_lab.reserve(%s,%s,%s,%s,%s,%s,%s,%s)",
                (p[0],p[1],"request-1",*p[2:])).fetchone()[0],"RESERVED")
        self.assertEqual(reconcile()["outcome"],"BLOCKED_INCONSISTENT")
        self.assertEqual(self.f.state(),((),0,self.f.targets["org-a"].snapshot_sha256))

    def test_wrong_reservation_and_tenant_never_recover_as_success(self):
        target=self.f.stage()
        with actor("org-a") as c:commit_fixture(c)
        self.assertEqual(reconcile(rid="different")["outcome"],"BLOCKED_INCONSISTENT")
        self.assertEqual(reconcile(org="org-b")["outcome"],"UNKNOWN")
        self.verify_committed(target)

    def test_revoked_or_missing_approval(self):
        self.assertEqual(reconcile()["outcome"],"UNKNOWN")
        self.f.stage()
        with actor("org-a") as c:
            self.assertEqual(c.execute("SELECT naruv_approval_lab.revoke(%s,%s)",
                                      ("org-a","approval-1")).fetchone()[0],"REVOKED")
        self.assertEqual(reconcile()["outcome"],"BLOCKED_REVOKED")

if __name__=="__main__":
    if sys.argv[1:]==["--lost-ack-child"]:
        guarded_container(running=True)
        lost_ack_child()
    elif sys.argv[1:]:
        raise SystemExit(2)
    else:
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(RecoveryTests)
        outcome=unittest.TextTestRunner(verbosity=2).run(suite)
        if not outcome.wasSuccessful() or outcome.testsRun!=6 or outcome.skipped or outcome.expectedFailures or outcome.unexpectedSuccesses:
            raise SystemExit(1)
        print("NARUV_RECOVERY_PG17_PASS 6 tests; 2 actual SIGKILL/restarts; no automatic replay; synthetic data only")
