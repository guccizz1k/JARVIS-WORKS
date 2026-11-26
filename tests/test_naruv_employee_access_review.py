import unittest
from dataclasses import replace
from app.naruv_employee_access_review import (
    EmployeeIdentity,StatementEntitlement,issue_synthetic_session,
    review_employee_statement_access,AccessDenied,MAX_LIFETIME)

class EmployeeScope(unittest.TestCase):
    def setUp(self):
        self.identity=EmployeeIdentity("tenant-a","employee-1","worker-1",1,True)
        self.ent=StatementEntitlement("tenant-a","worker-1","receipt-1","a"*64,"b"*64,True)
        self.token,self.session=issue_synthetic_session(identity=self.identity,entitlement=self.ent,now=100)
        self.args=dict(token=self.token,session=self.session,identity=self.identity,entitlement=self.ent,now=100,
            requested_receipt="receipt-1",requested_review_sha256="a"*64,requested_render_sha256="b"*64)

    def test_exact_scope_no_release(self):
        for now in (100,399):
            result=review_employee_statement_access(**dict(self.args,now=now))
            self.assertEqual(result["status"],"SYNTHETIC_EMPLOYEE_SCOPE_MATCH_ONLY")
            self.assertTrue(all(v is False for k,v in result.items() if k!="status"))
        self.assertNotIn(self.token,repr(self.session))
        other,row=issue_synthetic_session(identity=self.identity,entitlement=self.ent,now=100)
        self.assertNotEqual(other,self.token)
        self.assertNotEqual(row.token_sha256,self.session.token_sha256)

    def test_deny_scope_and_live_state_changes(self):
        s=self.session;i=self.identity;e=self.ent
        changes=[
            dict(identity=replace(i,tenant="tenant-b")),dict(identity=replace(i,worker="worker-2")),
            dict(identity=replace(i,principal="employee-2")),dict(identity=replace(i,auth_epoch=2)),
            dict(identity=replace(i,active=False)),dict(identity=replace(i,active=1)),
            dict(identity=replace(i,auth_epoch=True)),dict(entitlement=replace(e,active=False)),
            dict(entitlement=replace(e,tenant="tenant-b")),dict(entitlement=replace(e,worker="worker-2")),
            dict(entitlement=replace(e,receipt="receipt-2")),dict(entitlement=replace(e,review_sha256="c"*64)),
            dict(entitlement=replace(e,render_sha256="d"*64)),dict(requested_receipt="receipt-2"),
            dict(requested_review_sha256="c"*64),dict(requested_render_sha256="d"*64),
            dict(session=replace(s,audience="erp-admin")),dict(session=replace(s,revoked=True)),
            dict(session=replace(s,auth_epoch=True)),dict(session=replace(s,expires_at=401)),
            dict(session=replace(s,issued_at=101)),dict(now=99),dict(now=400),dict(now=True),
            dict(token="x"*43),dict(token=self.token+"="),dict(token=None),dict(token="é"*43)]
        for change in changes:
            with self.subTest(change=list(change)),self.assertRaises(AccessDenied):
                review_employee_statement_access(**dict(self.args,**change))

    def test_issue_limits(self):
        for ttl in (0,MAX_LIFETIME+1,True):
            with self.assertRaises(AccessDenied):
                issue_synthetic_session(identity=self.identity,entitlement=self.ent,now=100,ttl=ttl)
        with self.assertRaises(AccessDenied):
            issue_synthetic_session(identity=replace(self.identity,tenant="tenant-b"),entitlement=self.ent,now=100)
