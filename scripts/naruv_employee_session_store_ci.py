"""Actual PG17 integration, rollback-only disposable CI service, not a migration."""
import hashlib
import os
from pathlib import Path
import unittest
import psycopg
from psycopg.conninfo import conninfo_to_dict
from app import naruv_employee_session_store_review as store
from app.naruv_employee_access_review import AccessDenied

class EmployeeStore(unittest.TestCase):
    def test_actual_pg17_session_scope_and_live_revocation(self):
        dsn=os.environ["JW_PG_CI_ROOT_DSN"]
        cfg=conninfo_to_dict(dsn)
        self.assertEqual((cfg.get("host"),cfg.get("port"),cfg.get("dbname"),cfg.get("user")),
                         ("127.0.0.1","5432","postgres","postgres"))
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"),"true")
        conn=psycopg.connect(dsn)
        try:
            conn.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
            conn.execute(Path("db/review/naruv_employee_session_store_ci.sql").read_text())
            for tenant,principal,worker in (("ci-a","e1","w1"),("ci-a","e2","w2"),("ci-b","e1","w1")):
                conn.execute("INSERT INTO naruv_employee_ci.identities VALUES (%s,%s,%s,1,true)",(tenant,principal,worker))
                conn.execute("INSERT INTO naruv_employee_ci.entitlements VALUES (%s,%s,'r1',%s,%s,true)",(tenant,worker,"a"*64,"b"*64))
            issue=dict(trusted_tenant="ci-a",trusted_principal="e1",receipt="r1")
            token=store.issue(conn,**issue)
            args=dict(**issue,review_sha256="a"*64,render_sha256="b"*64,token=token)
            stored=conn.execute("SELECT token_sha256 FROM naruv_employee_ci.sessions").fetchone()[0]
            self.assertEqual(stored,hashlib.sha256(token.encode()).hexdigest())
            self.assertNotEqual(stored,token)
            self.assertEqual(store.access(conn,**args)["status"],"CI_POSTGRES_EMPLOYEE_SCOPE_MATCH_ONLY")
            self.assertFalse(store.access(conn,**args)["delivery_authorized"])
            for change in (dict(trusted_tenant="ci-b"),dict(trusted_principal="e2"),dict(receipt="r2"),dict(token="x"*43),dict(render_sha256="c"*64)):
                with self.subTest(change=change),self.assertRaises(AccessDenied):
                    store.access(conn,**dict(args,**change))
            for update,undo in (
                ("UPDATE naruv_employee_ci.identities SET auth_epoch=2 WHERE tenant='ci-a' AND principal='e1'","UPDATE naruv_employee_ci.identities SET auth_epoch=1 WHERE tenant='ci-a' AND principal='e1'"),
                ("UPDATE naruv_employee_ci.identities SET active=false WHERE tenant='ci-a' AND principal='e1'","UPDATE naruv_employee_ci.identities SET active=true WHERE tenant='ci-a' AND principal='e1'"),
                ("UPDATE naruv_employee_ci.entitlements SET active=false WHERE tenant='ci-a' AND worker='w1'","UPDATE naruv_employee_ci.entitlements SET active=true WHERE tenant='ci-a' AND worker='w1'"),
                ("UPDATE naruv_employee_ci.sessions SET revoked=true","UPDATE naruv_employee_ci.sessions SET revoked=false"),
                ("UPDATE naruv_employee_ci.sessions SET issued_at=1,expires_at=2","UPDATE naruv_employee_ci.sessions SET issued_at=floor(extract(epoch FROM clock_timestamp()))::bigint,expires_at=floor(extract(epoch FROM clock_timestamp()))::bigint+299")):
                conn.execute(update)
                with self.assertRaises(AccessDenied):store.access(conn,**args)
                conn.execute(undo)
            conn.execute("SET LOCAL naruv.employee_store_ci='OFF'")
            with self.assertRaises(AccessDenied):store.access(conn,**args)
        finally:
            conn.rollback()
            self.assertIsNone(conn.execute("SELECT to_regnamespace('naruv_employee_ci')").fetchone()[0])
            conn.close()
if __name__=="__main__":unittest.main()
