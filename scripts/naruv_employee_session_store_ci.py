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
                with self.assertRaises(AccessDenied):
                    with conn.transaction():
                        conn.execute(update)
                        store.access(conn,**args)
            conn.execute("SET LOCAL ROLE naruv_employee_ci_a")
            self.assertEqual(conn.execute("SELECT current_user").fetchone()[0],"naruv_employee_ci_a")
            self.assertEqual(conn.execute("SELECT tenant,principal FROM naruv_employee_ci.identities").fetchall(),[("ci-a","e1")])
            self.assertEqual(conn.execute("SELECT tenant,worker FROM naruv_employee_ci.entitlements").fetchall(),[("ci-a","w1")])
            self.assertEqual(store.access(conn,**args)["status"],"CI_POSTGRES_EMPLOYEE_SCOPE_MATCH_ONLY")
            role_token=store.issue(conn,**issue)
            self.assertTrue(store.access(conn,**dict(args,token=role_token))["session_store_verified"])
            for wrong in (dict(trusted_tenant="ci-b"),dict(trusted_principal="e2")):
                with self.assertRaises(AccessDenied):store.issue(conn,**dict(issue,**wrong))
            for forbidden in (
                "UPDATE naruv_employee_ci.identities SET active=false",
                "UPDATE naruv_employee_ci.entitlements SET active=false",
                "UPDATE naruv_employee_ci.sessions SET revoked=true",
                "DELETE FROM naruv_employee_ci.sessions",
                "TRUNCATE naruv_employee_ci.sessions",
                "INSERT INTO naruv_employee_ci.identities VALUES ('ci-a','evil','w3',1,true)",
                "INSERT INTO naruv_employee_ci.sessions SELECT audience,'ci-b',principal,worker,auth_epoch,receipt,review_sha256,render_sha256,repeat('f',64),issued_at,expires_at,revoked FROM naruv_employee_ci.sessions LIMIT 1"):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    with conn.transaction():conn.execute(forbidden)
            conn.execute("SET LOCAL ROLE naruv_employee_ci_b")
            self.assertEqual(conn.execute("SELECT tenant,principal FROM naruv_employee_ci.identities").fetchall(),[("ci-b","e1")])
            self.assertEqual(conn.execute("SELECT count(*) FROM naruv_employee_ci.sessions").fetchone()[0],0)
            with self.assertRaises(AccessDenied):store.access(conn,**args)
            b_issue=dict(issue,trusted_tenant="ci-b")
            b_token=store.issue(conn,**b_issue)
            self.assertTrue(store.access(conn,**dict(args,trusted_tenant="ci-b",token=b_token))["session_store_verified"])
            conn.execute("SET LOCAL ROLE naruv_employee_ci_a")
            self.assertEqual(conn.execute("SELECT count(*) FROM naruv_employee_ci.sessions").fetchone()[0],2)
            conn.execute("RESET ROLE")
            # Build an actual existing payroll draft and bind the rendered
            # content to the live scoped session without issuing a document.
            from copy import deepcopy
            from dataclasses import replace
            import runpy
            from app.naruv_payroll_draft import draft_gross
            from app.naruv_kr_payroll_review import source_bound_review,restricted_wage_statement_2026,isolated_wage_statement_print_html
            from app.naruv_employee_statement_binding_review import TrustedDraft,review_bound_statement
            fixture=runpy.run_path("tests/test_naruv_kr_payroll_review.py")
            a=fixture["SourceBoundKRReview"]().inputs()
            a.update(tenant="ci-a",worker="w1")
            base={k:a[k] for k in ("tenant","worker","period","policy_revision","hourly_krw","minutes_by_day")}
            a["expected_draft_sha256"]=draft_gross(**base,multiplier_bps={"regular":10000,"additional":15000})["draft_sha256"]
            bound=source_bound_review(**a)
            args2={k:a[k] for k in ("tenant","worker","period","ordinary_hourly","classification_sha256","classified_days","deductions")}
            args2.update(base_hourly=a["hourly_krw"],bound_review=bound,payment_date="2026-12-10",scope="MANUALLY_ASSESSED_WORK_AND_PREMIUMS_ONLY",completeness_assessment_sha256="e"*64)
            statement=restricted_wage_statement_2026(**args2)
            wrapped=dict(status="MANUAL_SUBMISSION_REFERENCE_ONLY",wage_statement_reference=statement,
                         evidence_authenticity_verified=False,persisted=False,statutory_validated=False,payment_authorized=False,production_authorized=False)
            h=hashlib.sha256(isolated_wage_statement_print_html(wrapped).encode("utf-8")).hexdigest()
            conn.execute("INSERT INTO naruv_employee_ci.entitlements VALUES ('ci-a','w1','r2',%s,%s,true)",(statement["review_sha256"],h))
            conn.execute("SET LOCAL ROLE naruv_employee_ci_a")
            bind=dict(trusted_tenant="ci-a",trusted_principal="e1",receipt="r2")
            tok=store.issue(conn,**bind)
            draft=TrustedDraft("ci-a","w1","r2",wrapped)
            options=dict(**bind,token=tok,draft=draft)
            result=review_bound_statement(conn,**options)
            self.assertTrue(result["render_binding_verified"])
            self.assertEqual(result["render_sha256"],h)
            for flag in ("document_returned","delivery_authorized","production_authorized","statutory_validated","identity_proofing_verified"):
                self.assertIs(result[flag],False)
            for changes in (dict(trusted_tenant="ci-b"),dict(trusted_principal="e2"),dict(receipt="r1"),dict(token="x"*43),
                            dict(draft=replace(draft,worker="w2")),dict(draft=replace(draft,tenant="ci-b"))):
                with self.assertRaises(AccessDenied):review_bound_statement(conn,**dict(options,**changes))
            changed=deepcopy(wrapped)
            changed["wage_statement_reference"]["proposed_payment_date"]="2026-12-11"
            with self.assertRaises(AccessDenied):
                review_bound_statement(conn,**dict(options,draft=replace(draft,result=changed)))
            conn.execute("RESET ROLE")
            conn.execute("UPDATE naruv_employee_ci.entitlements SET active=false WHERE tenant='ci-a' AND receipt='r2'")
            conn.execute("SET LOCAL ROLE naruv_employee_ci_a")
            with self.assertRaises(AccessDenied):review_bound_statement(conn,**options)
            conn.execute("RESET ROLE")
            print("EMPLOYEE_STATEMENT_RENDER_BINDING=PASS")
            conn.execute("SET LOCAL naruv.employee_store_ci='OFF'")
            with self.assertRaises(AccessDenied):store.access(conn,**args)
        finally:
            conn.rollback()
            self.assertIsNone(conn.execute("SELECT to_regnamespace('naruv_employee_ci')").fetchone()[0])
            conn.close()
    def test_synthetic_provider_proof_one_time_binding(self):
        from dataclasses import replace
        from app import naruv_employee_proof_review as proof
        dsn=os.environ["JW_PG_CI_ROOT_DSN"]
        cfg=conninfo_to_dict(dsn)
        self.assertEqual((cfg.get("host"),cfg.get("port"),cfg.get("dbname"),cfg.get("user")),("127.0.0.1","5432","postgres","postgres"))
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"),"true")
        conn=psycopg.connect(dsn)
        try:
            conn.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
            conn.execute(Path("db/review/naruv_employee_session_store_ci.sql").read_text())
            conn.execute(proof.DDL)
            for tenant in ("ci-a","ci-b"):
                conn.execute("INSERT INTO naruv_employee_ci.identities VALUES (%s,'e1','w1',1,true)",(tenant,))
                conn.execute("INSERT INTO naruv_employee_ci.entitlements VALUES (%s,'w1','r1',%s,%s,true)",(tenant,"a"*64,"b"*64))
                tag=proof.synthetic_tag(b"x"*32,tenant,"fixture-person")
                conn.execute("INSERT INTO naruv_employee_ci.proof_enrollment VALUES (%s,'e1','w1',%s,true)",(tenant,tag))
            bind=dict(tenant="ci-a",principal="e1",receipt="r1")
            tag=proof.synthetic_tag(b"x"*32,"ci-a","fixture-person")
            challenge=proof.begin(conn,**bind)
            result=proof.SyntheticServerResult(challenge,"VERIFIED",tag)
            opts=dict(**bind,challenge=challenge,result=result)
            for changes in (dict(tenant="ci-b"),dict(receipt="r2"),dict(challenge="x"*43),
                            dict(result=replace(result,status="FAILED")),dict(result=replace(result,subject_tag="a"*64)),
                            dict(result=replace(result,provider="UNTRUSTED")),dict(result={"status":"VERIFIED"})):
                with self.assertRaises(AccessDenied):proof.finish(conn,**dict(opts,**changes))
            other=dict(tenant="ci-b",principal="e1",receipt="r1")
            other_challenge=proof.begin(conn,**other)
            for update,undo in (
                ("UPDATE naruv_employee_ci.identities SET auth_epoch=2 WHERE tenant='ci-a'","UPDATE naruv_employee_ci.identities SET auth_epoch=1 WHERE tenant='ci-a'"),
                ("UPDATE naruv_employee_ci.identities SET active=false WHERE tenant='ci-a'","UPDATE naruv_employee_ci.identities SET active=true WHERE tenant='ci-a'"),
                ("UPDATE naruv_employee_ci.proof_enrollment SET active=false WHERE tenant='ci-a'","UPDATE naruv_employee_ci.proof_enrollment SET active=true WHERE tenant='ci-a'"),
                ("UPDATE naruv_employee_ci.entitlements SET active=false WHERE tenant='ci-a'","UPDATE naruv_employee_ci.entitlements SET active=true WHERE tenant='ci-a'"),
                ("UPDATE naruv_employee_ci.entitlements SET review_sha256=repeat('c',64) WHERE tenant='ci-a'","UPDATE naruv_employee_ci.entitlements SET review_sha256=repeat('a',64) WHERE tenant='ci-a'"),
                ("UPDATE naruv_employee_ci.entitlements SET render_sha256=repeat('d',64) WHERE tenant='ci-a'","UPDATE naruv_employee_ci.entitlements SET render_sha256=repeat('b',64) WHERE tenant='ci-a'")):
                conn.execute(update)
                with self.assertRaises(AccessDenied):proof.finish(conn,**opts)
                conn.execute(undo)
                with self.assertRaises(AccessDenied):proof.finish(conn,**opts)
                self.assertEqual(conn.execute("SELECT consumed,invalidated FROM naruv_employee_ci.proof_challenges WHERE id=%s",(challenge,)).fetchone(),(False,True))
                self.assertEqual(conn.execute("SELECT count(*) FROM naruv_employee_ci.sessions").fetchone()[0],0)
                with self.assertRaises(psycopg.errors.CheckViolation):
                    with conn.transaction():conn.execute("UPDATE naruv_employee_ci.proof_challenges SET invalidated=false WHERE id=%s",(challenge,))
                challenge=proof.begin(conn,**bind)
                result=proof.SyntheticServerResult(challenge,"VERIFIED",tag)
                opts=dict(**bind,challenge=challenge,result=result)
            self.assertEqual(conn.execute("SELECT invalidated FROM naruv_employee_ci.proof_challenges WHERE id=%s",(other_challenge,)).fetchone(),(False,))
            conn.execute("UPDATE naruv_employee_ci.entitlements SET active=active WHERE tenant='ci-a'")
            self.assertEqual(conn.execute("SELECT invalidated FROM naruv_employee_ci.proof_challenges WHERE id=%s",(challenge,)).fetchone(),(False,))
            print("EMPLOYEE_PROOF_SNAPSHOT_DRIFT_DENIAL=PASS")
            print("EMPLOYEE_PROOF_HISTORICAL_REVOCATION=PASS")
            conn.execute("SET LOCAL ROLE naruv_employee_ci_a")
            with self.assertRaises(AccessDenied):proof.finish(conn,**opts)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():conn.execute("SELECT * FROM naruv_employee_ci.proof_enrollment")
            conn.execute("RESET ROLE")
            token,receipt=proof.finish(conn,**opts)
            self.assertTrue(receipt["synthetic_proof_binding_verified"])
            self.assertFalse(receipt["provider_identity_verified"])
            self.assertFalse(receipt["delivery_authorized"])
            self.assertTrue(store.access(conn,trusted_tenant="ci-a",trusted_principal="e1",receipt="r1",review_sha256="a"*64,render_sha256="b"*64,token=token)["session_store_verified"])
            with self.assertRaises(AccessDenied):proof.finish(conn,**opts)
            self.assertEqual(conn.execute("SELECT count(*) FROM naruv_employee_ci.sessions").fetchone()[0],1)
            conn.execute("UPDATE naruv_employee_ci.proof_enrollment SET active=false WHERE tenant='ci-a'")
            conn.execute("UPDATE naruv_employee_ci.proof_enrollment SET active=true WHERE tenant='ci-a'")
            with self.assertRaises(AccessDenied):
                store.access(conn,trusted_tenant="ci-a",trusted_principal="e1",receipt="r1",review_sha256="a"*64,render_sha256="b"*64,token=token)
            challenge=proof.begin(conn,**bind)
            conn.execute("UPDATE naruv_employee_ci.proof_challenges SET issued_at=1,expires_at=2 WHERE id=%s",(challenge,))
            with self.assertRaises(AccessDenied):proof.finish(conn,**bind,challenge=challenge,result=proof.SyntheticServerResult(challenge,"VERIFIED",tag))
            print("EMPLOYEE_SYNTHETIC_PROOF_ONE_TIME_BINDING=PASS")
        finally:
            conn.rollback()
            self.assertIsNone(conn.execute("SELECT to_regnamespace('naruv_employee_ci')").fetchone()[0])
            conn.close()

    def test_proof_concurrent_consume_and_atomic_rollback(self):
        from unittest.mock import patch
        from app import naruv_employee_proof_review as proof
        dsn=os.environ["JW_PG_CI_ROOT_DSN"]
        cfg=conninfo_to_dict(dsn)
        self.assertEqual((cfg.get("host"),cfg.get("port"),cfg.get("dbname"),cfg.get("user")),("127.0.0.1","5432","postgres","postgres"))
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"),"true")
        a=psycopg.connect(dsn)
        b=None
        created=False
        def begin(c):
            c.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            c.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
            c.execute("SET LOCAL lock_timeout='250ms'")
        try:
            begin(a)
            self.assertIsNone(a.execute("SELECT to_regnamespace('naruv_employee_ci')").fetchone()[0])
            a.execute(Path("db/review/naruv_employee_session_store_ci.sql").read_text())
            a.execute(proof.DDL)
            a.execute("INSERT INTO naruv_employee_ci.identities VALUES ('ci-a','e1','w1',1,true)")
            a.execute("INSERT INTO naruv_employee_ci.entitlements VALUES ('ci-a','w1','r1',%s,%s,true)",("a"*64,"b"*64))
            tag=proof.synthetic_tag(b"x"*32,"ci-a","fixture-person")
            a.execute("INSERT INTO naruv_employee_ci.proof_enrollment VALUES ('ci-a','e1','w1',%s,true)",(tag,))
            bind=dict(tenant="ci-a",principal="e1",receipt="r1")
            challenge=proof.begin(a,**bind)
            opts=dict(**bind,challenge=challenge,result=proof.SyntheticServerResult(challenge,"VERIFIED",tag))
            a.commit()
            created=True
            b=psycopg.connect(dsn)
            begin(a)
            with patch.object(store,"issue",side_effect=AccessDenied("INJECTED")):
                with self.assertRaises(AccessDenied):proof.finish(a,**opts)
            self.assertEqual(a.execute("SELECT consumed FROM naruv_employee_ci.proof_challenges WHERE id=%s",(challenge,)).fetchone(),(False,))
            self.assertEqual(a.execute("SELECT count(*) FROM naruv_employee_ci.sessions").fetchone(),(0,))
            a.commit()
            begin(a)
            token,report=proof.finish(a,**opts)
            self.assertTrue(report["synthetic_proof_binding_verified"])
            begin(b)
            with self.assertRaises(psycopg.errors.LockNotAvailable):proof.finish(b,**opts)
            b.rollback()
            a.commit()
            begin(b)
            with self.assertRaises(AccessDenied):proof.finish(b,**opts)
            self.assertEqual(b.execute("SELECT count(*) FROM naruv_employee_ci.sessions").fetchone(),(1,))
            self.assertTrue(store.access(b,trusted_tenant="ci-a",trusted_principal="e1",receipt="r1",review_sha256="a"*64,render_sha256="b"*64,token=token)["session_store_verified"])
            b.commit()
            begin(a)
            challenge=proof.begin(a,**bind)
            expired=dict(**bind,challenge=challenge,result=proof.SyntheticServerResult(challenge,"VERIFIED",tag))
            # Independently set a deterministic test clock to the expiry boundary.
            expiry=a.execute("SELECT expires_at FROM naruv_employee_ci.proof_challenges WHERE id=%s",(challenge,)).fetchone()[0]
            with patch.object(store,"_now",return_value=expiry):
                with self.assertRaises(AccessDenied):proof.finish(a,**expired)
            self.assertEqual(a.execute("SELECT consumed FROM naruv_employee_ci.proof_challenges WHERE id=%s",(challenge,)).fetchone(),(False,))
            a.rollback()
            print("EMPLOYEE_PROOF_ATOMIC_REPLAY_ROLLBACK=PASS")
        finally:
            if b is not None:b.close()
            a.rollback()
            try:
                if created:
                    a.execute("DROP SCHEMA naruv_employee_ci CASCADE")
                    a.execute("DROP ROLE naruv_employee_ci_a,naruv_employee_ci_b")
                    a.commit()
                    self.assertIsNone(a.execute("SELECT to_regnamespace('naruv_employee_ci')").fetchone()[0])
            finally:a.close()

    def test_committed_access_serializes_with_revocation(self):
        # A separate committed fixture is necessary for real independent transactions.
        dsn=os.environ["JW_PG_CI_ROOT_DSN"]
        cfg=conninfo_to_dict(dsn)
        self.assertEqual((cfg.get("host"),cfg.get("port"),cfg.get("dbname"),cfg.get("user")),
                         ("127.0.0.1","5432","postgres","postgres"))
        self.assertEqual(os.environ.get("GITHUB_ACTIONS"),"true")
        owner=psycopg.connect(dsn)
        reader=None
        created=False
        try:
            self.assertIsNone(owner.execute("SELECT to_regnamespace('naruv_employee_ci')").fetchone()[0])
            self.assertEqual(owner.execute("SELECT count(*) FROM pg_roles WHERE rolname IN ('naruv_employee_ci_a','naruv_employee_ci_b')").fetchone()[0],0)
            owner.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
            owner.execute(Path("db/review/naruv_employee_session_store_ci.sql").read_text())
            owner.execute("INSERT INTO naruv_employee_ci.identities VALUES ('ci-a','e1','w1',1,true)")
            owner.execute("INSERT INTO naruv_employee_ci.entitlements VALUES ('ci-a','w1','r1',%s,%s,true)",("a"*64,"b"*64))
            owner.commit()
            created=True
            reader=psycopg.connect(dsn)
            issue=dict(trusted_tenant="ci-a",trusted_principal="e1",receipt="r1")
            def begin():
                reader.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
                reader.execute("SET LOCAL naruv.employee_store_ci='DISPOSABLE_ONLY'")
                reader.execute("SET LOCAL ROLE naruv_employee_ci_a")
            for revoke,restore in (
                ("UPDATE naruv_employee_ci.identities SET auth_epoch=2","UPDATE naruv_employee_ci.identities SET auth_epoch=1"),
                ("UPDATE naruv_employee_ci.entitlements SET active=false","UPDATE naruv_employee_ci.entitlements SET active=true"),
                ("UPDATE naruv_employee_ci.sessions SET revoked=true",None)):
                begin()
                token=store.issue(reader,**issue)
                reader.commit()
                args=dict(**issue,review_sha256="a"*64,render_sha256="b"*64,token=token)
                begin()
                self.assertTrue(store.access(reader,**args)["session_store_verified"])
                # Locks must be held until the access transaction completes.
                owner.execute("SET LOCAL lock_timeout='250ms'")
                with self.assertRaises(psycopg.errors.LockNotAvailable):
                    with owner.transaction():owner.execute(revoke)
                owner.rollback()
                reader.commit()
                owner.execute(revoke)
                owner.commit()
                begin()
                with self.assertRaises(AccessDenied):store.access(reader,**args)
                reader.rollback()
                # Restore only synthetic fixture state for the next independent case.
                if restore is not None:
                    owner.execute(restore)
                    owner.commit()
                with self.assertRaises(psycopg.errors.CheckViolation):
                    with owner.transaction():owner.execute("UPDATE naruv_employee_ci.sessions SET revoked=false WHERE revoked")
                owner.rollback()
                begin()
                with self.assertRaises(AccessDenied):store.access(reader,**args)
                with self.assertRaises(AccessDenied):store.access(reader,**dict(args,token="x"*43))
                reader.rollback()
            print("EMPLOYEE_SESSION_HISTORICAL_REVOCATION=PASS")
            print("EMPLOYEE_ACCESS_REVOCATION_SERIALIZATION=PASS")
        finally:
            if reader is not None:reader.close()
            owner.rollback()
            try:
                if created:
                    owner.execute("DROP SCHEMA naruv_employee_ci CASCADE")
                    owner.execute("DROP ROLE naruv_employee_ci_a,naruv_employee_ci_b")
                    owner.commit()
                    self.assertIsNone(owner.execute("SELECT to_regnamespace('naruv_employee_ci')").fetchone()[0])
                    self.assertEqual(owner.execute("SELECT count(*) FROM pg_roles WHERE rolname IN ('naruv_employee_ci_a','naruv_employee_ci_b')").fetchone()[0],0)
                    print("EMPLOYEE_CONCURRENCY_FIXTURE_CLEANUP=PASS")
            finally:owner.close()

if __name__=="__main__":unittest.main()
