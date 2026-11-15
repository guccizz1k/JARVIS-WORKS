import sqlite3
import unittest
from scripts.jw_jteam_durable_dispatch import setup,dispatch
class JTeamDurableDispatchTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        setup(self.db)
        self.calls=[]
    def worker(self,role,task):
        self.calls.append(role)
        return {"receipt_id":"offline-"+role,"input_tokens":3,"output_tokens":2}
    def test_no_worker_blocks(self):
        with self.assertRaises(PermissionError):dispatch(self.db,"id","task")
    def test_five_roles(self):
        r=dispatch(self.db,"id","task",self.worker)
        self.assertEqual(r["role_receipts"],5)
        self.assertEqual(r["release"],"BLOCKED")
    def test_resume_skips_completed(self):
        with self.assertRaisesRegex(RuntimeError,"INTERRUPTION"):
            dispatch(self.db,"id","task",self.worker,fail_after="manager")
        self.assertEqual(len(self.calls),3)
        dispatch(self.db,"id","task",self.worker)
        self.assertEqual(len(self.calls),5)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM usage_events").fetchone()[0],5)
    def test_same_id_different_task_rejected(self):
        dispatch(self.db,"id","task",self.worker)
        with self.assertRaises(ValueError):dispatch(self.db,"id","different",self.worker)
    def test_bad_usage_blocks(self):
        with self.assertRaisesRegex(ValueError,"INVALID_USAGE"):
            dispatch(self.db,"id","task",lambda r,t:{"receipt_id":"x","input_tokens":-1})
        self.assertEqual(self.db.execute("SELECT state FROM jobs WHERE id='id'").fetchone()[0],"BLOCKED")
    def test_usage_cost_unverified(self):
        dispatch(self.db,"id","task",self.worker)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM usage_events WHERE estimated_krw IS NULL").fetchone()[0],5)
if __name__=="__main__":unittest.main()
