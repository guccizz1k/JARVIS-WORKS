import sqlite3
import unittest
from scripts.jw_jteam_durable_dispatch import setup, dispatch

class JTeamRetrySafetyTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        setup(self.db)
    def test_interrupted_remote_step_fails_closed(self):
        def crash(role,task):
            raise TimeoutError("provider response unknown")
        with self.assertRaises(TimeoutError):
            dispatch(self.db,"job","task",crash)
        called=[]
        def worker(role,task):
            called.append(role)
            return {"receipt_id":"x","input_tokens":1,"output_tokens":1}
        with self.assertRaisesRegex(PermissionError,"RECONCILIATION_REQUIRED"):
            dispatch(self.db,"job","task",worker)
        self.assertEqual(called,[])
    def test_running_checkpoint_fails_closed(self):
        with self.db:
            self.db.execute("INSERT INTO jobs VALUES ('job','{}','RUNNING',0)".format(__import__('hashlib').sha256(b'task').hexdigest()))
            self.db.execute("INSERT INTO steps VALUES ('job','deputy',0,'RUNNING',NULL)")
        with self.assertRaisesRegex(PermissionError,"RECONCILIATION_REQUIRED"):
            dispatch(self.db,"job","task",lambda r,t:{"receipt_id":"x"})
    def test_completed_checkpoint_skipped(self):
        calls=[]
        def worker(role,task):
            calls.append(role)
            return {"receipt_id":role,"input_tokens":1,"output_tokens":1}
        dispatch(self.db,"job","task",worker)
        dispatch(self.db,"job","task",worker)
        self.assertEqual(len(calls),5)
if __name__=="__main__":unittest.main()
