import sqlite3
import tempfile
import unittest
from scripts.jw_jteam_durable_simulator import initialize,simulate
class DurableSimulatorTests(unittest.TestCase):
    def setUp(self):
        self.db=sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        initialize(self.db)
    def test_five_role_checkpoints(self):
        result=simulate(self.db,"job-1","sample")
        self.assertEqual(len(result["roles"]),5)
        self.assertEqual(result["actual_model_calls"],0)
    def test_idempotent_resume(self):
        simulate(self.db,"job-1","sample")
        simulate(self.db,"job-1","sample")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0],5)
    def test_reused_id_different_task_fails(self):
        simulate(self.db,"job-1","sample")
        with self.assertRaisesRegex(ValueError,"JOB_ID_TASK_MISMATCH"):
            simulate(self.db,"job-1","changed")
    def test_release_never_approved(self):
        self.assertEqual(simulate(self.db,"job-2","sample")["release"],"BLOCKED")
    def test_receipts_cannot_claim_real_models(self):
        simulate(self.db,"job-1","sample")
        for (receipt,) in self.db.execute("SELECT receipt FROM checkpoints"):
            self.assertIn('"real_model_executed": false',receipt)
if __name__=="__main__":unittest.main()
