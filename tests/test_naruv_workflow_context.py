"""Regression guard for Actions context placement, without external dependencies."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
class WorkflowContext(unittest.TestCase):
    def test_restore_services_are_bound_at_step_scope(self):
        source=(ROOT/".github/workflows/naruv-migration-mapping-lab.yml").read_text()
        body=source.split("  native-file-write-pg17:\n",1)[1]
        job,steps=body.split("    steps:\n",1)
        self.assertNotIn("job.services.",job)
        self.assertIn("      erp_restore:\n",job)
        self.assertIn("          - 5433:5432",job)
        self.assertIn("        env:\n          NARUV_ERP_SOURCE_SERVICE: ${{ job.services.postgres.id }}\n          NARUV_ERP_DEST_SERVICE: ${{ job.services.erp_restore.id }}\n        run: |",steps)
        self.assertIn("python -m scripts.naruv_native_write_review_ci",steps)
        self.assertIn("      - scripts/naruv_erp_restore_ci.py\n",source)
