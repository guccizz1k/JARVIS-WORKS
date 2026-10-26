"""Offline negative tests; does not create external model/team sessions."""
import json
import tempfile
import unittest
from pathlib import Path
from scripts.jw_agent_team_gate import audit, evaluate_receipts, ORDER

SHA="a"*40

def make_fixture(root):
    from scripts.jw_agent_team_gate import TEAM
    roles=[]
    for i,name in enumerate(ORDER):
        roles.append(dict(id=name,depends_on=[] if i<2 else ([ORDER[0],ORDER[1]] if i==2 else [ORDER[i-1]]),
                          can_commit=name=="jarvis_lead",may_execute_paid_tools=False,
                          skills=["jw-verified-delivery"],output="reviewed_artifact"))
    doc=dict(schema="jw-agent-team-v1",team_id="jarvis-works-one-team",harness="J1-J6",
        status="REVIEW_ONLY",runtime="MODEL_DISPATCH_NOT_CONFIGURED",
        single_writer="jarvis_lead",signoff="HUMAN_RELEASE_SIGNOFF_REQUIRED",
        actual_model_session_started=False,max_concurrent_subagents=2,
        monthly_caps=dict(github_actions_extra_usd=5,openai_api_krw=50000,
                          automatic_cloud_spend=False,render_plan_approved=False),
        must_not=["main","production","live_db_migrations","unapproved_paid_api"],
        roles=roles)
    f=root/TEAM
    f.parent.mkdir(parents=True)
    f.write_text(json.dumps(doc),encoding="utf-8")
    p=root/".agents/skills/jw-verified-delivery/SKILL.md"
    p.parent.mkdir(parents=True)
    p.write_text("existing",encoding="utf-8")
    for name in ORDER:
        r=f.parent/"roles"/(name+".md")
        r.parent.mkdir(parents=True,exist_ok=True)
        r.write_text("J1–J6 review BLOCKED until verified PASS; main protected",encoding="utf-8")
    return f

class AgentTeamGate(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.path=make_fixture(self.root)
    def mutate(self,fn):
        obj=json.loads(self.path.read_text())
        fn(obj)
        self.path.write_text(json.dumps(obj))
    def contains(self,s):
        self.assertIn(s," | ".join(audit(self.root)))
    def test_valid_fixture(self):self.assertEqual(audit(self.root),[])
    def test_exclusive_writer(self):
        self.mutate(lambda x:x["roles"][0].update(can_commit=True))
        self.contains("write boundary")
    def test_order_or_role_swap(self):
        self.mutate(lambda x:x["roles"].reverse())
        self.contains("roles/order")
    def test_forged_model_run(self):
        self.mutate(lambda x:x.update(actual_model_session_started=True))
        self.contains("unproven team execution")
    def test_budget_raise(self):
        self.mutate(lambda x:x["monthly_caps"].update(openai_api_krw=50001))
        self.contains("spending policy")
    def test_malformed_protected_lists_fail_closed(self):
        self.mutate(lambda x:x.update(must_not=[{"evil":1}]))
        self.contains("main/production protection")

    def test_malformed_dep_list_fails_closed(self):
        self.mutate(lambda x:x["roles"][2].update(depends_on=[{"bad":True}]))
        self.contains("dependency DAG")

    def test_paid_tool(self):
        self.mutate(lambda x:x["roles"][3].update(may_execute_paid_tools=True))
        self.contains("paid tool")
    def test_circular_dependency(self):
        self.mutate(lambda x:x["roles"][0].update(depends_on=["jarvis_lead"]))
        self.contains("dependency DAG")
    def test_missing_skill(self):
        (self.root/".agents/skills/jw-verified-delivery/SKILL.md").unlink()
        self.contains("uninstalled local skill")
    def test_missing_prompt(self):
        (self.path.parent/"roles/deputy.md").unlink()
        self.contains("role prompt missing")
    def test_claims_with_any_status_never_approve_release(self):
        for status in ("PASS","FAIL","NOT RUN"):
            r={"sha":SHA,"receipts":[{"role":n,"status":status,"run_ref":"self-asserted"} for n in ORDER]}
            out=evaluate_receipts(r,SHA)
            self.assertEqual(out["release"],"BLOCKED")
            self.assertEqual(out["team_run"],"NOT_ATTESTED")
    def test_invalid_receipt_sha(self):
        out=evaluate_receipts({"sha":"b"*40,"receipts":[]},SHA)
        self.assertEqual(out["status"],"BLOCKED")
    def test_wrong_receipt_order(self):
        r={"sha":SHA,"receipts":[{"role":n,"status":"PASS","run_ref":"x"} for n in reversed(ORDER)]}
        self.assertEqual(evaluate_receipts(r,SHA)["status"],"BLOCKED")

if __name__=="__main__":
    unittest.main()
