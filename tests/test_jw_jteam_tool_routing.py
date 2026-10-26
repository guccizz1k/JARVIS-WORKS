import json
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
DATA=json.loads((ROOT/"agents/team/jarvis_v1/tool_routing.json").read_text(encoding="utf-8"))
class JTeamToolRoutingTests(unittest.TestCase):
    def test_five_distinct_tools(self):
        names=[t["name"] for t in DATA["tools"]]
        self.assertEqual(len(names),len(set(names)))
        self.assertTrue({"Playwright","axe-core","Ruff","Hypothesis","Schemathesis"}.issubset(names))
        self.assertEqual(set(names)-{"Playwright","axe-core","Ruff","Hypothesis","Schemathesis"},{"Fabric","Gitingest"})
    def test_existing_playwright_not_reinstalled(self):
        self.assertEqual(DATA["tools"][0]["status"],"EXISTING_PROJECT_SCRIPTS")
    def test_pilots_not_claimed_installed(self):
        self.assertTrue(all(t["status"]=="PILOT_NOT_INSTALLED" for t in DATA["tools"] if t["name"] in {"axe-core","Ruff","Hypothesis","Schemathesis"}))
    def test_reviewers_and_lead(self):
        self.assertEqual(DATA["integration_owner"],"jarvis_lead")
        self.assertTrue(all("director" in t["owners"] for t in DATA["tools"]))
    def test_external_sources_are_not_unreviewed_runtime_installs(self):
        tools={t["name"]:t for t in DATA["tools"]}
        self.assertEqual(tools["Fabric"]["status"],"PROJECT_LOCAL_PATTERN_ADAPTER")
        self.assertEqual(tools["Gitingest"]["status"],"PINNED_ISOLATED_PILOT")
        self.assertEqual(DATA["integration_owner"],"jarvis_lead")
    def test_guardrails(self):
        self.assertTrue({"main_merge","production_testing","unreviewed_install"}.issubset(DATA["must_not"]))
if __name__=="__main__":unittest.main()
