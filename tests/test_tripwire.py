"""Seeded tamper tests for Control-Plane Tripwire. Run: python -m unittest discover tests"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

SKILL = Path(__file__).resolve().parents[1] / "skills" / "control-plane-tripwire"
sys.path.insert(0, str(SKILL / "scripts"))
import tripwire  # noqa: E402

DEMO = SKILL / "assets" / "fixtures" / "demo"


def run_demo(**kw):
    return tripwire.run(DEMO / "policy.json", DEMO / "baseline.json", DEMO / "current.json", DEMO / "change-events.json", kw.get("sha"))


class TwelveCaseFixture(unittest.TestCase):
    def setUp(self):
        self.report = run_demo()
        self.by_id = {r["control_id"]: r for r in self.report["results"]}

    def test_every_control_matches_expected_verdict(self):
        expected = json.loads((DEMO / "expected-verdicts.json").read_text())
        self.assertEqual(len(expected), 12)
        for cid, verdict in expected.items():
            with self.subTest(control=cid):
                self.assertEqual(self.by_id[cid]["verdict"], verdict, self.by_id[cid]["rationale"])

    def test_exactly_four_tamper_cases_caught(self):
        self.assertEqual(self.report["tamper_count"], 4)
        self.assertEqual(self.report["status"], "TAMPER_DETECTED")

    def test_unknown_is_never_reported_safe(self):
        self.assertEqual(self.by_id["agent.policy.require_human_approval_prod"]["verdict"], "UNVERIFIABLE")
        self.assertIn("agent.policy.require_human_approval_prod", self.report["human_decision_required"])

    def test_every_verdict_carries_evidence(self):
        for r in self.report["results"]:
            for key in ("baseline", "current", "rule", "rationale", "change_event"):
                self.assertIn(key, r)


class PolicyIntegrity(unittest.TestCase):
    def test_pinned_hash_mismatch_stops_evaluation(self):
        report = run_demo(sha="0" * 64)
        self.assertEqual(report["status"], "POLICY_INTEGRITY_FAILURE")
        self.assertEqual(report["results"], [])

    def test_pinned_hash_match_runs(self):
        sha = tripwire.sha256(DEMO / "policy.json")
        self.assertEqual(run_demo(sha=sha)["status"], "TAMPER_DETECTED")


class CleanRun(unittest.TestCase):
    def test_identical_snapshots_produce_no_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            empty = Path(d) / "events.json"
            empty.write_text("[]")
            report = tripwire.run(DEMO / "policy.json", DEMO / "baseline.json", DEMO / "baseline.json", empty, None)
        self.assertEqual(report["status"], "NO_TAMPER_DETECTED")
        self.assertEqual(report["tamper_count"], 0)


if __name__ == "__main__":
    unittest.main()
