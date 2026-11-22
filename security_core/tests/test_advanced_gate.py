"""Safety regressions for minimal, non-sensitive v3 reporting."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import advanced_gate as gate

def report(high=0, med=0, skipped=0):
    return {"summary":{"files_scanned":10,"findings":high+med,"high":high,"critical":0,
                       "medium":med,"low":0,"unscanned_files":skipped}}

class TestGate(unittest.TestCase):
    def test_clean_is_not_approval(self):
        r=gate.evaluate(report(),[],{"results":[],"errors":[]})
        self.assertEqual(r["status"],"AUTOMATED_CHECKS_CLEAR")
        self.assertFalse(r["production_approved"])
    def test_lac_high_blocks(self):
        self.assertEqual(gate.evaluate(report(high=1),[],{"results":[]})["status"],"BLOCKED_REVIEW")
    def test_potential_secret_blocks(self):
        leak={"Secret":"DoNotCopyThisPotentialSecret", "Match":"DoNotCopyThisPotentialSecret"}
        r=gate.evaluate(report(),[leak],{"results":[]})
        self.assertEqual(r["status"],"BLOCKED_REVIEW")
        self.assertNotIn("DoNotCopyThisPotentialSecret",json.dumps(r))
        self.assertNotIn("DoNotCopyThisPotentialSecret",gate.render_markdown(r))
    def test_semgrep_error_blocks_without_snippet(self):
        raw={"results":[{"extra":{"severity":"ERROR","lines":"SECRET_NOT_FOR_REPORT"}}]}
        out=gate.evaluate(report(),[],raw)
        self.assertEqual(out["status"],"BLOCKED_REVIEW")
        self.assertNotIn("SECRET_NOT_FOR_REPORT",json.dumps(out))
    def test_medium_needs_review(self):
        self.assertEqual(gate.evaluate(report(med=1),[],{"results":[]})["status"],"REVIEW_REQUIRED")
    def test_skipped_is_incomplete(self):
        self.assertEqual(gate.evaluate(report(skipped=1),[],{"results":[]})["status"],"INCOMPLETE")
    def test_semgrep_errors_incomplete(self):
        self.assertEqual(gate.evaluate(report(),[],{"results":[],"errors":["scanner failed"]})["status"],"INCOMPLETE")
    def test_missing_data_rejected(self):
        for bad in (None, [], {}):
            with self.assertRaises(ValueError):
                gate.evaluate(bad,[],{"results":[]})
    def test_invalid_leak_data_rejected(self):
        with self.assertRaises(ValueError):
            gate.evaluate(report(),{"secret":"x"},{"results":[]})
    def test_output_minimal_without_findings(self):
        r=gate.evaluate(report(),[],{"results":[{"extra":{"severity":"WARNING","lines":"CODE"}}]})
        self.assertEqual(r["status"],"REVIEW_REQUIRED")
        self.assertNotIn("CODE",gate.render_markdown(r))
if __name__ == "__main__":
    unittest.main()
