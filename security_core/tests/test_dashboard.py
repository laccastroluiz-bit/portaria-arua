import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import dashboard
from test_advanced_gate import report,gate
class TestDashboard(unittest.TestCase):
    def base(self):
        return gate.evaluate(report(),[],{"results":[],"errors":[]})
    def test_offline_page(self):
        html=dashboard.render(self.base())
        self.assertIn("LAC Security Center",html)
        self.assertIn("NÃO CONCEDIDA",html)
        self.assertNotIn("<script",html)
        self.assertNotIn('https://',html)
    def test_requires_sanitized_format(self):
        with self.assertRaises(ValueError):
            dashboard.render({"findings":[{"secret":"exposed"}]})
    def test_not_published_if_approval_claimed(self):
        d=self.base();d["production_approved"]=True
        with self.assertRaises(ValueError):
            dashboard.render(d)
    def test_no_user_supplied_string_interpolation(self):
        d=self.base();d["metadata"]="<script>malicious</script>"
        self.assertNotIn("malicious",dashboard.render(d))
    def test_non_numeric_metrics_rejected(self):
        d=self.base();d["results"]["lac_files"]="<script>bad</script>"
        with self.assertRaises(ValueError):
            dashboard.render(d)
if __name__=="__main__":
    unittest.main()
