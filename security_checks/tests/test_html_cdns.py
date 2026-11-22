"""Security regressions for HTML CDN version/integrity checker."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_html_cdns import inspect_html

SRI = "sha512-" + "A"*88

class CDNSecurityTests(unittest.TestCase):
    def tag(self, version="4.2.1", sri=SRI, crossorigin="anonymous", scheme="https"):
        return (f'<script src="{scheme}://cdnjs.cloudflare.com/ajax/libs/jspdf/{version}/jspdf.umd.min.js" '
                f'integrity="{sri}" crossorigin="{crossorigin}"></script>')

    def test_patched_version_with_integrity(self):
        errors, count = inspect_html(self.tag())
        self.assertEqual(errors, [])
        self.assertEqual(count, 1)

    def test_old_version_rejected(self):
        errors, _ = inspect_html(self.tag(version="2.5.1"))
        self.assertIn("JSPDF_KNOWN_VULNERABLE_VERSION", errors)

    def test_missing_integrity_rejected(self):
        errors, _ = inspect_html(self.tag(sri=""))
        self.assertIn("EXTERNAL_SCRIPT_MISSING_SRI", errors)

    def test_insecure_url_rejected(self):
        errors, _ = inspect_html(self.tag(scheme="http"))
        self.assertIn("EXTERNAL_SCRIPT_NOT_HTTPS", errors)

    def test_missing_cors_rejected(self):
        errors, _ = inspect_html(self.tag(crossorigin=""))
        self.assertIn("EXTERNAL_SCRIPT_MISSING_CORS", errors)

    def test_relative_script_is_not_external(self):
        self.assertEqual(inspect_html('<script src="vendor/jspdf.js"></script>'), ([], 0))

    def test_unpinned_jspdf_is_rejected(self):
        text='<script src="https://cdn.jsdelivr.net/npm/jspdf@latest/dist/jspdf.umd.min.js" integrity="'+SRI+'" crossorigin="anonymous"></script>'
        errors, _ = inspect_html(text)
        self.assertIn("JSPDF_UNPINNED", errors)

    def test_no_logging_or_reprinting_secret_query(self):
        text='<script src="https://example.org/app.js?apikey=do-not-display" integrity="'+SRI+'" crossorigin="anonymous"></script>'
        errors, n = inspect_html(text)
        self.assertEqual(errors, [])
        self.assertEqual(n, 1)

if __name__ == "__main__":
    unittest.main()
