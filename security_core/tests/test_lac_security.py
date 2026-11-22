"""Testes negativos e positivos do LAC Security Core, sem conexão externa."""
import json
import io
import tarfile
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import lac_security as core


class TestScanner(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "app"
        self.root.mkdir()

    def write(self, name, data):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding="utf-8")
        return p

    def rules(self):
        return [f["rule"] for f in core.audit(self.root)["findings"]]

    def test_clean_app(self):
        self.write("main.py", "import json\nprint(json.dumps({'ok': True}))\n")
        self.assertEqual(self.rules(), [])

    def test_python_ast_does_not_flag_eval_in_comment(self):
        self.write("main.py", "# eval('bad')\ntext = \"eval('not executed')\"\n")
        self.assertNotIn("PY_DYNAMIC_EXEC", self.rules())

    def test_python_exec(self):
        self.write("main.py", "eval(user_input)\n")
        self.assertIn("PY_DYNAMIC_EXEC", self.rules())

    def test_shell_true(self):
        self.write("main.py", "import subprocess\nsubprocess.run('echo test', shell=True)\n")
        self.assertIn("PY_SHELL_TRUE", self.rules())

    def test_pickle_deserialize(self):
        self.write("main.py", "import pickle\npickle.loads(payload)\n")
        self.assertIn("PY_DESERIALIZE", self.rules())

    def test_debug_true(self):
        self.write("main.py", "DEBUG = True\n")
        self.assertIn("DEBUG_ENABLED", self.rules())

    def test_tls_verification(self):
        self.write("main.py", "result = requests.get(url, verify=False)\n")
        self.assertIn("TLS_VALIDATION_DISABLED", self.rules())

    def test_secrets_are_never_printed(self):
        secret = "ThisIsARealLookingTestingSecret123"
        self.write("main.py", f'client_secret = "{secret}"\n')
        report = core.audit(self.root)
        self.assertIn("POTENTIAL_SECRET", self.rules())
        self.assertNotIn(secret, json.dumps(report))
        self.assertNotIn(secret, core.markdown(report))

    def test_test_fixture_literal_is_low_severity(self):
        self.write("test_auth.py", 'password = "CredentialOnlyForAutomatedTests123"\n')
        report = core.audit(self.root)
        self.assertEqual(report["findings"][0]["severity"], "LOW")

    def test_placeholder_ignored(self):
        self.write(".env.example", "APP_PASSWORD=definir_senha_forte\n")
        self.assertNotIn("POTENTIAL_SECRET", self.rules())

    def test_html_sink(self):
        self.write("index.html", "<script>out.innerHTML = value</script>\n")
        self.assertIn("DOM_HTML_SINK", self.rules())

    def test_localstorage(self):
        self.write("index.js", "localStorage.setItem('chat', history)\n")
        self.assertIn("BROWSER_STORAGE_REVIEW", self.rules())

    def test_dependency_pin(self):
        self.write("requirements.txt", "flask>=3\nrequests==2.32.4\n")
        self.assertEqual(self.rules().count("PY_DEPENDENCY_NOT_PINNED"), 1)

    def test_node_dependency_unbounded(self):
        self.write("package.json", '{"dependencies":{"old":"latest"}}')
        self.assertIn("NODE_UNBOUNDED_DEPENDENCY", self.rules())

    def test_invalid_json(self):
        self.write("package.json", "{broken")
        self.assertIn("PACKAGE_JSON_INVALID", self.rules())

    def test_archive_incomplete(self):
        (self.root / "app_source.tar.xz").write_bytes(b"sample")
        result = core.audit(self.root)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["summary"]["unscanned_files"], 1)

    def test_tar_source_scanning_without_extraction(self):
        source = b"exec(input_data)\n"
        archive = self.root / "app_source.tar.xz"
        with tarfile.open(archive, "w:xz") as tar:
            metadata = tarfile.TarInfo("code/main.py")
            metadata.size = len(source)
            tar.addfile(metadata, io.BytesIO(source))
        result = core.audit(self.root)
        self.assertIn("PY_DYNAMIC_EXEC", [x["rule"] for x in result["findings"]])
        self.assertEqual(result["summary"]["unscanned_files"], 0)
        self.assertEqual(result["summary"]["files_scanned"], 1)
        self.assertFalse((self.root / "code").exists())

    def test_tar_rejects_traversal_path(self):
        archive = self.root / "app_source.tar.xz"
        source = b"print('safe')\n"
        with tarfile.open(archive, "w:xz") as tar:
            entry = tarfile.TarInfo("../outside.py")
            entry.size = len(source)
            tar.addfile(entry, io.BytesIO(source))
        result = core.audit(self.root)
        self.assertEqual(result["status"], "PARTIAL")
        self.assertEqual(result["summary"]["files_scanned"], 0)
        self.assertFalse((self.root.parent / "outside.py").exists())

    def test_excludes_and_symlink(self):
        self.write("node_modules/bad.js", "eval('test')\n")
        self.write("ignored/bad.js", "eval('test')\n")
        self.assertEqual(core.audit(self.root, additional_excludes=("ignored/**",))["summary"]["findings"], 0)
        target = self.write("main.py", "print('safe')\n")
        (self.root / "link.py").symlink_to(target)
        self.assertEqual(core.audit(self.root)["summary"]["files_scanned"], 2)

    def test_size_limit_incomplete(self):
        self.write("large.py", "x=" + "0" * 101)
        result = core.audit(self.root, max_bytes=10)
        self.assertEqual(result["status"], "PARTIAL")

    def test_cli_generates_reports_and_exit_codes(self):
        self.write("main.py", "exec(user_input)\n")
        reports = Path(self.temp.name) / "reports"
        self.assertEqual(core.main([str(self.root), "--output", str(reports), "--fail-on", "critical"]), 0)
        self.assertEqual(core.main([str(self.root), "--output", str(reports), "--fail-on", "high"]), 1)
        self.assertTrue((reports / "report.json").exists())
        self.assertTrue((reports / "report.md").exists())
        self.assertEqual(core.main([str(self.root / "notfound")]), 2)

    def test_scan_does_not_modify_input(self):
        file = self.write("main.py", "print('ok')\n")
        before = file.read_bytes()
        core.audit(self.root)
        self.assertEqual(file.read_bytes(), before)

    def test_consistent_fingerprint(self):
        self.write("main.py", "exec(value)\n")
        one, two = core.audit(self.root), core.audit(self.root)
        self.assertEqual(one["findings"][0]["fingerprint"], two["findings"][0]["fingerprint"])

    def test_raw_password_storage_high(self):
        self.write("auth.ts", 'localStorage.setItem(`user_password_${id}`, password);\n')
        findings = core.audit(self.root)["findings"]
        self.assertTrue(any(x["rule"] == "BROWSER_RAW_CREDENTIAL" and x["severity"] == "HIGH" for x in findings))

    def test_raw_token_storage_high(self):
        self.write("auth.js", 'sessionStorage.setItem("token", accessToken);\n')
        self.assertIn("BROWSER_RAW_CREDENTIAL", self.rules())

    def test_derived_value_not_raw(self):
        self.write("auth.js", 'localStorage.setItem("verifier", encoded);\n')
        self.assertNotIn("BROWSER_RAW_CREDENTIAL", self.rules())

    def test_auth_state_read(self):
        self.write("auth.ts", 'const state = localStorage.getItem("current_user");\n')
        self.assertIn("BROWSER_AUTH_STATE", self.rules())

    def test_theme_read_not_auth(self):
        self.write("theme.js", 'const theme = localStorage.getItem("theme");\n')
        self.assertNotIn("BROWSER_AUTH_STATE", self.rules())

    def test_empty_html_reset_not_sink(self):
        self.write("preview.js", 'preview.innerHTML = "";\n')
        self.assertNotIn("DOM_HTML_SINK", self.rules())


if __name__ == "__main__":
    unittest.main()
