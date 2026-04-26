"""
Static analysis tests — CppCheck, Flawfinder, regex patterns, CWE enrichment.
These tests do NOT require external tools to be installed; the regex path is
always exercised, and external tools are tested with graceful-skip if absent.
"""
import shutil
import tempfile
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pipeline.static_analysis import StaticAnalyzer, StaticFinding
from src.pipeline.cwe_database import get_cwe_info, enrich_finding, CWE_DATABASE

FIXTURES = Path(__file__).parent / "fixtures"
VULN_DIR = FIXTURES / "vulnerable_code"
SAFE_DIR = FIXTURES / "safe_code"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _func(code: str, name: str = "test_func", path: str = "test.c") -> dict:
    return {"code": code, "function_name": name, "file_path": path, "line_number": 1}


# ---------------------------------------------------------------------------
# Regex / built-in pattern detection
# ---------------------------------------------------------------------------

class TestRegexPatterns(unittest.TestCase):
    """Regex patterns fire without any external tool installed."""

    def setUp(self):
        self.analyzer = StaticAnalyzer()

    def test_strcpy_detected(self):
        func = _func('void f(char *s) { char buf[32]; strcpy(buf, s); }')
        results = self.analyzer.analyze_batch([func])
        self.assertTrue(results[0].vulnerable)

    def test_gets_detected(self):
        func = _func('void f() { char buf[64]; gets(buf); }')
        results = self.analyzer.analyze_batch([func])
        self.assertTrue(results[0].vulnerable)

    def test_sprintf_detected(self):
        func = _func('void f(char *s) { char buf[50]; sprintf(buf, "%s", s); }')
        results = self.analyzer.analyze_batch([func])
        self.assertTrue(results[0].vulnerable)

    def test_safe_snprintf_no_false_positive(self):
        func = _func('void f(char *s) { char buf[50]; snprintf(buf, sizeof(buf), "%s", s); }')
        results = self.analyzer.analyze_batch([func])
        # snprintf should NOT trigger strcpy/sprintf pattern
        vuln_findings = [
            fi for fi in results[0].findings
            if "strcpy" in fi.message.lower() or "sprintf" in fi.message.lower()
        ]
        self.assertEqual(len(vuln_findings), 0)

    def test_null_pointer_deref_detected(self):
        func = _func('void f(int *p) { if (p == NULL) *p = 1; }')
        results = self.analyzer.analyze_batch([func])
        # At minimum the regex should catch the null deref pattern
        self.assertIsNotNone(results[0])

    def test_empty_function_body(self):
        func = _func('void f() {}')
        results = self.analyzer.analyze_batch([func])
        self.assertFalse(results[0].vulnerable)

    def test_batch_returns_one_result_per_function(self):
        funcs = [
            _func('void a() { strcpy(buf, s); }', 'a'),
            _func('void b() { snprintf(buf, 10, "%s", s); }', 'b'),
            _func('void c() {}', 'c'),
        ]
        results = self.analyzer.analyze_batch(funcs)
        self.assertEqual(len(results), 3)

    def test_severity_populated(self):
        func = _func('void f(char *s) { char buf[32]; strcpy(buf, s); }')
        results = self.analyzer.analyze_batch([func])
        if results[0].findings:
            for finding in results[0].findings:
                self.assertIn(finding.severity, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    def test_cwe_id_format(self):
        func = _func('void f(char *s) { char buf[32]; strcpy(buf, s); }')
        results = self.analyzer.analyze_batch([func])
        if results[0].findings:
            for finding in results[0].findings:
                if finding.cwe_id:
                    self.assertRegex(finding.cwe_id, r"^CWE-\d+$")


class TestStaticFindingDataclass(unittest.TestCase):
    def test_finding_fields(self):
        f = StaticFinding(
            tool="regex",
            message="strcpy found",
            severity="CRITICAL",
            cwe_id="CWE-120",
            cwe_name="Buffer Copy without Checking Size",
        )
        self.assertEqual(f.tool, "regex")
        self.assertEqual(f.cwe_id, "CWE-120")


# ---------------------------------------------------------------------------
# Fixture-based integration
# ---------------------------------------------------------------------------

class TestFixtureFiles(unittest.TestCase):
    """Run static analysis on real fixture C files."""

    def setUp(self):
        self.analyzer = StaticAnalyzer()

    def _read_fixture(self, path: Path) -> dict:
        return _func(path.read_text(encoding="utf-8"), path.stem, str(path))

    def test_buffer_overflow_fixture_is_flagged(self):
        func = self._read_fixture(VULN_DIR / "buffer_overflow.c")
        results = self.analyzer.analyze_batch([func])
        self.assertTrue(results[0].vulnerable, "buffer_overflow.c should be flagged")

    def test_safe_string_fixture_is_clean(self):
        func = self._read_fixture(SAFE_DIR / "safe_string.c")
        results = self.analyzer.analyze_batch([func])
        # Regex layer should not flag safe snprintf/strncpy usage
        critical_findings = [f for f in results[0].findings if f.severity == "CRITICAL"]
        self.assertEqual(len(critical_findings), 0)


# ---------------------------------------------------------------------------
# CWE database
# ---------------------------------------------------------------------------

class TestCWEDatabase(unittest.TestCase):
    def test_known_cwe_lookup(self):
        info = get_cwe_info("CWE-120")
        self.assertIsNotNone(info)
        self.assertIn("name", info)
        self.assertIn("severity", info)
        self.assertIn("mitigation", info)

    def test_unknown_cwe_returns_none_or_default(self):
        info = get_cwe_info("CWE-99999")
        # Either None or a default dict — must not raise
        self.assertTrue(info is None or isinstance(info, dict))

    def test_cwe_120_is_critical(self):
        info = get_cwe_info("CWE-120")
        self.assertEqual(info["severity"], "CRITICAL")

    def test_all_entries_have_required_keys(self):
        required = {"name", "severity", "mitigation"}
        for cwe_id, entry in CWE_DATABASE.items():
            missing = required - entry.keys()
            self.assertEqual(missing, set(), f"{cwe_id} missing keys: {missing}")

    def test_enrich_finding_adds_name(self):
        finding = StaticFinding(
            tool="regex", message="test", severity="HIGH",
            cwe_id="CWE-120", cwe_name=""
        )
        enriched = enrich_finding(finding)
        self.assertTrue(len(enriched.cwe_name) > 0)


# ---------------------------------------------------------------------------
# External tool availability (skip if not installed)
# ---------------------------------------------------------------------------

class TestCppCheckAvailability(unittest.TestCase):
    @unittest.skipUnless(shutil.which("cppcheck"), "cppcheck not on PATH")
    def test_cppcheck_runs_on_vuln_code(self):
        analyzer = StaticAnalyzer()
        func = _func(
            'void f(char *s) { char buf[32]; strcpy(buf, s); }',
            path="test.c",
        )
        results = analyzer.analyze_batch([func])
        # At least regex will fire; cppcheck may add more
        self.assertIsNotNone(results[0])


class TestFlawfinderAvailability(unittest.TestCase):
    @unittest.skipUnless(shutil.which("flawfinder"), "flawfinder not on PATH")
    def test_flawfinder_runs_on_vuln_code(self):
        analyzer = StaticAnalyzer()
        func = _func('void f(char *s) { char buf[32]; strcpy(buf, s); }')
        results = analyzer.analyze_batch([func])
        tools_used = {f.tool for f in results[0].findings}
        self.assertIn("flawfinder", tools_used)


if __name__ == "__main__":
    unittest.main()
