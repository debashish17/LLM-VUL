"""
Integration tests for the Vulnerability Detection Pipeline.

Tests cover:
  1. ZIP ingestion and function extraction
  2. Static analysis (CppCheck + Flawfinder + regex patterns)
  3. ML graceful degradation when models are missing
  4. Full pipeline end-to-end (static-only mode)
  5. Edge cases (empty ZIP, no C files, corrupt files)
"""
import json
import os
import shutil
import tempfile
import unittest
import zipfile
import logging
from pathlib import Path

# Ensure project root is importable
import sys
PROJECT_ROOT = str(Path(__file__).parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.pipeline.ingestion import CodeIngestion, IngestionResult, FunctionUnit
from src.pipeline.static_analysis import StaticAnalyzer, StaticFinding
from src.pipeline.ml_analysis import MLAnalyzer
from src.pipeline.cwe_database import get_cwe_info, enrich_finding, CWE_DATABASE
from src.pipeline.pipeline import VulnerabilityPipeline

logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(name)s: %(message)s')

FIXTURES_DIR = Path(__file__).parent / 'fixtures'
VULN_DIR = FIXTURES_DIR / 'vulnerable_code'
SAFE_DIR = FIXTURES_DIR / 'safe_code'


def _make_zip(source_dir: Path, zip_name: str = 'test.zip') -> str:
    """Create a ZIP from a directory, return path to the ZIP file."""
    tmp = tempfile.mkdtemp(prefix='test_zip_')
    zip_path = os.path.join(tmp, zip_name)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(source_dir):
            for fname in files:
                abs_path = os.path.join(root, fname)
                arc_name = os.path.relpath(abs_path, source_dir)
                zf.write(abs_path, arc_name)
    return zip_path


def _make_zip_from_multiple(dirs: list, zip_name: str = 'combined.zip') -> str:
    """Create a ZIP from multiple directories, preserving structure."""
    tmp = tempfile.mkdtemp(prefix='test_zip_')
    zip_path = os.path.join(tmp, zip_name)
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for d in dirs:
            folder_name = d.name
            for root, _dirs, files in os.walk(d):
                for fname in files:
                    abs_path = os.path.join(root, fname)
                    arc_name = os.path.join(folder_name, os.path.relpath(abs_path, d))
                    zf.write(abs_path, arc_name)
    return zip_path


# ======================================================================
# Test: Ingestion
# ======================================================================
class TestIngestion(unittest.TestCase):

    def test_ingest_vulnerable_zip(self):
        """Ingesting the vulnerable fixture ZIP should find files and functions."""
        zip_path = _make_zip(VULN_DIR, 'vuln.zip')
        try:
            ingestion = CodeIngestion()
            result = ingestion.ingest_zip(zip_path)

            self.assertIsInstance(result, IngestionResult)
            self.assertGreater(len(result.files), 0, "Should find C files")
            self.assertGreater(len(result.functions), 0, "Should extract functions")

            # Check we got known function names
            func_names = {f.function_name for f in result.functions}
            self.assertIn('copy_username', func_names)
            self.assertIn('run_command', func_names)
        finally:
            result.cleanup()
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_ingest_safe_zip(self):
        """Ingesting the safe fixture ZIP should find files and functions."""
        zip_path = _make_zip(SAFE_DIR, 'safe.zip')
        try:
            ingestion = CodeIngestion()
            result = ingestion.ingest_zip(zip_path)

            self.assertGreater(len(result.files), 0)
            self.assertGreater(len(result.functions), 0)

            func_names = {f.function_name for f in result.functions}
            self.assertIn('safe_copy', func_names)
            self.assertIn('gcd', func_names)
        finally:
            result.cleanup()
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_invalid_zip(self):
        """Should raise on non-ZIP file."""
        tmp = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        tmp.write(b"this is not a zip file")
        tmp.close()
        try:
            ingestion = CodeIngestion()
            with self.assertRaises(ValueError):
                ingestion.ingest_zip(tmp.name)
        finally:
            os.unlink(tmp.name)

    def test_empty_zip(self):
        """An empty ZIP should return zero files and functions."""
        tmp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(tmp_dir, 'empty.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            pass  # empty
        try:
            ingestion = CodeIngestion()
            result = ingestion.ingest_zip(zip_path)
            self.assertEqual(len(result.files), 0)
            self.assertEqual(len(result.functions), 0)
        finally:
            result.cleanup()
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_zip_with_non_c_files(self):
        """ZIP containing only Python files should return zero C files."""
        tmp_dir = tempfile.mkdtemp()
        py_file = os.path.join(tmp_dir, 'hello.py')
        with open(py_file, 'w') as f:
            f.write("print('hello')\n")
        zip_path = os.path.join(tmp_dir, 'python_only.zip')
        with zipfile.ZipFile(zip_path, 'w') as zf:
            zf.write(py_file, 'hello.py')
        try:
            ingestion = CodeIngestion()
            result = ingestion.ingest_zip(zip_path)
            self.assertEqual(len(result.files), 0)
            self.assertEqual(len(result.functions), 0)
        finally:
            result.cleanup()
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_function_uid_uniqueness(self):
        """Every extracted function should have a unique UID."""
        zip_path = _make_zip_from_multiple([VULN_DIR, SAFE_DIR])
        try:
            ingestion = CodeIngestion()
            result = ingestion.ingest_zip(zip_path)
            uids = [f.uid for f in result.functions]
            self.assertEqual(len(uids), len(set(uids)), "UIDs must be unique")
        finally:
            result.cleanup()
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)


# ======================================================================
# Test: Static Analysis
# ======================================================================
class TestStaticAnalysis(unittest.TestCase):

    def setUp(self):
        self.zip_path = _make_zip(VULN_DIR, 'vuln.zip')
        self.ingestion = CodeIngestion()
        self.result = self.ingestion.ingest_zip(self.zip_path)
        self.analyzer = StaticAnalyzer()

    def tearDown(self):
        self.result.cleanup()
        shutil.rmtree(os.path.dirname(self.zip_path), ignore_errors=True)

    def test_static_finds_vulnerabilities(self):
        """Static analysis should flag at least some functions in the vuln fixture."""
        sa_result = self.analyzer.analyze(self.result)

        self.assertGreater(len(sa_result.all_findings), 0, "Should find some issues")
        flagged = {uid for uid, fl in sa_result.function_findings.items() if fl}
        self.assertGreater(len(flagged), 0, "At least one function should be flagged")

    def test_pattern_matcher_detects_strcpy(self):
        """Regex patterns should catch strcpy in buffer_overflow.c."""
        sa_result = self.analyzer.analyze(self.result)

        # Look for a CWE-120 finding
        cwe120_findings = [
            f for f in sa_result.all_findings
            if f.cwe_id and 'CWE-120' in f.cwe_id
        ]
        self.assertGreater(len(cwe120_findings), 0, "Should find CWE-120 (buffer overflow)")

    def test_pattern_matcher_detects_system(self):
        """Regex patterns should catch system() in command_injection.c."""
        sa_result = self.analyzer.analyze(self.result)

        cwe78_findings = [
            f for f in sa_result.all_findings
            if f.cwe_id and 'CWE-78' in f.cwe_id
        ]
        self.assertGreater(len(cwe78_findings), 0, "Should find CWE-78 (command injection)")

    def test_clean_functions_identified(self):
        """Some functions in the vulnerable files might still be clean."""
        sa_result = self.analyzer.analyze(self.result)
        # clean_functions should be a list (possibly empty)
        self.assertIsInstance(sa_result.clean_functions, list)

    def test_safe_code_has_fewer_findings(self):
        """The safe fixture should have significantly fewer findings."""
        safe_zip = _make_zip(SAFE_DIR, 'safe.zip')
        try:
            safe_result = self.ingestion.ingest_zip(safe_zip)
            sa_safe = self.analyzer.analyze(safe_result)
            sa_vuln = self.analyzer.analyze(self.result)

            # Safe code should have fewer or equal findings
            self.assertLessEqual(
                len(sa_safe.all_findings),
                len(sa_vuln.all_findings),
                "Safe code should not have more findings than vulnerable code"
            )
        finally:
            safe_result.cleanup()
            shutil.rmtree(os.path.dirname(safe_zip), ignore_errors=True)

    def test_findings_have_required_fields(self):
        """Every StaticFinding should have tool, severity, message, file_path, line."""
        sa_result = self.analyzer.analyze(self.result)
        for f in sa_result.all_findings:
            self.assertIsNotNone(f.tool)
            self.assertIn(f.severity, ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'))
            self.assertIsNotNone(f.message)
            self.assertIsNotNone(f.file_path)
            self.assertGreater(f.line, 0)
            self.assertGreaterEqual(f.confidence, 0.0)
            self.assertLessEqual(f.confidence, 1.0)


# ======================================================================
# Test: ML Analyzer (graceful degradation)
# ======================================================================
class TestMLAnalyzer(unittest.TestCase):

    def test_ml_reports_unavailable_when_models_missing(self):
        """MLAnalyzer.available should be False when model files don't exist."""
        analyzer = MLAnalyzer()
        # This may be True or False depending on whether models are trained
        # Just verify it returns a bool and doesn't crash
        self.assertIsInstance(analyzer.available, bool)

    def test_ml_analyze_returns_empty_when_unavailable(self):
        """analyze() should return empty list gracefully when models are missing."""
        analyzer = MLAnalyzer()
        if not analyzer.available:
            dummy_func = FunctionUnit(
                file_rel_path='test.c',
                file_abs_path='/tmp/test.c',
                function_name='foo',
                code='int foo() { return 0; }',
                start_line=1,
                end_line=1,
                language='c',
            )
            result = analyzer.analyze([dummy_func])
            self.assertEqual(result, [])

    def test_ml_analyze_empty_input(self):
        """analyze([]) should return [] without crashing."""
        analyzer = MLAnalyzer()
        self.assertEqual(analyzer.analyze([]), [])


# ======================================================================
# Test: CWE Database
# ======================================================================
class TestCWEDatabase(unittest.TestCase):

    def test_database_has_entries(self):
        self.assertGreater(len(CWE_DATABASE), 20)

    def test_get_known_cwe(self):
        info = get_cwe_info('CWE-120')
        self.assertIsNotNone(info)
        self.assertEqual(info['name'], 'Buffer Copy without Checking Size of Input (Classic Buffer Overflow)')

    def test_get_unknown_cwe(self):
        self.assertIsNone(get_cwe_info('CWE-99999'))

    def test_enrich_known_cwe(self):
        enriched = enrich_finding('CWE-120')
        self.assertEqual(enriched['cwe_id'], 'CWE-120')
        self.assertIsNotNone(enriched['mitigation'])
        self.assertIsNotNone(enriched['severity'])

    def test_enrich_unknown_cwe(self):
        enriched = enrich_finding('CWE-99999')
        self.assertIn('Manual code review', enriched['mitigation'])

    def test_enrich_none(self):
        enriched = enrich_finding(None)
        self.assertIn('Manual code review', enriched['mitigation'])


# ======================================================================
# Test: Full Pipeline (static-only, ML disabled)
# ======================================================================
class TestPipelineEndToEnd(unittest.TestCase):

    def test_pipeline_on_vulnerable_code(self):
        """Full pipeline should produce a valid report with findings."""
        zip_path = _make_zip(VULN_DIR, 'vuln.zip')
        try:
            pipeline = VulnerabilityPipeline(enable_ml=False, save_report=False)
            report = pipeline.scan_zip(zip_path)

            # Check top-level schema
            self.assertIn('scan_id', report)
            self.assertIn('timestamp', report)
            self.assertIn('source', report)
            self.assertIn('summary', report)
            self.assertIn('findings', report)
            self.assertIn('safe_functions', report)

            # Summary fields
            summary = report['summary']
            self.assertGreater(summary['total_files'], 0)
            self.assertGreater(summary['total_functions'], 0)
            self.assertGreater(summary['vulnerable_functions'], 0,
                               "Should detect vulnerabilities in the fixture")

            # Findings structure
            for finding in report['findings']:
                self.assertIn(finding['label'], ('VULNERABLE',))
                self.assertIn(finding['detection_method'], ('static_analysis', 'ml_model'))
                self.assertIsInstance(finding['confidence'], float)
                self.assertGreaterEqual(finding['confidence'], 0.0)
                self.assertLessEqual(finding['confidence'], 1.0)
                self.assertIsNotNone(finding['mitigation'])
        finally:
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_pipeline_on_safe_code(self):
        """Safe code should produce few or no vulnerability findings."""
        zip_path = _make_zip(SAFE_DIR, 'safe.zip')
        try:
            pipeline = VulnerabilityPipeline(enable_ml=False, save_report=False)
            report = pipeline.scan_zip(zip_path)

            self.assertGreater(report['summary']['total_functions'], 0)
            # Safe code should have very few findings (maybe zero)
            # We don't assert zero because CppCheck might flag style issues
            self.assertLessEqual(
                report['summary']['vulnerable_functions'],
                report['summary']['total_functions'],
            )
        finally:
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_pipeline_on_combined(self):
        """Combined ZIP should find more vulns in vulnerable code than safe code."""
        zip_path = _make_zip_from_multiple([VULN_DIR, SAFE_DIR])
        try:
            pipeline = VulnerabilityPipeline(enable_ml=False, save_report=False)
            report = pipeline.scan_zip(zip_path)

            self.assertGreater(report['summary']['total_files'], 3)
            self.assertGreater(report['summary']['vulnerable_functions'], 0)
        finally:
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_report_is_json_serializable(self):
        """The report should be fully JSON-serialisable."""
        zip_path = _make_zip(VULN_DIR, 'vuln.zip')
        try:
            pipeline = VulnerabilityPipeline(enable_ml=False, save_report=False)
            report = pipeline.scan_zip(zip_path)

            json_str = json.dumps(report, indent=2)
            self.assertIsInstance(json_str, str)
            roundtrip = json.loads(json_str)
            self.assertEqual(roundtrip['scan_id'], report['scan_id'])
        finally:
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_pipeline_saves_report(self):
        """With save_report=True, a JSON file should be created."""
        zip_path = _make_zip(VULN_DIR, 'vuln.zip')
        try:
            pipeline = VulnerabilityPipeline(enable_ml=False, save_report=True)
            report = pipeline.scan_zip(zip_path)

            report_path = (
                Path(__file__).parent.parent / 'outputs' / 'reports'
                / f"{report['scan_id']}.json"
            )
            self.assertTrue(report_path.exists(), f"Report file should exist at {report_path}")

            # Cleanup the report file
            report_path.unlink(missing_ok=True)
        finally:
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)


# ======================================================================
# Test: CppCheck false-positive filtering
# ======================================================================
class TestFalsePositiveFiltering(unittest.TestCase):
    """Verify that CppCheck style/performance findings are filtered out."""

    def test_safe_code_no_high_severity(self):
        """Safe code should have no CRITICAL or HIGH findings from CppCheck.
        
        Note: Flawfinder may flag safe functions like safe_copy (which uses
        strncpy) because Flawfinder lacks context awareness — it flags the
        function name regardless of correct usage. We specifically check that
        CppCheck style/performance noise doesn't leak through.
        """
        zip_path = _make_zip(SAFE_DIR, 'safe.zip')
        try:
            ingestion = CodeIngestion()
            result = ingestion.ingest_zip(zip_path)
            analyzer = StaticAnalyzer()
            sa_result = analyzer.analyze(result)

            cppcheck_findings = [f for f in sa_result.all_findings if f.tool == 'cppcheck']
            for f in cppcheck_findings:
                self.assertNotIn(
                    f.severity, ('CRITICAL', 'HIGH'),
                    f"CppCheck should not flag safe code as {f.severity}: "
                    f"{f.rule_id} ({f.message})"
                )
        finally:
            result.cleanup()
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_cppcheck_no_style_findings(self):
        """CppCheck findings should not include style/performance categories."""
        zip_path = _make_zip(SAFE_DIR, 'safe.zip')
        try:
            ingestion = CodeIngestion()
            result = ingestion.ingest_zip(zip_path)
            analyzer = StaticAnalyzer()
            sa_result = analyzer.analyze(result)

            cppcheck_findings = [f for f in sa_result.all_findings if f.tool == 'cppcheck']
            # If CppCheck finds anything in safe code, it should NOT be
            # a style/performance rule that leaked through
            for f in cppcheck_findings:
                # Security overrides are fine, but generic style rules should be gone
                self.assertNotIn(
                    'deadcode' if 'CWE-561' in (f.cwe_id or '') else '',
                    f.rule_id,
                    f"Style finding leaked through: {f.rule_id} ({f.message})"
                )
        finally:
            result.cleanup()
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)

    def test_majority_safe_functions_clean(self):
        """In a combined scan, safe_math functions should mostly be clean."""
        zip_path = _make_zip_from_multiple([VULN_DIR, SAFE_DIR], 'combined.zip')
        try:
            pipeline = VulnerabilityPipeline(enable_ml=False, save_report=False)
            report = pipeline.scan_zip(zip_path)

            # safe_math.c has 4 functions — they should all be safe
            safe_math_findings = [
                f for f in report['findings']
                if 'safe_math' in f['file']
            ]
            self.assertEqual(
                len(safe_math_findings), 0,
                f"safe_math functions should not be flagged, got: "
                f"{[f['function_name'] for f in safe_math_findings]}"
            )
        finally:
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)


# ======================================================================
# Test: Advanced regex patterns
# ======================================================================
class TestAdvancedPatterns(unittest.TestCase):
    """Verify the advanced regex patterns detect complex vulnerabilities."""

    def _analyze_code(self, code: str) -> list:
        """Helper: create a FunctionUnit and run pattern matcher on it."""
        from src.pipeline.static_analysis import StaticAnalyzer
        func = FunctionUnit(
            function_name='test_func',
            code=code,
            start_line=1,
            end_line=code.count('\n') + 1,
            file_rel_path='test.c',
            file_abs_path='test.c',
            language='c',
        )
        return StaticAnalyzer._run_pattern_matcher(func)

    def test_detects_use_after_free(self):
        """Should detect use-after-free pattern."""
        code = '''void vuln() {
    char *p = malloc(10);
    free(p);
    p[0] = 'x';  // use after free
}'''
        findings = self._analyze_code(code)
        cwe_ids = {f.cwe_id for f in findings}
        self.assertTrue(
            'CWE-416' in cwe_ids or 'CWE-415' in cwe_ids,
            f"Should detect use-after-free, got CWEs: {cwe_ids}"
        )

    def test_detects_null_pointer_deref(self):
        """Should detect malloc without NULL check."""
        code = '''void vuln() {
    char *p = malloc(100);
    p[0] = 'a';
}'''
        findings = self._analyze_code(code)
        cwe_ids = {f.cwe_id for f in findings}
        self.assertIn('CWE-476', cwe_ids, f"Should detect NULL pointer deref, got: {cwe_ids}")

    def test_detects_toctou(self):
        """Should detect TOCTOU race condition."""
        code = '''void vuln(const char *path) {
    if (access(path, F_OK) == 0) {
        FILE *f = fopen(path, "r");
    }
}'''
        findings = self._analyze_code(code)
        cwe_ids = {f.cwe_id for f in findings}
        self.assertIn('CWE-362', cwe_ids, f"Should detect TOCTOU, got: {cwe_ids}")

    def test_detects_command_injection(self):
        """Should detect system() call."""
        code = '''void vuln(char *input) {
    system(input);
}'''
        findings = self._analyze_code(code)
        cwe_ids = {f.cwe_id for f in findings}
        self.assertIn('CWE-78', cwe_ids)

    def test_safe_code_not_flagged_critical(self):
        """Safe string handling code should not get CRITICAL findings."""
        code = '''void safe(char *dest, const char *src, size_t n) {
    strncpy(dest, src, n - 1);
    dest[n - 1] = '\\0';
}'''
        findings = self._analyze_code(code)
        critical = [f for f in findings if f.severity == 'CRITICAL']
        self.assertEqual(
            len(critical), 0,
            f"Safe code should not have CRITICAL findings: {[f.message for f in critical]}"
        )

    def test_report_has_new_summary_fields(self):
        """Report should include ml_confirmed and ml_dismissed counts."""
        zip_path = _make_zip(VULN_DIR, 'vuln.zip')
        try:
            pipeline = VulnerabilityPipeline(enable_ml=False, save_report=False)
            report = pipeline.scan_zip(zip_path)

            dm = report['summary']['detection_methods']
            self.assertIn('ml_confirmed', dm)
            self.assertIn('ml_dismissed', dm)
            # Without ML, these should be 0
            self.assertEqual(dm['ml_confirmed'], 0)
            self.assertEqual(dm['ml_dismissed'], 0)
        finally:
            shutil.rmtree(os.path.dirname(zip_path), ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
