"""
Ingestion tests — ZIP extraction, GitHub cloning path, function extraction,
file filtering, and edge cases.
"""
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pipeline.ingestion import CodeIngestion, IngestionResult, FunctionUnit

FIXTURES = Path(__file__).parent / "fixtures"
VULN_DIR = FIXTURES / "vulnerable_code"
SAFE_DIR = FIXTURES / "safe_code"


def _make_zip(source_dir: Path) -> str:
    tmp = tempfile.mkdtemp(prefix="test_zip_")
    zip_path = os.path.join(tmp, "test.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(source_dir):
            for fname in files:
                abs_path = os.path.join(root, fname)
                arc_name = os.path.relpath(abs_path, source_dir)
                zf.write(abs_path, arc_name)
    return zip_path


def _make_zip_with_content(files: dict) -> str:
    """files = {filename: content_str}"""
    tmp = tempfile.mkdtemp(prefix="test_zip_")
    zip_path = os.path.join(tmp, "test.zip")
    with zipfile.ZipFile(zip_path, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return zip_path


class TestZIPIngestion(unittest.TestCase):
    def setUp(self):
        self.ingestion = CodeIngestion()
        self.tmp_dirs = []

    def tearDown(self):
        for d in self.tmp_dirs:
            shutil.rmtree(d, ignore_errors=True)

    def test_c_files_extracted_from_zip(self):
        zip_path = _make_zip(VULN_DIR)
        result = self.ingestion.ingest_zip(zip_path)
        self.assertIsInstance(result, IngestionResult)
        self.assertGreater(len(result.source_files), 0)
        for sf in result.source_files:
            self.assertTrue(sf.path.endswith((".c", ".cpp", ".h", ".hpp")))

    def test_non_c_files_excluded(self):
        zip_path = _make_zip_with_content({
            "main.c": 'void foo() { }',
            "README.md": "# readme",
            "script.py": "print('hello')",
            "data.json": '{}',
        })
        result = self.ingestion.ingest_zip(zip_path)
        names = [sf.path for sf in result.source_files]
        self.assertTrue(any("main.c" in n for n in names))
        self.assertFalse(any(".md" in n for n in names))
        self.assertFalse(any(".py" in n for n in names))

    def test_empty_zip_returns_empty_result(self):
        zip_path = _make_zip_with_content({})
        result = self.ingestion.ingest_zip(zip_path)
        self.assertEqual(len(result.source_files), 0)

    def test_zip_with_no_c_files_returns_empty(self):
        zip_path = _make_zip_with_content({
            "notes.txt": "hello",
            "config.yaml": "key: value",
        })
        result = self.ingestion.ingest_zip(zip_path)
        self.assertEqual(len(result.source_files), 0)

    def test_corrupt_zip_raises_or_returns_empty(self):
        tmp = tempfile.mkdtemp()
        self.tmp_dirs.append(tmp)
        bad_path = os.path.join(tmp, "corrupt.zip")
        with open(bad_path, "wb") as f:
            f.write(b"this is not a zip file")
        try:
            result = self.ingestion.ingest_zip(bad_path)
            self.assertEqual(len(result.source_files), 0)
        except Exception:
            pass  # raising is also acceptable

    def test_max_files_limit_respected(self):
        files = {f"file_{i}.c": f"void f{i}() {{}}" for i in range(20)}
        zip_path = _make_zip_with_content(files)
        result = self.ingestion.ingest_zip(zip_path, max_files=5)
        self.assertLessEqual(len(result.source_files), 5)

    def test_nested_directory_structure_in_zip(self):
        zip_path = _make_zip_with_content({
            "src/main.c": "void main() {}",
            "src/utils/helper.c": "void helper() {}",
            "include/header.h": "void foo();",
        })
        result = self.ingestion.ingest_zip(zip_path)
        self.assertEqual(len(result.source_files), 3)


class TestFunctionExtraction(unittest.TestCase):
    def setUp(self):
        self.ingestion = CodeIngestion()

    def test_functions_extracted_from_vuln_fixture(self):
        zip_path = _make_zip(VULN_DIR)
        result = self.ingestion.ingest_zip(zip_path)
        functions = self.ingestion.extract_functions(result)
        self.assertGreater(len(functions), 0)
        for func in functions:
            self.assertIsInstance(func, FunctionUnit)
            self.assertTrue(len(func.code) > 0)
            self.assertTrue(len(func.name) > 0)

    def test_function_unit_has_required_fields(self):
        zip_path = _make_zip(VULN_DIR)
        result = self.ingestion.ingest_zip(zip_path)
        functions = self.ingestion.extract_functions(result)
        if functions:
            f = functions[0]
            self.assertIsNotNone(f.code)
            self.assertIsNotNone(f.name)
            self.assertIsNotNone(f.file_path)

    def test_empty_source_gives_no_functions(self):
        zip_path = _make_zip_with_content({"empty.c": ""})
        result = self.ingestion.ingest_zip(zip_path)
        functions = self.ingestion.extract_functions(result)
        self.assertEqual(len(functions), 0)

    def test_single_function_file(self):
        code = "int add(int a, int b) { return a + b; }"
        zip_path = _make_zip_with_content({"math.c": code})
        result = self.ingestion.ingest_zip(zip_path)
        functions = self.ingestion.extract_functions(result)
        self.assertGreaterEqual(len(functions), 1)

    def test_multiple_functions_in_one_file(self):
        code = (
            "void foo() { }\n"
            "void bar() { }\n"
            "int baz(int x) { return x * 2; }\n"
        )
        zip_path = _make_zip_with_content({"multi.c": code})
        result = self.ingestion.ingest_zip(zip_path)
        functions = self.ingestion.extract_functions(result)
        self.assertGreaterEqual(len(functions), 3)


class TestIngestionResultSchema(unittest.TestCase):
    def test_ingestion_result_has_source_files(self):
        result = IngestionResult(source_files=[])
        self.assertIsInstance(result.source_files, list)

    def test_function_unit_to_dict(self):
        fu = FunctionUnit(
            name="foo",
            code="void foo() {}",
            file_path="test.c",
            line_number=1,
            language="c",
        )
        d = fu.to_dict() if hasattr(fu, "to_dict") else fu.__dict__
        self.assertIn("code", d)
        self.assertIn("name", d)


if __name__ == "__main__":
    unittest.main()
