"""
CodeParser tests — language detection, function extraction, multi-language.
"""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.parser.code_parser import CodeParser

FIXTURES = Path(__file__).parent / "fixtures"


class TestLanguageDetection(unittest.TestCase):
    def setUp(self):
        self.parser = CodeParser()

    def test_c_extension(self):
        self.assertEqual(self.parser.detect_language("main.c"), "c")

    def test_cpp_extensions(self):
        for ext in ["file.cpp", "file.cc", "file.cxx"]:
            self.assertEqual(self.parser.detect_language(ext), "cpp", ext)

    def test_header_extension(self):
        self.assertIn(self.parser.detect_language("header.h"), ["c", "cpp"])

    def test_hpp_extension(self):
        self.assertEqual(self.parser.detect_language("header.hpp"), "cpp")

    def test_python_extension(self):
        self.assertEqual(self.parser.detect_language("script.py"), "python")

    def test_unknown_extension_returns_none(self):
        self.assertIsNone(self.parser.detect_language("file.xyz"))

    def test_no_extension_returns_none(self):
        self.assertIsNone(self.parser.detect_language("Makefile"))

    def test_case_insensitive(self):
        self.assertEqual(self.parser.detect_language("MAIN.C"), "c")


class TestCFunctionParsing(unittest.TestCase):
    def setUp(self):
        self.parser = CodeParser()

    def test_single_function_extracted(self):
        code = "int add(int a, int b) { return a + b; }"
        result = self.parser.parse_code(code, language="c")
        self.assertGreaterEqual(len(result["functions"]), 1)

    def test_multiple_functions_extracted(self):
        code = (
            "void foo() { }\n"
            "int bar(int x) { return x; }\n"
            "char *baz(char *s) { return s; }\n"
        )
        result = self.parser.parse_code(code, language="c")
        self.assertGreaterEqual(len(result["functions"]), 3)

    def test_function_has_name_and_body(self):
        code = "void my_func() { int x = 1; }"
        result = self.parser.parse_code(code, language="c")
        if result["functions"]:
            f = result["functions"][0]
            self.assertIn("name", f)
            self.assertIn("body", f)
            self.assertGreater(len(f["body"]), 0)

    def test_empty_source_returns_empty_functions(self):
        result = self.parser.parse_code("", language="c")
        self.assertEqual(len(result["functions"]), 0)

    def test_no_functions_source(self):
        code = "#include <stdio.h>\nint x = 5;\nfloat PI = 3.14;"
        result = self.parser.parse_code(code, language="c")
        self.assertEqual(len(result["functions"]), 0)

    def test_nested_braces_handled(self):
        code = """
        int nested(int x) {
            if (x > 0) {
                for (int i = 0; i < x; i++) {
                    x--;
                }
            }
            return x;
        }
        """
        result = self.parser.parse_code(code, language="c")
        self.assertGreaterEqual(len(result["functions"]), 1)

    def test_function_with_pointer_params(self):
        code = "void process(char *buf, size_t len) { buf[0] = '\\0'; }"
        result = self.parser.parse_code(code, language="c")
        self.assertGreaterEqual(len(result["functions"]), 1)


class TestFixtureParsing(unittest.TestCase):
    def setUp(self):
        self.parser = CodeParser()

    def test_parse_buffer_overflow_fixture(self):
        path = FIXTURES / "vulnerable_code" / "buffer_overflow.c"
        result = self.parser.parse_file(str(path))
        self.assertGreater(len(result["functions"]), 0)

    def test_parse_safe_string_fixture(self):
        path = FIXTURES / "safe_code" / "safe_string.c"
        result = self.parser.parse_file(str(path))
        self.assertGreater(len(result["functions"]), 0)

    def test_parse_nonexistent_file_raises(self):
        with self.assertRaises(Exception):
            self.parser.parse_file("/nonexistent/path/file.c")


class TestMultiLanguageParsing(unittest.TestCase):
    def setUp(self):
        self.parser = CodeParser()

    def test_cpp_class_method(self):
        code = """
        class Foo {
        public:
            int bar(int x) { return x * 2; }
        };
        """
        result = self.parser.parse_code(code, language="cpp")
        self.assertIsNotNone(result)

    def test_python_function(self):
        if "python" not in self.parser.parsers:
            self.skipTest("python parser not loaded")
        code = "def hello(name):\n    return 'Hello ' + name\n"
        result = self.parser.parse_code(code, language="python")
        self.assertIsNotNone(result)


if __name__ == "__main__":
    unittest.main()
