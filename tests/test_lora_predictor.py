"""
LoRA predictor tests.

When adapter weights are present: runs full inference and validates output.
When absent: validates graceful error handling.
GPU is not required — model loads in CPU mode if no CUDA.
"""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

ADAPTER_DIR = Path(__file__).parent.parent / "models" / "lora_adapter"
ADAPTER_AVAILABLE = (ADAPTER_DIR / "adapter_config.json").exists()

VULN_CODE = """
void bad_copy(char *src) {
    char dest[16];
    strcpy(dest, src);
}
"""

SAFE_CODE = """
int clamp(int value, int min_val, int max_val) {
    if (value < min_val) return min_val;
    if (value > max_val) return max_val;
    return value;
}
"""

LONG_CODE = ("void long_func() {\n" + "    int x = 0;\n" * 300 + "}\n")


class TestLoRAPredictorInterface(unittest.TestCase):

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def setUp(self):
        from src.pipeline.lora_predictor import LoRAPredictor
        self.predictor = LoRAPredictor()

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_single_prediction_returns_dict(self):
        result = self.predictor.predict(VULN_CODE)
        self.assertIsInstance(result, dict)

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_output_has_required_keys(self):
        result = self.predictor.predict(VULN_CODE)
        required = {"is_vulnerable", "confidence", "model"}
        missing = required - result.keys()
        self.assertEqual(missing, set(), f"Missing keys: {missing}")

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_confidence_in_range(self):
        result = self.predictor.predict(VULN_CODE)
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_is_vulnerable_is_boolean(self):
        result = self.predictor.predict(VULN_CODE)
        self.assertIsInstance(result["is_vulnerable"], bool)

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_model_field_identifies_lora(self):
        result = self.predictor.predict(VULN_CODE)
        self.assertIn("lora", result["model"].lower())

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_long_function_sliding_window(self):
        """Functions > 512 tokens should be processed via sliding window."""
        result = self.predictor.predict(LONG_CODE)
        self.assertIn("is_vulnerable", result)
        self.assertIn("confidence", result)

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_empty_code_returns_result(self):
        result = self.predictor.predict("")
        self.assertIn("is_vulnerable", result)

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_threshold_loaded_from_file(self):
        """Adapter directory must contain threshold.json."""
        import json
        threshold_path = ADAPTER_DIR / "threshold.json"
        self.assertTrue(threshold_path.exists(), "threshold.json missing from lora_adapter/")
        data = json.loads(threshold_path.read_text())
        self.assertIn("threshold", data)
        t = data["threshold"]
        self.assertGreater(t, 0.0)
        self.assertLess(t, 1.0)

    @unittest.skipUnless(ADAPTER_AVAILABLE, "models/lora_adapter not present")
    def test_custom_threshold_overrides_default(self):
        result_low = self.predictor.predict(VULN_CODE, threshold=0.01)
        result_high = self.predictor.predict(VULN_CODE, threshold=0.99)
        # Low threshold → more likely vulnerable; high → less likely
        self.assertTrue(result_low["is_vulnerable"] or not result_high["is_vulnerable"])


class TestLoRAPreprocessing(unittest.TestCase):
    """Comment stripping and whitespace normalisation — no model needed."""

    def setUp(self):
        from src.pipeline.lora_predictor import _strip_comments, _normalise_whitespace
        self._strip = _strip_comments
        self._norm = _normalise_whitespace

    def test_single_line_comment_stripped(self):
        code = "int x = 1; // this is a comment\nint y = 2;"
        result = self._strip(code)
        self.assertNotIn("this is a comment", result)
        self.assertIn("int x = 1;", result)

    def test_block_comment_stripped(self):
        code = "/* block comment */\nvoid foo() {}"
        result = self._strip(code)
        self.assertNotIn("block comment", result)
        self.assertIn("void foo()", result)

    def test_string_literal_preserved(self):
        code = 'char *s = "// not a comment";'
        result = self._strip(code)
        self.assertIn("not a comment", result)

    def test_whitespace_normalised(self):
        code = "void   foo(  )  {   }"
        result = self._norm(code)
        self.assertNotIn("  ", result)

    def test_empty_string_handled(self):
        self.assertEqual(self._strip(""), "")
        self.assertEqual(self._norm(""), "")


class TestLoRAMissingAdapter(unittest.TestCase):
    @unittest.skipIf(ADAPTER_AVAILABLE, "adapter present — skipping missing test")
    def test_missing_adapter_raises_on_init(self):
        from src.pipeline.lora_predictor import LoRAPredictor
        with self.assertRaises(Exception):
            LoRAPredictor()


if __name__ == "__main__":
    unittest.main()
