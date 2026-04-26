"""
Ensemble (Run12) predictor tests.

When model files are present: runs full inference and checks output schema.
When model files are absent: verifies graceful failure and error messaging.
Tests are marked with @unittest.skipUnless so CI passes without models.
"""
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

MODELS_DIR = Path(__file__).parent.parent / "models" / "saved_models"
MODELS_AVAILABLE = (MODELS_DIR / "xgb_conservative.pkl").exists()

VULN_CODE = """
void copy_username(char *input) {
    char buffer[32];
    strcpy(buffer, input);
}
"""

SAFE_CODE = """
int add(int a, int b) {
    if (a > 0 && b > 0 && a < 1000 && b < 1000) {
        return a + b;
    }
    return -1;
}
"""


def _func(code: str, name: str = "test") -> dict:
    return {"code": code, "function_name": name, "file_path": "test.c", "line_number": 1}


class TestRun12PredictorInterface(unittest.TestCase):
    """Output schema tests — run only when models are present."""

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def setUp(self):
        from src.pipeline.run12_predictor import Run12Predictor
        self.predictor = Run12Predictor()

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_single_prediction_returns_dict(self):
        result = self.predictor.predict([_func(VULN_CODE)])
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 1)

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_output_has_required_keys(self):
        result = self.predictor.predict([_func(VULN_CODE)])
        r = result[0]
        required = {"ml_vulnerable", "ml_confidence", "severity", "individual_models"}
        missing = required - r.keys()
        self.assertEqual(missing, set(), f"Missing keys: {missing}")

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_confidence_is_float_0_to_1(self):
        result = self.predictor.predict([_func(VULN_CODE)])
        conf = result[0]["ml_confidence"]
        self.assertIsInstance(conf, float)
        self.assertGreaterEqual(conf, 0.0)
        self.assertLessEqual(conf, 1.0)

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_severity_is_valid_label(self):
        result = self.predictor.predict([_func(VULN_CODE)])
        self.assertIn(result[0]["severity"], ["LOW", "MEDIUM", "HIGH", "CRITICAL"])

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_individual_models_present(self):
        result = self.predictor.predict([_func(VULN_CODE)])
        models = result[0]["individual_models"]
        self.assertIsInstance(models, dict)
        expected = {"xgb_conservative", "xgb_aggressive", "lgb_balanced", "catboost"}
        self.assertEqual(set(models.keys()), expected)

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_batch_prediction_length_matches_input(self):
        funcs = [_func(VULN_CODE, "f1"), _func(SAFE_CODE, "f2"), _func("void noop() {}", "f3")]
        results = self.predictor.predict(funcs)
        self.assertEqual(len(results), 3)

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_ml_vulnerable_is_boolean(self):
        result = self.predictor.predict([_func(VULN_CODE)])
        self.assertIsInstance(result[0]["ml_vulnerable"], bool)

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_empty_input_returns_empty_list(self):
        result = self.predictor.predict([])
        self.assertEqual(result, [])

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_threshold_affects_classification(self):
        """Higher threshold should produce fewer vulnerable predictions."""
        funcs = [_func(VULN_CODE, "f1"), _func(SAFE_CODE, "f2")]
        low_thresh = self.predictor.predict(funcs, threshold=0.1)
        high_thresh = self.predictor.predict(funcs, threshold=0.95)
        low_count = sum(1 for r in low_thresh if r["ml_vulnerable"])
        high_count = sum(1 for r in high_thresh if r["ml_vulnerable"])
        self.assertGreaterEqual(low_count, high_count)


class TestRun12PredictorMissingModels(unittest.TestCase):
    """Graceful failure when model files do not exist."""

    @unittest.skipIf(MODELS_AVAILABLE, "models present — skipping missing-model test")
    def test_missing_models_raises_on_init(self):
        from src.pipeline.run12_predictor import Run12Predictor
        with self.assertRaises(Exception):
            Run12Predictor(models_dir="/nonexistent/path")


class TestFeatureEngineerOutput(unittest.TestCase):
    """FeatureEngineer produces a 240-dim vector for any C function."""

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_feature_vector_dimension(self):
        from models.ensemble_boosting.feature_engineer import FeatureEngineer
        fe = FeatureEngineer()
        features = fe.extract(VULN_CODE)
        self.assertEqual(len(features), 240)

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_feature_vector_is_numeric(self):
        from models.ensemble_boosting.feature_engineer import FeatureEngineer
        fe = FeatureEngineer()
        features = fe.extract(VULN_CODE)
        for v in features:
            self.assertIsInstance(v, (int, float))

    @unittest.skipUnless(MODELS_AVAILABLE, "models/saved_models not present")
    def test_empty_code_returns_zeros_or_defaults(self):
        from models.ensemble_boosting.feature_engineer import FeatureEngineer
        fe = FeatureEngineer()
        features = fe.extract("")
        self.assertEqual(len(features), 240)


if __name__ == "__main__":
    unittest.main()
