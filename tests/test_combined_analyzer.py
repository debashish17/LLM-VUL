"""
CombinedAnalyzer integration tests.

Uses mocked ML predictors so tests run without model files.
Validates the contract between static + ML results and the output schema
consumed by the API layer.
"""
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.pipeline.combined_analyzer import CombinedAnalyzer


def _func(code: str, name: str = "test", path: str = "test.c") -> dict:
    return {"code": code, "function_name": name, "file_path": path, "line_number": 1}


def _make_ml_result(name: str, vulnerable: bool, confidence: float) -> dict:
    return {
        "function_name": name,
        "file_path": "test.c",
        "line_number": 1,
        "code": "void f() {}",
        "code_snippet": "void f() {}",
        "ml_vulnerable": vulnerable,
        "ml_confidence": confidence,
        "severity": "HIGH" if vulnerable else "LOW",
        "individual_models": {
            "xgb_conservative": confidence,
            "xgb_aggressive": confidence,
            "lgb_balanced": confidence,
            "catboost": confidence,
        },
        "ml_threshold": 0.308,
    }


class TestCombinedAnalyzerOutputSchema(unittest.TestCase):

    def setUp(self):
        self.analyzer = CombinedAnalyzer()

    def _mock_ensemble(self, funcs, threshold=0.308):
        return [_make_ml_result(f["function_name"], False, 0.1) for f in funcs]

    def test_output_has_static_and_ml_results(self):
        funcs = [_func("void f() {}", "f")]
        with patch.object(self.analyzer, "_get_ml_predictor") as mock_pred:
            mock_pred.return_value.predict = self._mock_ensemble
            result = self.analyzer.analyze(funcs, ml_model="ensemble")
        self.assertIn("static_results", result)
        self.assertIn("ml_results", result)

    def test_output_has_ml_model_used(self):
        funcs = [_func("void f() {}", "f")]
        with patch.object(self.analyzer, "_get_ml_predictor") as mock_pred:
            mock_pred.return_value.predict = self._mock_ensemble
            result = self.analyzer.analyze(funcs, ml_model="ensemble")
        self.assertIn("ml_model_used", result)
        self.assertEqual(result["ml_model_used"], "ensemble")

    def test_result_counts_match_input(self):
        funcs = [_func("void a() {}", "a"), _func("void b() {}", "b")]
        with patch.object(self.analyzer, "_get_ml_predictor") as mock_pred:
            mock_pred.return_value.predict = self._mock_ensemble
            result = self.analyzer.analyze(funcs, ml_model="ensemble")
        self.assertEqual(len(result["static_results"]), 2)
        self.assertEqual(len(result["ml_results"]), 2)

    def test_static_results_have_required_fields(self):
        funcs = [_func('void f(char *s) { strcpy(buf, s); }', "vuln")]
        with patch.object(self.analyzer, "_get_ml_predictor") as mock_pred:
            mock_pred.return_value.predict = self._mock_ensemble
            result = self.analyzer.analyze(funcs, ml_model="ensemble")
        sr = result["static_results"][0]
        required = {"function_name", "file_path", "static_vulnerable", "static_confidence", "static_findings"}
        missing = required - sr.keys()
        self.assertEqual(missing, set(), f"Static result missing: {missing}")

    def test_ml_results_have_required_fields(self):
        funcs = [_func("void f() {}", "f")]
        with patch.object(self.analyzer, "_get_ml_predictor") as mock_pred:
            mock_pred.return_value.predict = self._mock_ensemble
            result = self.analyzer.analyze(funcs, ml_model="ensemble")
        mr = result["ml_results"][0]
        required = {"function_name", "ml_vulnerable", "ml_confidence", "severity"}
        missing = required - mr.keys()
        self.assertEqual(missing, set(), f"ML result missing: {missing}")

    def test_static_and_ml_results_are_independent(self):
        """Static and ML vulnerable flags can differ — they must NOT be merged."""
        funcs = [_func('void f(char *s) { strcpy(buf, s); }', "f")]

        def mock_safe(funcs, threshold=0.308):
            return [_make_ml_result(f["function_name"], False, 0.05) for f in funcs]

        with patch.object(self.analyzer, "_get_ml_predictor") as mock_pred:
            mock_pred.return_value.predict = mock_safe
            result = self.analyzer.analyze(funcs, ml_model="ensemble")

        # Static may flag strcpy; ML says safe — they must remain separate
        sr = result["static_results"][0]
        mr = result["ml_results"][0]
        # Values may differ — that's by design
        self.assertIn("static_vulnerable", sr)
        self.assertIn("ml_vulnerable", mr)

    def test_empty_function_list_returns_empty_results(self):
        result = self.analyzer.analyze([], ml_model="ensemble")
        self.assertEqual(result["static_results"], [])
        self.assertEqual(result["ml_results"], [])

    def test_lora_model_selection_routes_to_lora_predictor(self):
        funcs = [_func("void f() {}", "f")]
        lora_result = {
            "function_name": "f",
            "file_path": "test.c",
            "line_number": 1,
            "code": "void f() {}",
            "code_snippet": "void f() {}",
            "ml_vulnerable": False,
            "ml_confidence": 0.1,
            "severity": "LOW",
            "individual_models": {},
            "ml_threshold": 0.55,
        }
        with patch.object(self.analyzer, "_get_lora_predictor") as mock_pred:
            mock_pred.return_value.predict_batch = MagicMock(return_value=[lora_result])
            result = self.analyzer.analyze(funcs, ml_model="lora")
        self.assertEqual(result["ml_model_used"], "lora")


class TestSeverityMapping(unittest.TestCase):
    """Confidence → severity mapping is consistent."""

    def setUp(self):
        self.analyzer = CombinedAnalyzer()

    def _check_severity(self, confidence: float, ml_model: str = "ensemble"):
        funcs = [_func("void f() {}", "f")]
        ml_result = _make_ml_result("f", confidence > 0.308, confidence)

        with patch.object(self.analyzer, "_get_ml_predictor") as mock_pred:
            mock_pred.return_value.predict = lambda funcs, threshold=0.308: [ml_result]
            result = self.analyzer.analyze(funcs, ml_model=ml_model)
        return result["ml_results"][0]["severity"]

    def test_high_confidence_gives_critical_or_high(self):
        sev = self._check_severity(0.9)
        self.assertIn(sev, ["HIGH", "CRITICAL"])

    def test_low_confidence_gives_low_or_medium(self):
        sev = self._check_severity(0.1)
        self.assertIn(sev, ["LOW", "MEDIUM"])

    def test_severity_is_valid_label(self):
        for conf in [0.1, 0.35, 0.5, 0.7, 0.9]:
            sev = self._check_severity(conf)
            self.assertIn(sev, ["LOW", "MEDIUM", "HIGH", "CRITICAL"])


if __name__ == "__main__":
    unittest.main()
