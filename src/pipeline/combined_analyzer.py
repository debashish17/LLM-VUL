"""
Combined Static + ML Analyzer
Runs both static analysis and ML detection on all functions,
then merges results for comprehensive vulnerability detection.
"""

import time
import logging
import numpy as np
from typing import List, Dict, Any
from src.pipeline.static_analysis import StaticAnalyzer

logger = logging.getLogger(__name__)

class CombinedAnalyzer:
    """
    Hybrid vulnerability detection combining:
    1. Static Analysis (CppCheck, Flawfinder, Semgrep) — always runs
    2. ML Analysis — either Run12 Ensemble OR LoRA CodeBERT (user choice)
    """

    def __init__(self):
        """Initialize static analyzer only. Both ML models are lazy-loaded on first use."""
        logger.info("Initializing Combined Analyzer...")
        self.static_analyzer = StaticAnalyzer()
        self._ml_predictor = None   # lazy loaded when ml_model="ensemble"
        self._lora_predictor = None  # lazy loaded when ml_model="lora"
        logger.info("✓ Combined Analyzer ready (Static ready; ML models lazy-loaded on demand)")

    def _get_ml_predictor(self):
        """Lazy-load Run12 ensemble predictor on first use."""
        if self._ml_predictor is None:
            from src.pipeline.run12_predictor import Run12Predictor
            logger.info("Loading Run12 Ensemble models...")
            self._ml_predictor = Run12Predictor()
            logger.info("✓ Run12 Ensemble loaded")
        return self._ml_predictor

    def _get_lora_predictor(self):
        """Lazy-load LoRA predictor on first use."""
        if self._lora_predictor is None:
            from src.pipeline.lora_predictor import LoRAPredictor
            logger.info("Loading LoRA CodeBERT adapter...")
            self._lora_predictor = LoRAPredictor()
            logger.info("✓ LoRA predictor loaded")
        return self._lora_predictor
    
    def analyze(
        self,
        functions: List[Dict[str, Any]],
        ml_threshold: float = 0.308,
        ml_model: str = "ensemble",
        lora_threshold: float = 0.55,
    ) -> Dict[str, Any]:
        """
        Analyze functions using static analysis + the chosen ML model.

        Args:
            functions:      List of function dicts with 'code', 'function_name', etc.
            ml_threshold:   Classification threshold for Run12 ensemble model.
            ml_model:       'ensemble' (Run12) or 'lora' (CodeBERT QLoRA adapter).
            lora_threshold: Classification threshold for LoRA model.

        Returns:
            Dict with 'static_results', 'ml_results', and 'ml_model_used'.
        """
        logger.info(f"\n{'='*70}")
        logger.info(f"ANALYZING {len(functions)} FUNCTIONS")
        logger.info(f"{'='*70}")

        # ====================================================================
        # PHASE 1: STATIC ANALYSIS
        # ====================================================================
        t0 = time.time()
        logger.info("\n[PHASE 1] Running Static Analysis (CppCheck + Flawfinder + Semgrep)...")

        static_findings_batch = self.static_analyzer.analyze_batch(functions)

        static_results = []
        for i, (func, static_finding) in enumerate(zip(functions, static_findings_batch), 1):
            if i % 10 == 0:
                logger.info(f"  Static analysis processed: {i}/{len(functions)}")

            # Aggregate CWE types from all findings for this function
            cwe_types = []
            for finding in static_finding.get('findings', []):
                if finding.get('cwe_id'):
                    entry = f"{finding['cwe_id']}: {finding.get('cwe_name', '')}"
                    if entry not in cwe_types:
                        cwe_types.append(entry)

            static_results.append({
                'function_name': func['function_name'],
                'file_path': func['file_path'],
                'line_number': func.get('line_number', 'Unknown'),
                'code': func['code'],
                'code_snippet': func['code'][:500] + '...' if len(func['code']) > 500 else func['code'],
                'static_vulnerable': static_finding['is_vulnerable'],
                'static_confidence': static_finding['confidence'],
                'static_findings': [
                    {
                        'tool': f.get('tool', 'unknown'),
                        'message': f.get('message', ''),
                        'severity': f.get('severity', 'LOW'),
                        'cwe_id': f.get('cwe_id', 'N/A'),
                        'cwe_name': f.get('cwe_name', ''),
                    }
                    for f in static_finding.get('findings', [])
                ],
                'cwe_types': cwe_types,
            })

        t1 = time.time()
        logger.info(f"✓ Static analysis complete in {t1 - t0:.2f} seconds")
        static_vulnerable = sum(1 for r in static_results if r['static_vulnerable'])
        logger.info(f"  Static findings: {static_vulnerable}/{len(functions)} vulnerable")

        # ====================================================================
        # PHASE 2: ML ANALYSIS (Ensemble OR LoRA — user choice)
        # ====================================================================
        t2 = time.time()

        if ml_model == "lora":
            logger.info("\n[PHASE 2] Running ML Analysis (LoRA CodeBERT)...")
            lora = self._get_lora_predictor()
            ml_results = []
            for func in functions:
                pred = lora.predict(func['code'])
                conf = pred['confidence']
                if conf >= 0.85:
                    severity = 'CRITICAL'
                elif conf >= 0.65:
                    severity = 'HIGH'
                elif conf >= 0.45:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                ml_results.append({
                    'function_name': func['function_name'],
                    'file_path': func['file_path'],
                    'line_number': func.get('line_number', 'Unknown'),
                    'code': func['code'],
                    'code_snippet': func['code'][:500] + '...' if len(func['code']) > 500 else func['code'],
                    'ml_vulnerable': pred['is_vulnerable'],
                    'ml_confidence': conf,
                    'severity': severity if pred['is_vulnerable'] else 'N/A',
                    'individual_models': {"LoRA CodeBERT": conf},
                    'ml_threshold': lora_threshold,
                    'ml_model': 'lora',
                })
        else:
            logger.info("\n[PHASE 2] Running ML Analysis (Run12 Ensemble)...")
            codes = [func['code'] for func in functions]
            ml_predictions = self._get_ml_predictor().predict(codes, threshold=ml_threshold)
            ml_results = []
            for func, ml_pred in zip(functions, ml_predictions):
                conf = ml_pred['confidence']
                if conf >= 0.85:
                    severity = 'CRITICAL'
                elif conf >= 0.65:
                    severity = 'HIGH'
                elif conf >= 0.40:
                    severity = 'MEDIUM'
                else:
                    severity = 'LOW'
                ml_results.append({
                    'function_name': func['function_name'],
                    'file_path': func['file_path'],
                    'line_number': func.get('line_number', 'Unknown'),
                    'code': func['code'],
                    'code_snippet': func['code'][:500] + '...' if len(func['code']) > 500 else func['code'],
                    'ml_vulnerable': ml_pred['is_vulnerable'],
                    'ml_confidence': conf,
                    'severity': severity if ml_pred['is_vulnerable'] else 'N/A',
                    'individual_models': ml_pred['individual_models'],
                    'ml_threshold': ml_threshold,
                    'ml_model': 'ensemble',
                })

        t3 = time.time()
        logger.info(f"✓ ML analysis complete in {t3 - t2:.2f} seconds")
        ml_vulnerable = sum(1 for r in ml_results if r['ml_vulnerable'])
        logger.info(f"  ML findings: {ml_vulnerable}/{len(functions)} vulnerable")

        logger.info(f"\n{'='*70}")
        logger.info(f"Total Analysis Time: {t3 - t0:.2f} seconds")
        logger.info(f"{'='*70}\n")

        return {
            'static_results': static_results,
            'ml_results': ml_results,
            'ml_model_used': ml_model,
        }
