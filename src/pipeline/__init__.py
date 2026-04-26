"""
Pipeline Package — Vulnerability Detection Pipeline
Entry point: CombinedAnalyzer (static + Run12 ML ensemble)
"""
import sys
from pathlib import Path

PROJECT_ROOT = str(Path(__file__).parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from .combined_analyzer import CombinedAnalyzer

__all__ = ['CombinedAnalyzer']
