"""
Tests for separated static and ML analysis output shapes.
"""
import pytest
from unittest.mock import MagicMock, patch


SAMPLE_FUNCTIONS = [
    {
        'function_name': 'vuln_func',
        'code': 'void f() { char buf[10]; gets(buf); }',
        'file_path': '/tmp/test.c',
        'line_number': 1,
        'language': 'c',
    },
    {
        'function_name': 'safe_func',
        'code': 'int add(int a, int b) { return a + b; }',
        'file_path': '/tmp/test.c',
        'line_number': 5,
        'language': 'c',
    },
]

MOCK_STATIC_FINDINGS = [
    {
        'is_vulnerable': True,
        'confidence': 0.85,
        'findings': [
            {
                'tool': 'flawfinder',
                'message': 'gets() is unsafe',
                'severity': 'CRITICAL',
                'cwe_id': 'CWE-120',
                'cwe_name': 'Buffer Copy without Checking Size',
            }
        ],
    },
    {
        'is_vulnerable': False,
        'confidence': 0.0,
        'findings': [],
    },
]

MOCK_ML_PREDICTIONS = [
    {
        'is_vulnerable': True,
        'confidence': 0.87,
        'label': 'VULNERABLE',
        'threshold': 0.308,
        'individual_models': {'xgb_conservative': 0.8, 'xgb_aggressive': 0.9, 'lgb_balanced': 0.85, 'catboost': 0.88},
    },
    {
        'is_vulnerable': False,
        'confidence': 0.12,
        'label': 'SAFE',
        'threshold': 0.308,
        'individual_models': {'xgb_conservative': 0.1, 'xgb_aggressive': 0.15, 'lgb_balanced': 0.11, 'catboost': 0.13},
    },
]


@pytest.fixture
def analyzer():
    with patch('src.pipeline.combined_analyzer.StaticAnalyzer') as MockStatic, \
         patch('src.pipeline.combined_analyzer.Run12Predictor') as MockML:
        MockStatic.return_value.analyze_batch.return_value = MOCK_STATIC_FINDINGS
        MockML.return_value.predict.return_value = MOCK_ML_PREDICTIONS

        from src.pipeline.combined_analyzer import CombinedAnalyzer
        return CombinedAnalyzer()


def test_analyze_returns_both_keys(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    assert 'static_results' in result
    assert 'ml_results' in result


def test_static_results_length(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    assert len(result['static_results']) == len(SAMPLE_FUNCTIONS)


def test_ml_results_length(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    assert len(result['ml_results']) == len(SAMPLE_FUNCTIONS)


def test_static_result_has_no_severity_at_function_level(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    for r in result['static_results']:
        assert 'severity' not in r, "Static results must not have a top-level severity"


def test_static_result_has_cwe_types(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    vuln = result['static_results'][0]
    assert vuln['static_vulnerable'] is True
    assert 'CWE-120: Buffer Copy without Checking Size' in vuln['cwe_types']


def test_static_result_no_ml_fields(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    for r in result['static_results']:
        assert 'ml_vulnerable' not in r
        assert 'ml_confidence' not in r
        assert 'individual_models' not in r


def test_ml_result_has_severity(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    vuln = result['ml_results'][0]
    assert vuln['ml_vulnerable'] is True
    assert vuln['severity'] == 'CRITICAL'  # confidence 0.87 >= 0.85


def test_ml_result_no_cwe_fields(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    for r in result['ml_results']:
        assert 'cwe_types' not in r
        assert 'static_findings' not in r


def test_ml_severity_thresholds(analyzer):
    """Severity is derived from ml_confidence only."""
    # confidence 0.87 -> CRITICAL (>= 0.85)
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    assert result['ml_results'][0]['severity'] == 'CRITICAL'
    # safe function -> N/A
    assert result['ml_results'][1]['severity'] == 'N/A'


def test_static_finding_shape(analyzer):
    result = analyzer.analyze(SAMPLE_FUNCTIONS)
    finding = result['static_results'][0]['static_findings'][0]
    assert 'tool' in finding
    assert 'message' in finding
    assert 'severity' in finding
    assert 'cwe_id' in finding
    assert 'cwe_name' in finding


def test_services_generate_static_summary():
    from src.api.services import generate_static_summary
    static_results = [
        {
            'static_vulnerable': True,
            'static_findings': [
                {'tool': 'cppcheck', 'message': 'err', 'severity': 'HIGH', 'cwe_id': 'CWE-476', 'cwe_name': 'NULL Deref'},
                {'tool': 'flawfinder', 'message': 'warn', 'severity': 'CRITICAL', 'cwe_id': 'CWE-120', 'cwe_name': 'Buffer Copy'},
            ],
            'cwe_types': ['CWE-476: NULL Deref', 'CWE-120: Buffer Copy'],
        },
        {
            'static_vulnerable': False,
            'static_findings': [],
            'cwe_types': [],
        },
    ]
    summary = generate_static_summary(static_results)
    assert summary['total_functions'] == 2
    assert summary['vulnerable'] == 1
    assert summary['safe'] == 1
    assert summary['tool_counts'] == {'cppcheck': 1, 'flawfinder': 1}
    assert summary['cwe_frequency']['CWE-476: NULL Deref'] == 1


def test_services_generate_ml_summary():
    from src.api.services import generate_ml_summary
    ml_results = [
        {'ml_vulnerable': True, 'ml_confidence': 0.87, 'severity': 'CRITICAL'},
        {'ml_vulnerable': True, 'ml_confidence': 0.70, 'severity': 'HIGH'},
        {'ml_vulnerable': False, 'ml_confidence': 0.10, 'severity': 'N/A'},
    ]
    summary = generate_ml_summary(ml_results)
    assert summary['total_functions'] == 3
    assert summary['vulnerable'] == 2
    assert summary['safe'] == 1
    assert summary['critical_count'] == 1
    assert summary['high_count'] == 1
    assert summary['medium_count'] == 0
    assert abs(summary['avg_ml_confidence'] - (0.87 + 0.70) / 2) < 0.001