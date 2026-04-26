"""Pre-training comprehensive check for Run 11."""
import sys
import os
sys.path.insert(0, '.')

print("=" * 70)
print("PRE-TRAINING CHECK FOR RUN 11")
print("=" * 70)

issues = []
warnings = []

# ============================================================
# 1. CONFIG VERIFICATION
# ============================================================
print("\n[1] CONFIGURATION VERIFICATION")
print("-" * 70)

from models.ensemble_boosting.config import (
    THRESHOLD_CONFIG, FEATURE_CONFIG, ENSEMBLE_WEIGHTS,
    XGBOOST_CONSERVATIVE, XGBOOST_AGGRESSIVE, LIGHTGBM_BALANCED,
    CATBOOST, PATHS
)

# Threshold config
print(f"  Threshold optimization: {THRESHOLD_CONFIG['optimize']}")
if not THRESHOLD_CONFIG['optimize']:
    issues.append("Threshold optimization is DISABLED")
else:
    print(f"    ✓ ENABLED with {THRESHOLD_CONFIG['joint_rounds']} joint rounds")

print(f"  Search range: {THRESHOLD_CONFIG['search_range']}")
print(f"  Search steps: {THRESHOLD_CONFIG['search_steps']}")

# Feature config
print(f"\n  Feature Configuration:")
print(f"    Embedding mode: {FEATURE_CONFIG['embedding_mode']}")
if FEATURE_CONFIG['embedding_mode'] == 'full':
    warnings.append("Using 'full' 768d embeddings (Run 10 showed no improvement over PCA)")
elif FEATURE_CONFIG['embedding_mode'] == 'pca':
    print(f"    ✓ PCA mode (32 components)")
    
print(f"    Skip graphs: {FEATURE_CONFIG['skip_graphs']}")
print(f"    Clean cached: {FEATURE_CONFIG.get('clean_cached_features', False)}")

# Model configs
print(f"\n  Model Configurations:")
print(f"    XGB Conservative: max_depth={XGBOOST_CONSERVATIVE['max_depth']}, lr={XGBOOST_CONSERVATIVE['learning_rate']}")
print(f"    XGB Aggressive: max_depth={XGBOOST_AGGRESSIVE['max_depth']}, lr={XGBOOST_AGGRESSIVE['learning_rate']}")
print(f"    LightGBM: max_depth={LIGHTGBM_BALANCED['max_depth']}, lr={LIGHTGBM_BALANCED['learning_rate']}")
print(f"    CatBoost: depth={CATBOOST['depth']}, lr={CATBOOST['learning_rate']}")

# Ensemble weights (Run 10 optimized)
print(f"\n  Ensemble Weights (Run 10 baseline):")
for name, weight in ENSEMBLE_WEIGHTS.items():
    print(f"    {name}: {weight}")

# ============================================================
# 2. FEATURE ENGINEER VERIFICATION
# ============================================================
print("\n[2] FEATURE ENGINEER VERIFICATION")
print("-" * 70)

from models.ensemble_boosting.feature_engineer import (
    FeatureEngineer, UNSAFE_STRING_FUNCS, SAFE_STRING_FUNCS
)

fe = FeatureEngineer()
print(f"  Total features: {fe.n_features}")
names = fe._get_feature_names()
print(f"  Feature names count: {len(names)}")

if fe.n_features != len(names):
    issues.append(f"Feature count mismatch: n_features={fe.n_features} vs names={len(names)}")
else:
    print(f"    ✓ Feature count matches names")

# Verify function classifications
print(f"\n  String Function Classification:")
print(f"    UNSAFE: {len(UNSAFE_STRING_FUNCS)} functions")
if 'strncpy' in UNSAFE_STRING_FUNCS or 'strncat' in UNSAFE_STRING_FUNCS:
    issues.append("strncpy/strncat incorrectly in UNSAFE_STRING_FUNCS")
else:
    print(f"      ✓ strncpy/strncat not in UNSAFE list")
    
print(f"    SAFE: {len(SAFE_STRING_FUNCS)} functions")
if 'strncpy' not in SAFE_STRING_FUNCS or 'strncat' not in SAFE_STRING_FUNCS:
    issues.append("strncpy/strncat missing from SAFE_STRING_FUNCS")
else:
    print(f"      ✓ strncpy/strncat in SAFE list")

# Verify graph features
graph_names = [n for n in names if n.startswith('graph_')]
print(f"\n  Graph Features: {len(graph_names)}")
expected_graph = 40
if len(graph_names) != expected_graph:
    issues.append(f"Expected {expected_graph} graph features, found {len(graph_names)}")
else:
    print(f"    ✓ All {expected_graph} graph features present")

# ============================================================
# 3. ENSEMBLE MODEL VERIFICATION
# ============================================================
print("\n[3] ENSEMBLE MODEL VERIFICATION")
print("-" * 70)

from models.ensemble_boosting.ensemble import EnsembleModel

ens = EnsembleModel(load_optimized=True)
print(f"  Optimized threshold: {ens.optimal_threshold}")
print(f"  Weights loaded: {list(ens.weights.keys())}")

if ens.optimal_threshold == 0.5:
    warnings.append("Using default threshold 0.5 (optimal_threshold.json may not exist yet)")
else:
    print(f"    ✓ Loaded saved threshold: {ens.optimal_threshold:.4f}")

# ============================================================
# 4. CACHED DATA CHECK
# ============================================================
print("\n[4] CACHED DATA CHECK")
print("-" * 70)

processed_dir = "data/processed"
if os.path.exists(processed_dir):
    cached_files = [f for f in os.listdir(processed_dir) 
                   if f.endswith(('.pkl', '.npy', '.arrow'))]
    if cached_files:
        warnings.append(f"Found {len(cached_files)} cached files in data/processed/")
        print(f"  WARNING: {len(cached_files)} cached files found")
        print(f"    First 5: {cached_files[:5]}")
    else:
        print(f"    ✓ No cached feature files (.pkl/.npy)")
else:
    print(f"    ✓ Processed directory empty/doesn't exist")

# ============================================================
# 5. MAIN PIPELINE SYNTAX CHECK
# ============================================================
print("\n[5] MAIN PIPELINE SYNTAX CHECK")
print("-" * 70)

try:
    from models.ensemble_boosting.main import main, optimize_threshold, optimize_ensemble_weights
    print(f"    ✓ All imports successful")
    print(f"    ✓ optimize_threshold function available")
    print(f"    ✓ optimize_ensemble_weights function available")
except Exception as e:
    issues.append(f"Import error: {e}")

# ============================================================
# 6. GPU AVAILABILITY
# ============================================================
print("\n[6] GPU AVAILABILITY")
print("-" * 70)

try:
    import torch
    if torch.cuda.is_available():
        print(f"    ✓ CUDA available")
        print(f"      Device: {torch.cuda.get_device_name(0)}")
        print(f"      Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.2f} GB")
    else:
        warnings.append("CUDA not available - training will use CPU")
except Exception as e:
    warnings.append(f"Could not check GPU: {e}")

# ============================================================
# 7. CRITICAL DEPENDENCIES
# ============================================================
print("\n[7] CRITICAL DEPENDENCIES")
print("-" * 70)

deps = {
    'numpy': 'numpy',
    'pandas': 'pandas',
    'scikit-learn': 'sklearn',
    'xgboost': 'xgboost',
    'lightgbm': 'lightgbm',
    'catboost': 'catboost',
    'transformers': 'transformers',
    'torch': 'torch',
    'tree-sitter': 'tree_sitter',
    'tree-sitter-c': 'tree_sitter_c',
}

for name, module in deps.items():
    try:
        __import__(module)
        print(f"    ✓ {name}")
    except ImportError:
        issues.append(f"Missing dependency: {name}")
        print(f"    ✗ {name} - NOT INSTALLED")

# ============================================================
# 8. DATA FILES CHECK
# ============================================================
print("\n[8] DATA FILES CHECK")
print("-" * 70)

required_data = [
    'data/normalized/devign.jsonl',
    'data/normalized/diversevul.jsonl',
    'data/normalized/megavul.jsonl',
]

for filepath in required_data:
    if os.path.exists(filepath):
        size_mb = os.path.getsize(filepath) / 1e6
        print(f"    ✓ {filepath} ({size_mb:.1f} MB)")
    else:
        issues.append(f"Missing data file: {filepath}")

# Check model directory exists
if not os.path.exists(PATHS['models_dir']):
    os.makedirs(PATHS['models_dir'])
    print(f"\n  Created models directory: {PATHS['models_dir']}")
else:
    print(f"\n    ✓ Models directory exists: {PATHS['models_dir']}")

# ============================================================
# 9. PREVIOUS RUN ARTIFACTS
# ============================================================
print("\n[9] PREVIOUS RUN ARTIFACTS")
print("-" * 70)

artifacts = {
    'optimal_threshold.json': 'Threshold from Run 10',
    'optimal_weights.json': 'Weights (will be re-optimized)',
    'evaluation_results.json': 'Previous test results',
}

models_dir = PATHS['models_dir']
for artifact, desc in artifacts.items():
    path = os.path.join(models_dir, artifact)
    if os.path.exists(path):
        print(f"    ✓ {artifact} ({desc})")
    else:
        print(f"      {artifact} - not found (will be created)")

# ============================================================
# SUMMARY
# ============================================================
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

if issues:
    print(f"\n❌ {len(issues)} CRITICAL ISSUES FOUND:")
    for i, issue in enumerate(issues, 1):
        print(f"  {i}. {issue}")
else:
    print(f"\n✓ No critical issues found")

if warnings:
    print(f"\n⚠ {len(warnings)} WARNINGS:")
    for i, warning in enumerate(warnings, 1):
        print(f"  {i}. {warning}")
else:
    print(f"\n✓ No warnings")

print("\n" + "=" * 70)
if not issues:
    print("READY FOR RUN 11 TRAINING")
    print("=" * 70)
    print("\nTo start training:")
    print("  python models/ensemble_boosting/main.py --full-training")
    print("\nExpected changes from Run 10:")
    print("  • PCA-32 embeddings (768→272 features)")
    print("  • 15 graph features now populated correctly")
    print("  • 3-round joint threshold+weight optimization")
    print("  • Proportional CWE-125 scoring")
    print("  • Fixed cognitive complexity metric")
    print("=" * 70)
else:
    print("PLEASE FIX ISSUES BEFORE TRAINING")
    print("=" * 70)
    sys.exit(1)
