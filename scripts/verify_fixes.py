"""Quick verification of all bug fixes."""
import sys
sys.path.insert(0, '.')

from models.ensemble_boosting.config import (
    THRESHOLD_CONFIG, FEATURE_CONFIG, ENSEMBLE_WEIGHTS,
    XGBOOST_CONSERVATIVE
)
from models.ensemble_boosting.ensemble import EnsembleModel
from models.ensemble_boosting.feature_engineer import (
    FeatureEngineer, UNSAFE_STRING_FUNCS, SAFE_STRING_FUNCS
)

print("=" * 60)
print("VERIFICATION OF ALL FIXES")
print("=" * 60)

errors = []

# Fix 1: Threshold optimization enabled
print("\n[1] Threshold optimization...")
if THRESHOLD_CONFIG['optimize']:
    print("  PASS: optimize = True")
else:
    errors.append("FAIL: THRESHOLD_CONFIG['optimize'] should be True")
    print(f"  {errors[-1]}")

# Fix 1b: Joint rounds configured
rounds = THRESHOLD_CONFIG.get('joint_rounds', None)
if rounds and rounds >= 2:
    print(f"  PASS: joint_rounds = {rounds}")
else:
    errors.append(f"FAIL: joint_rounds = {rounds}")
    print(f"  {errors[-1]}")

# Fix 2: No duplicate tree_method key (check raw file)
print("\n[2] Duplicate config key...")
with open('models/ensemble_boosting/config.py', 'r', encoding='utf-8', errors='replace') as f:
    config_text = f.read()
count = config_text.count("'tree_method'")
if count <= 2:  # 2 is correct: one per XGBoost dict (Conservative + Aggressive)
    print(f"  PASS: tree_method appears {count} time(s) (one per XGB config)")
else:
    errors.append(f"FAIL: tree_method appears {count} times (should be 2, one per XGB config)")
    print(f"  {errors[-1]}")

# Fix 3: strncpy/strncat not in UNSAFE_STRING_FUNCS
print("\n[3] strncpy/strncat classification...")
if 'strncpy' not in UNSAFE_STRING_FUNCS and 'strncat' not in UNSAFE_STRING_FUNCS:
    print("  PASS: strncpy/strncat removed from UNSAFE_STRING_FUNCS")
else:
    errors.append("FAIL: strncpy/strncat still in UNSAFE_STRING_FUNCS")
    print(f"  {errors[-1]}")

if 'strncpy' in SAFE_STRING_FUNCS and 'strncat' in SAFE_STRING_FUNCS:
    print("  PASS: strncpy/strncat in SAFE_STRING_FUNCS")
else:
    errors.append("FAIL: strncpy/strncat should be in SAFE_STRING_FUNCS")
    print(f"  {errors[-1]}")

# Fix 4: PCA mode
print("\n[4] Embedding mode...")
if FEATURE_CONFIG['embedding_mode'] == 'pca':
    print("  PASS: embedding_mode = 'pca'")
else:
    errors.append(f"FAIL: embedding_mode = '{FEATURE_CONFIG['embedding_mode']}' (should be 'pca')")
    print(f"  {errors[-1]}")

# Fix 5: Feature count consistency
print("\n[5] Feature count consistency...")
fe = FeatureEngineer()
names = fe._get_feature_names()
if fe.n_features == len(names):
    print(f"  PASS: n_features={fe.n_features} matches names count={len(names)}")
else:
    errors.append(f"FAIL: n_features={fe.n_features} != names count={len(names)}")
    print(f"  {errors[-1]}")

# Fix 6: Graph feature name alignment (fallback vs canonical)
print("\n[6] Graph feature names alignment...")
# Get canonical graph names
canonical_graph = [n for n in names if n.startswith('graph_')]
print(f"  Canonical graph features: {len(canonical_graph)}")

# Get fallback names by running with skip_graphs=True
fe_skip = FeatureEngineer(skip_graphs=True)
test_code = "int main() { return 0; }"
features = fe_skip.extract_features(test_code)
feature_names = fe_skip._get_feature_names()

# Check each canonical graph name exists in the fallback output
fallback_dict = dict(zip(feature_names, features))
missing = []
for name in canonical_graph:
    if name not in fallback_dict:
        missing.append(name)

if not missing:
    print(f"  PASS: All {len(canonical_graph)} canonical graph names present in fallback")
else:
    errors.append(f"FAIL: {len(missing)} graph names missing from fallback: {missing[:5]}...")
    print(f"  {errors[-1]}")

# Fix 7: Duplicate feature check
print("\n[7] Duplicate feature values...")
features_full = fe.extract_features("""
void vulnerable(char *input) {
    char buf[64];
    if (strlen(input) > 100) {
        for (int i = 0; i < 10; i++) {
            if (buf[i] == 0) {
                while (1) { break; }
            }
        }
        if (input[0] == 'a') {
            strcpy(buf, input);
        }
    }
    for (int j = 0; j < 5; j++) {
        buf[j] = input[j];
    }
}
""")
feature_dict = dict(zip(names, features_full))
max_nesting = feature_dict.get('ast_max_nesting_depth', None)
nested_ctrl = feature_dict.get('ast_nested_control_depth', None)
if max_nesting != nested_ctrl:
    print(f"  PASS: ast_max_nesting_depth={max_nesting:.2f} != ast_nested_control_depth={nested_ctrl:.2f}")
else:
    errors.append(f"FAIL: still duplicate: both = {max_nesting}")
    print(f"  {errors[-1]}")

# Fix 8: Ensemble loads optimized config
print("\n[8] Ensemble model config loading...")
ens = EnsembleModel(load_optimized=True)
print(f"  Threshold: {ens.optimal_threshold}")
print(f"  Weights: {ens.weights}")
print(f"  PASS: EnsembleModel loads config without error")

# Summary
print("\n" + "=" * 60)
if errors:
    print(f"RESULT: {len(errors)} ERRORS FOUND")
    for e in errors:
        print(f"  - {e}")
else:
    print("RESULT: ALL CHECKS PASSED!")
print("=" * 60)
