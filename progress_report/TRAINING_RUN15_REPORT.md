# Training Run 15 - Controlled CodeBERT Discipline

**Date:** February 16, 2026  
**Model:** Weighted Ensemble (XGBoost×2, LightGBM, CatBoost)  
**Dataset:** Devign + DiverseVul + MegaVul (~338k samples, Zenodo excluded)  
**Objective:** Reduce CodeBERT PCA-0 dominance through controlled fusion (0.6× scaling)

---

## Executive Summary

Run 15 tested a **scaling-based intervention** to address Run 12's discovery that `codebert_pca_0` drives 98.4% of false positives (SHAP=1.126). Instead of removing the dominant feature entirely (as in Run 13), Run 15 **scales all CodeBERT PCA features by 0.6** to reduce their boosting split gain while preserving the signal.

**Key Results:**
- ✅ F1 Score: **0.6079** (-0.0059 vs Run 12)
- ❌ Precision: **0.5289** (-0.0177 vs Run 12, -3.2%)
- ✅ Recall: **0.7146** (+0.0148 vs Run 12, **highest achieved**)
- ✅ ROC-AUC: **0.9050** (maintained excellent ranking)
- ❌ False Positives: **2,752** (+242 vs Run 12, +9.6%)

**Critical Finding:** Scaling reduced codebert_pca_0 SHAP from 1.126 → 0.8426 (-25%), but it still drives **97.2% of false positives**. The intervention was insufficient to break the CodeBERT dominance pattern.

**Verdict:** Marginal decline in F1 with improved recall but worse precision. Scaling approach hit diminishing returns — architectural change needed.

---

## Configuration Changes from Run 12

### Single Intervention: Feature Scaling Discipline

| Parameter | Run 12 | Run 15 | Change |
|-----------|--------|--------|--------|
| CodeBERT PCA scaling | 1.0 (raw) | **0.6** | **-40% signal strength** |
| Engineered features | 240 | 240 | Same |
| CodeBERT PCA | 32 | 32 | Same (count) |
| GraphCodeBERT PCA | 32 | 32 | Same |
| **Total features** | 304 | 304 | Same |
| Calibration | Isotonic | Isotonic | Same |
| Noise detection | Enabled | Enabled | Same |

### Implementation Details
```python
# Step 3a: CodeBERT embeddings with 0.6× scaling
train_pca_cb = generate_pca_embeddings(...)
val_pca_cb = ... 
test_pca_cb = ...

# SCALING APPLIED HERE
SCALING_FACTOR = 0.6
train_pca_cb *= SCALING_FACTOR
val_pca_cb *= SCALING_FACTOR
test_pca_cb *= SCALING_FACTOR

# Then concatenate with engineered + GraphCodeBERT
train_features = np.hstack([train_eng, train_pca_cb, train_pca_gcb])
```

**Rationale:**
- Preserve CodeBERT signal (unlike Run 13 which removed CodeBERT entirely)
- Reduce boosting split priority by lowering feature magnitudes
- Expected: SHAP contribution <50%, balanced importance across components

---

## Results Comparison: Run 12 vs Run 15

###Test Set Performance

| Metric | Run 12 | Run 15 | Change | % Change |
|--------|--------|--------|--------|----------|
| **F1 Score** | 0.6138 | **0.6079** | **-0.0059** | **-1.0%** ❌ |
| **Precision** | 0.5466 | **0.5289** | **-0.0177** | **-3.2%** ❌ |
| **Recall** | 0.6998 | **0.7146** | **+0.0148** | **+2.1%** ✅ |
| **ROC-AUC** | 0.9060 | **0.9050** | -0.0010 | -0.1% |
| **PR-AUC** | 0.6050 | **0.6047** | -0.0003 | -0.05% |
| **Brier Score** | 0.0706 | **0.0709** | +0.0003 | +0.4% |
| **Precision@10%** | 0.6439 | **0.6398** | -0.0041 | -0.6% |
| **Threshold** | 0.319 | **0.319** | 0.000 | Same |
| **Suspicious Samples** | 400 | **11** | -389 | -97% |

### Confusion Matrix

| Metric | Run 12 | Run 15 | Change |
|--------|--------|--------|--------|
| True Negatives | 27,006 | **26,764** | **-242** ❌ |
| False Positives | 2,510 | **2,752** | **+242** ❌ |
| False Negatives | 1,298 | **1,234** | **-64** ✅ |
| True Positives | 3,026 | **3,090** | **+64** ✅ |
| **FP Rate** | 8.50% | **9.32%** | **+0.82%** ❌ |
| **FN Rate** | 30.01% | **28.54%** | **-1.47%** ✅ |

**Analysis:**
- ✅ Caught 64 MORE vulnerabilities (3,090 vs 3,026 TP) — strong recall improvement
- ❌ Generated 242 MORE false alarms (2,752 vs 2,510 FP) — precision degraded
- ❌ Lost 242 correct safe classifications (26,764 vs 27,006 TN)
- **Trade-off:** Higher recall at cost of higher FP rate — recall-precision imbalance worsened

---

## Individual Model Performance

| Model | F1 Score | Precision | Recall | vs Run 12 ΔF1 |
|-------|----------|-----------|--------|----------------|
| **XGB Conservative** | 0.6054 | 0.5122 | 0.7401 | -0.0011 |
| **XGB Aggressive** | 0.5999 | 0.5963 | 0.6036 | -0.0032 |
| **LightGBM Balanced** | 0.6079 | 0.5194 | 0.7327 | +0.0004 |
| **CatBoost** | 0.5651 | 0.4367 | 0.8004 | -0.0196 |
| **Ensemble (Weighted)** | **0.6079** | **0.5289** | **0.7146** | **-0.0059** |

**Key Observations:**
1. All individual models declined or stayed flat vs Run 12
2. **CatBoost suffered most** (F1 -0.0196) — recall increased but precision collapsed to 0.4367
3. LightGBM slightly improved (+0.0004) — most resilient to scaling
4. Ensemble coordination weaker than Run 12 (wider spread among individual models)

### Ensemble Weight Configuration
```json
{
  "xgb_conservative": 0.25,
  "xgb_aggressive": 0.20,
  "lgb_balanced": 0.15,
  "catboost": 0.40
}
```

**Weight Changes from Run 12:**
- CatBoost decreased from 0.45 → 0.40 (-11%) — still highest weight
- XGB Conservative increased from 0.20 → 0.25 (+25%)
- XGB Aggressive decreased from 0.30 → 0.20 (-33%)
- LightGBM increased from 0.05 → 0.15 (+200%) — significant boost

---

## SHAP Analysis: Scaling Impact Assessment

### Global Feature Importance (Top 15)

| Rank | Feature | Run 12 SHAP | Run 15 SHAP | Change | Category |
|------|---------|-------------|-------------|--------|----------|
| 1 | **codebert_pca_0** | **1.126** | **0.8426** | **-25%** ⚠️ | Embedding (CB) |
| 2 | codebert_pca_4 | 0.079 | **0.2105** | **+166%** | Embedding (CB) |
| 3 | graphcodebert_pca_9 | 0.024 | 0.1455 | +506% | Embedding (GCB) |
| 4 | codebert_pca_1 | 0.304 | 0.1324 | -56% | Embedding (CB) |
| 5 | codebert_pca_12 | ~0.025 | 0.1142 | +357% | Embedding (CB) |
| 6 | graphcodebert_pca_23 | ~0.020 | 0.1039 | +420% | Embedding (GCB) |
| 7 | codebert_pca_17 | ~0.022 | 0.0881 | +300% | Embedding (CB) |
| 8 | ctx_std_line_length | 0.033 | 0.0839 | +154% | Context |
| 9 | graphcodebert_pca_6 | ~0.018 | 0.0800 | +344% | Embedding (GCB) |
| 10 | codebert_pca_28 | ~0.020 | 0.0787 | +294% | Embedding (CB) |

### 🎯 Critical Analysis: Scaling Failed to Break Dominance

**Observation:**
- `codebert_pca_0` reduced from 1.126 → 0.8426 (-25%)
- BUT still **3-4× more important** than next features
- Other CodeBERT/GraphCodeBERT PCs increased significantly (+150-500%)
- **Signal redistributed within embeddings, not to engineered features**

**Implication:**
- Scaling reduced PC-0's absolute contribution but not its relative dominance
- Model compensated by elevating other embedding components
- **Engineered features still marginalized** (ctx_std_line_length highest at only 0.0839)

---

## False Positive Driver Analysis

### Top Features Contributing to FPs (500 FPs analyzed)

| Rank | Feature | FP Count | % of FPs | Run 12 % | Change |
|------|---------|----------|----------|----------|--------|
| 1 | **codebert_pca_0** | 486 | **97.2%** | 98.4% | **-1.2%** ⚠️ |
| 2 | codebert_pca_4 | 268 | 53.6% | 31.8% | +21.8% |
| 3 | codebert_pca_28 | 201 | 40.2% | ~15% | +25% |
| 4 | codebert_pca_1 | 178 | 35.6% | 36.2% | -0.6% |
| 5 | codebert_pca_12 | 153 | 30.6% | ~20% | +10% |
| 6 | graphcodebert_pca_9 | 142 | 28.4% | <5% | +23% |
| 7 | codebert_pca_17 | 125 | 25.0% | ~12% | +13% |
| 8 | ctx_std_line_length | 89 | 17.8% | 12.8% | +5% |
| 9 | graphcodebert_pca_23 | 76 | 15.2% | <3% | +12% |
| 10 | ast_n_pointer_declarators | 68 | 13.6% | ~8% | +6% |

### 🚨 Breakthrough Insight: Scaling Ineffective

**The Problem Persists:**
- `codebert_pca_0` STILL drives 97.2% of false positives (only -1.2% reduction)
- More FP drivers emerged from other embedding components
- GraphCodeBERT components now appear in FP top-10 (previously absent)
- **Scaling redistributed FP blame without reducing total FPs**

**Hypothesis Refined:**
- PC-0 captures a semantic axis strongly correlated with false positive triggers
- Reducing its magnitude caused model to rely on correlated secondary axes
- **Fundamental issue:** Embedding-based features don't align with vulnerability semantics

**Next Steps Recommended:**
- **Run 16:** Test agreement/gating architecture (dual models with different feature sets)
- **Alternative:** Remove CodeBERT entirely, use GraphCodeBERT + engineered only
- **Success criteria:** FP rate <8.0%, Precision >0.58, F1 ≥0.61

---

## Noise Detection Results

### Suspicious Sample Identification

**Identified:** 11 suspicious samples (vs 400 in Run 12)

**97% Reduction Explanation:**
- Scaling made model more conservative overall
- Fewer high-confidence mispredictions (>0.8 or <0.2)
- Suggests model is less certain but also less precise

**Impact:**
- Minimal benefit from noise down-weighting (only 11 samples)
- Run 12's noise detection primarily helped with 400 samples
- **Scaling may have introduced calibration shift** reducing confidence extremes

---

## Training Performance

### Training Pipeline Duration

| Step | Task | Time | Notes |
|------|------|------|-------|
| 1 | Load & split data | 5 min | 338,400 samples → 270,720 train |
| 2 | Extract features (240) | Cached | Reused from Run 12 |
| 3a | CodeBERT embeddings + PCA-32 | Cached | Reused from Run 12 |
| 3b | GraphCodeBERT embeddings + PCA-32 | Cached | Reused from Run 12 |
| 4 | **Apply 0.6× scaling to CodeBERT** | <1 sec | **NEW: in-memory multiplication** |
| 5 | Balance training data | 2 min | 7:1 safe:vuln ratio |
| 6 | Scale features (StandardScaler) | 1 min | |
| 7a | Initial training (4 models) | 27 min | 3000 trees × 4 models |
| 7b | Noise detection | 5 min | Only 11 suspicious found |
| 7c | Retrain with noise weights | 27 min | Minimal impact |
| 8 | Isotonic calibration | 3 min | |
| 9 | Joint optimization (3 rounds) | 18 min | Weights + threshold |
| 10 | Evaluation + SHAP | 12 min | 33,840 test samples |
| **Total** | | **~100 min** | **Cached embeddings saved 4+ hours** |

---

## Per-CWE Performance Analysis

### Top 10 CWE Categories (by F1 Score)

| CWE | Type | Samples | F1 | Precision | Recall | vs Run 12 ΔF1 |
|-----|------|---------|-----|-----------|--------|----------------|
| **CWE-Other** | Grouped rare | 1,268 | **0.649** | 0.573 | 0.752 | +0.053 ✅ |
| **CWE-125** | Buffer over-read | 2,030 | **0.628** | 0.556 | 0.723 | +0.004 |
| **Unknown** | No label | 4,940 | 0.620 | 0.507 | 0.805 | -0.075 ❌ |
| **CWE-119** | Buffer errors | 2,234 | 0.599 | 0.540 | 0.674 | +0.005 |
| **CWE-787** | Out-of-bounds write | 2,201 | 0.592 | 0.529 | 0.672 | +0.003 |
| **CWE-200** | Info exposure | 1,065 | 0.588 | 0.509 | 0.695 | -0.079 ❌ |
| **CWE-20** | Improper validation | 1,955 | 0.556 | 0.473 | 0.676 | +0.007 |
| **CWE-476** | NULL pointer deref | 1,963 | 0.549 | 0.454 | 0.704 | +0.006 |
| **CWE-399** | Resource mgmt | 935 | 0.537 | 0.488 | 0.597 | -0.130 ❌ |
| **CWE-416** | Use after free | 2,001 | **0.467** | 0.429 | 0.515 | -0.001 |

**Key Findings:**
1. **Unknown category declined significantly** (F1 -0.075) — previously best performer
2. **CWE-399 collapsed** (F1 -0.130) — scaling hurt resource management detection
3. Buffer-related CWEs maintained stability (∆F1 < ±0.01)
4. **CWE-416 remains worst** (F1=0.467) — use-after-free fundamentally hard

---

## Key Takeaways

### What Worked ✅
1. **Recall improvement** — 71.46% (highest achieved across all runs)
2. **Caught 64 more vulnerabilities** vs Run 12
3. **ROC-AUC maintained** at 0.9050 (excellent ranking preserved)
4. **Embedding cache reuse** — saved 4+ hours training time

### What Didn't Work ❌
1. **Scaling failed to break codebert_pca_0 dominance** — still drives 97.2% of FPs
2. **Precision degraded** (-3.2%) — 242 more false alarms
3. **Signal redistributed within embeddings** — engineered features still marginalized
4. **FP rate increased** to 9.32% (vs 8.50% in Run 12)

### Critical Insight 🎯
**Scaling is insufficient structural correction.** The intervention reduced PC-0's absolute SHAP value but model compensated by elevating other embedding components. The fundamental issue — embedding similarity doesn't align with vulnerability semantics — remains unsolved.

---

## Recommendations

### Immediate Next Steps
1. **Attempt Run 16** — Two-stage gated ensemble:
   - Stage 1: Recall model (240 eng + 32 CB + 32 GCB)
   - Stage 2: Precision filter (240 eng + 32 GCB, NO CodeBERT)
   - Gating: vulnerable only if BOTH agree above thresholds
   - Expected: Precision improves, recall balanced, F1 > 0.62

2. **Alternative: Drop CodeBERT entirely**
   - Use 272 features (240 eng + 32 GCB only)
   - May match Run 14 results (pure GraphCodeBERT)

### Production Considerations
- **Deploy Run 12** if precision critical (P=0.5466, FP=2,510)
- **Deploy Run 15** if recall critical (R=0.7146, catches more vulns)
- **Never deploy below F1=0.60** — unacceptable accuracy floor

---

## Appendix: Configuration Files

### Ensemble Weights (Final)
```json
{
  "xgb_conservative": 0.25,
  "xgb_aggressive": 0.20,
  "lgb_balanced": 0.15,
  "catboost": 0.40
}
```

### Optimal Threshold
**Value:** 0.3188 (calibrated probabilities)

### Noise Detection Config
```python
NOISE_DETECTION_CONFIG = {
    'enabled': True,
    'high_confidence_threshold': 0.8,
    'low_confidence_threshold': 0.2,
    'suspicious_weight': 0.3,
}
```

### GraphCodeBERT Config
```python
GRAPHCODEBERT_CONFIG = {
    'enabled': True,
    'model_name': 'microsoft/graphcodebert-base',
    'pca_components': 32,
}
```

---

**Report Generated:** February 16, 2026  
**Training Time:** ~100 minutes (cached embeddings)  
**Next Run:** Run 16 (Two-Stage Gated Ensemble)
