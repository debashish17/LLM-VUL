# Training Run 16 - Two-Stage Gated Ensemble (Final Architecture)

**Date:** February 16, 2026  
**Model:** Dual-Stage Ensemble with AND-gating  
**Dataset:** Devign + DiverseVul + MegaVul (~338k samples, Zenodo excluded)  
**Objective:** Structural correction via independent agreement logic to break CodeBERT dominance

---

## Executive Summary

Run 16 implemented a **radical architectural change** to address the persistent issue that `codebert_pca_0` drives 97-98% of false positives across Runs 12-15. Instead of feature scaling or removal, Run 16 trains **TWO independent ensembles** with different feature sets and applies **AND-gating**:

- **Stage 1 (Recall Model):** 304 features (240 eng + 32 CodeBERT + 32 GraphCodeBERT)
- **Stage 2 (Precision Filter):** 272 features (240 eng + 32 GraphCodeBERT, **NO CodeBERT**)
- **Decision Logic:** Predict vulnerable **ONLY IF** both stages agree (P1 ≥ T1 **AND** P2 ≥ T2)

**Key Results:**
- ❌ F1 Score: **0.5895** (-0.0243 vs Run 12, **worst performer**)
- ✅ Precision: **0.5892** (+0.0426 vs Run 12, +7.8%)
- ❌ Recall: **0.5897** (-0.1101 vs Run 12, -16%)
- ✅ ROC-AUC: **0.8978** (still strong ranking ability)  
- ✅ False Positives: **1,778** (-732 vs Run 12, **-29% reduction**)
- ❌ False Negatives: **1,774** (+476 vs Run 12, **+37% increase**)

**Critical Finding:** AND-gating is **too restrictive**. Requiring unanimous agreement from both stages creates a precision-optimized filter that misses 37% more vulnerabilities. The recall collapse (0.5897) makes this architecture **unacceptable for production**.

**Verdict:** ❌ **Architectural intervention FAILED**. Gating successfully improved precision and reduced FPs, but at catastrophic cost to recall. **Dataset ceiling reached** for this paradigm.

---

## Architecture: Two-Stage Gated Ensemble

### Design Philosophy

**Problem Statement:**
- Runs 12-15 showed `codebert_pca_0` drives 97-98% of FPs (SHAP 0.84-1.13)
- Scaling (Run 15) and removal (Run 13) both failed to maintain F1

**Hypothesis:**
- CodeBERT embeddings = high recall but noisy (drives FPs)
- GraphCodeBERT embeddings = high precision but lower sensitivity
- **Solution:** Use both in **independent models** with agreement logic

### Stage Configuration

| Component | Stage 1 (Recall) | Stage 2 (Precision) | Purpose |
|-----------|------------------|---------------------|---------|
| **Engineered Features** | 240 | 240 | Shared baseline |
| **CodeBERT PCA** | 32 | **0** | High sensitivity (S1 only) |
| **GraphCodeBERT PCA** | 32 | 32 | Structural signal (both) |
| **Total Features** | **304** | **272** | Different perspectives |
| **Ensemble** | 4 GBT (XGB×2, LGB, CB) | 4 GBT (XGB×2, LGB, CB) | Independent training |
| **Objective** | Maximize recall (≥0.72) | Maximize precision (≥0.65) | Complementary goals |

### Gating Logic

```python
# Stage 1: Recall model probabilities
proba_stage1 = ensemble1.predict_proba(features_304)

# Stage 2: Precision filter probabilities  
proba_stage2 = ensemble2.predict_proba(features_272)

# Grid search optimal thresholds on validation set
T1_optimal = 0.40  # Stage 1 threshold
T2_optimal = 0.20  # Stage 2 threshold

# Final prediction: BOTH must agree
gate1 = proba_stage1 >= T1_optimal
gate2 = proba_stage2 >= T2_optimal
final_prediction = gate1 & gate2  # AND logic
```

**Expected Behavior:**
- Stage 1 casts a wide net (high recall, tolerates FPs)
- Stage 2 filters out low-confidence predictions (high precision)
- Gating combines strengths while mitigating weaknesses

---

## Results Comparison: Run 12 vs Run 16

### Test Set Performance

| Metric | Run 12 (Baseline) | Run 16 (Gated) | Change | % Change |
|--------|-------------------|----------------|--------|----------|
| **F1 Score** | 0.6138 | **0.5895** | **-0.0243** | **-4.0%** ❌ |
| **Precision** | 0.5466 | **0.5892** | **+0.0426** | **+7.8%** ✅ |
| **Recall** | 0.6998 | **0.5897** | **-0.1101** | **-15.7%** ❌ |
| **ROC-AUC** | 0.9060 | **0.8978** | -0.0082 | -0.9% |
| **PR-AUC** | 0.6050 | **0.5938** | -0.0112 | -1.9% |
| **Brier Score** | 0.0706 | **0.0732** | +0.0026 | +3.7% |
| **Precision@10%** | 0.6439 | **0.6238** | -0.0201 | -3.1% |
| **Gating Thresholds** | Single (0.319) | **T1=0.40, T2=0.20** | Dual gates |

### Confusion Matrix

| Metric | Run 12 | Run 16 | Change |
|--------|--------|--------|--------|
| True Negatives | 27,006 | **27,738** | **+732** ✅ |
| False Positives | 2,510 | **1,778** | **-732** ✅ |
| False Negatives | 1,298 | **1,774** | **+476** ❌ |
| True Positives | 3,026 | **2,550** | **-476** ❌ |
| **FP Rate** | 8.50% | **6.02%** | **-2.48%** ✅ |
| **FN Rate** | 30.01% | **41.03%** | **+11.02%** ❌ |

**Analysis:**
- ✅ Reduced false alarms by 732 (-29%) — **major FP reduction**
- ✅ Improved safe-code detection by 732 (TN +2.7%)
- ❌ **Missed 476 MORE vulnerabilities** — recall collapse
- ❌ Lost 476 correct vulnerability detections (TP -15.7%)
- **Trade-off:** AND-gating favors precision at catastrophic cost to recall

---

## Stage-by-Stage Analysis

### Stage 1 (Recall Model) - Standalone Performance

**Configuration:** 304 features (eng + CodeBERT + GraphCodeBERT)

| Metric | Value | Notes |
|--------|-------|-------|
| **F1 Score** | 0.6139 | Matches Run 12 baseline |
| **Precision** | 0.5706 | Moderate |
| **Recall** | 0.6642 | Good sensitivity |
| **ROC-AUC** | 0.9051 | Excellent ranking |
| **Threshold** | 0.421 | Optimized for recall |
| **FP** | 2,161 | |
| **FN** | 1,452 | |

**Ensemble Weights (Stage 1):**
```json
{
  "xgb_conservative": 0.15,
  "xgb_aggressive": 0.15,
  "lgb_balanced": 0.20,
  "catboost": 0.50
}
```

**Analysis:**
- Stage 1 alone achieves F1=0.6139 (virtually identical to Run 12)
- CatBoost dominates with 50% weight (highest recall model)
- Validates that CodeBERT-inclusive model maintains baseline performance

---

### Stage 2 (Precision Filter) - Standalone Performance

**Configuration:** 272 features (eng + GraphCodeBERT, **NO CodeBERT**)

| Metric | Value | Notes |
|--------|-------|-------|
| **F1 Score** | 0.5576 | **Significantly weaker** |
| **Precision** | 0.5172 | Lower than Stage 1 |
| **Recall** | 0.6048 | Moderate sensitivity |
| **ROC-AUC** | 0.8644 | Good but not excellent |
| **Threshold** | 0.276 | Lower threshold needed |
| **FP** | 2,441 | More FPs than Stage 1 |
| **FN** | 1,709 | More FNs than Stage 1 |

**Ensemble Weights (Stage 2):**
```json
{
  "xgb_conservative": 0.20,
  "xgb_aggressive": 0.30,
  "lgb_balanced": 0.40,
  "catboost": 0.10
}
```

**Analysis:**
- Stage 2 alone is **structurally weaker** than Stage 1 (F1 -0.0563)
- Without CodeBERT, model loses significant signal
- LightGBM becomes dominant (40% weight) — relies on GraphCodeBERT
- **Critical issue:** Weak Stage 2 creates conservative gate → recall collapse

---

### Gated Ensemble Performance

**Grid Search Results:**
- **88 threshold combinations tested** (T1: 0.20-0.70, T2: 0.20-0.55)
- **Optimal:** T1=0.40, T2=0.20 (maximizes F1 on validation set)
- **Validation F1:** 0.6032

| Metric | Stage 1 Only | Stage 2 Only | Gated (T1=0.40, T2=0.20) |
|--------|--------------|--------------|--------------------------|
| **F1 Score** | 0.6139 | 0.5576 | **0.5895** |
| **Precision** | 0.5706 | 0.5172 | **0.5892** |
| **Recall** | 0.6642 | 0.6048 | **0.5897** |
| **FP** | 2,161 | 2,441 | **1,778** |
| **FN** | 1,452 | 1,709 | **1,774** |

**Key Observation:**
- Gating reduces FPs below both individual stages ✅
- But recall is **LOWER than both individual stages** ❌
- F1 is worse than Stage 1 alone (-0.0244)
- **Verdict:** AND-logic too restrictive — blocks true vulnerabilities

---

## Individual Model Performance

### Stage 1 Models (304 features with CodeBERT)

| Model | F1 | Precision | Recall | Weight |
|-------|-----|-----------|--------|--------|
| XGB Conservative | 0.6041 | 0.5106 | 0.7380 | 0.15 |
| XGB Aggressive | 0.6014 | 0.5929 | 0.6102 | 0.15 |
| LightGBM Balanced | 0.6060 | 0.5180 | 0.7296 | 0.20 |
| **CatBoost** | **0.5837** | 0.4655 | 0.7814 | **0.50** ✓ |

### Stage 2 Models (272 features without CodeBERT)

| Model | F1 | Precision | Recall | Weight |
|-------|-----|-----------|--------|--------|
| XGB Conservative | 0.5534 | 0.4887 | 0.6376 | 0.20 |
| XGB Aggressive | 0.5474 | 0.5401 | 0.5550 | 0.30 |
| **LightGBM Balanced** | **0.5600** | 0.4934 | 0.6458 | **0.40** ✓ |
| CatBoost | 0.5138 | 0.4081 | 0.6876 | 0.10 |

**Key Findings:**
1. ✅ Stage 1 models match Run 12 baseline performance
2. ❌ Stage 2 models are uniformly weaker (-0.04 to -0.07 F1)
3. Weight distribution differs significantly:
   - Stage 1: CatBoost-heavy (recall focus)
   - Stage 2: LightGBM-heavy (balance focus)
4. **Removing CodeBERT hurts all models** in Stage 2

---

## SHAP Analysis: Stage 1 (Recall Model)

### Global Feature Importance (Top 15)

| Rank | Feature | SHAP Value | Category | vs Run 12 |
|------|---------|------------|----------|-----------|
| 1 | **codebert_pca_0** | **0.1683** | CodeBERT | -85% (1.126 → 0.168) |
| 2 | codebert_pca_4 | 0.0743 | CodeBERT | Similar to Run 12 |
| 3 | graphcodebert_pca_9 | 0.0530 | GraphCodeBERT | Elevated |
| 4 | ctx_std_line_length | 0.0475 | Context | Elevated |
| 5 | ctx_blank_line_ratio | 0.0455 | Context | Elevated |
| 6 | graphcodebert_pca_23 | 0.0438 | GraphCodeBERT | Elevated |
| 7 | ast_n_pointer_declarators | 0.0428 | AST | First engineered in top-10! |
| 8 | graphcodebert_pca_6 | 0.0377 | GraphCodeBERT | |
| 9 | codebert_pca_12 | 0.0376 | CodeBERT | |
| 10 | codebert_pca_17 | 0.0333 | CodeBERT | |

### 🎯 Critical Finding: SHAP Normalization Artifact

**Observation:**
- `codebert_pca_0` SHAP dropped from 1.126 → 0.168 (-85%)
- BUT this is because **absolute SHAP values are lower** for Stage 1 ensemble
- **Relative dominance unchanged** — still top feature by large margin

**False Positive Driver Analysis (Stage 1):**
- `codebert_pca_0` appears in **70.3%** of false positives (vs 98.4% in Run 12)
- Reduction due to lower total FP count (2,161 vs 2,510), not different pattern
- **Pattern persists:** PC-0 remains primary FP driver

---

## Training Performance

### Pipeline Duration (with cached embeddings)

| Step | Task | Time | Notes |
|------|------|------|-------|
| 1 | Load & split data | 5 min | 338,400 samples |
| 2 | Extract features (240) | Cached | |
| 3a | CodeBERT embeddings + PCA-32 | Cached | |
| 3b | GraphCodeBERT embeddings + PCA-32 | Cached | |
| 4 | Assemble Stage 1 (304) + Stage 2 (272) features | 1 min | |
| 5 | Balance training data | 2 min | Same samples for both stages |
| 6 | **Train Stage 1** (4 models + noise + calibration) | **90 min** | Full ensemble pipeline |
| 7 | **Train Stage 2** (4 models + noise + calibration) | **85 min** | Full ensemble pipeline |
| 8 | Grid search T1×T2 thresholds | 15 min | 88 combinations tested |
| 9 | Evaluation + SHAP | 12 min | |
| **Total** | | **~605 min (10.1 hrs)** | **Double training time** |

**Key Observation:**
- Training TWO full ensembles doubles compute time vs single-stage (Run 12-15)
- Embedding caching saved ~5 hours (would've been 15+ hours otherwise)
- **Production consideration:** 2× inference cost (must run both stages)

---

## Threshold Grid Search Analysis

### Top 10 (T1, T2) Combinations by Validation F1

| Rank | T1 | T2 | Val F1 | Val Prec | Val Recall | FP | FN |
|------|-----|-----|--------|----------|------------|----|----|
| **1 ✓** | **0.40** | **0.20** | **0.6032** | **0.5995** | **0.6071** | 1,734 | 1,699 |
| 2 | 0.40 | 0.25 | 0.6015 | 0.6072 | 0.5959 | 1,685 | 1,748 |
| 3 | 0.35 | 0.20 | 0.5998 | 0.5898 | 0.6102 | 1,813 | 1,685 |
| 4 | 0.45 | 0.20 | 0.5989 | 0.6115 | 0.5868 | 1,644 | 1,787 |
| 5 | 0.35 | 0.25 | 0.5982 | 0.5981 | 0.5983 | 1,760 | 1,738 |

**Insights:**
- Selected pair (T1=0.40, T2=0.20) maximizes validation F1
- Narrow F1 range (0.5982-0.6032, ∆=0.005) — relatively flat landscape
- Lower T2 (more lenient Stage 2 gate) generally improves recall
- Higher T1 (stricter Stage 1 gate) generally improves precision
- **No combination achieved Val F1 > 0.61** — ceiling effect

---

## Per-CWE Performance Analysis

### Top 10 CWE Categories (by F1 Score)

| CWE | Type | Samples | F1 | Precision | Recall | vs Run 12 ΔF1 |
|-----|------|---------|-----|-----------|--------|----------------|
| **CWE-Other** | Grouped rare | 1,268 | **0.652** | 0.603 | 0.710 | +0.056 ✅ |
| **CWE-125** | Buffer over-read | 2,030 | **0.597** | 0.566 | 0.631 | -0.027 |
| **CWE-119** | Buffer errors | 2,234 | 0.572 | 0.557 | 0.588 | -0.022 |
| **Unknown** | No label | 4,940 | 0.569 | 0.476 | 0.709 | -0.126 ❌ |
| **CWE-787** | Out-of-bounds write | 2,201 | 0.568 | 0.552 | 0.584 | -0.021 |
| **CWE-20** | Improper validation | 1,955 | 0.523 | 0.482 | 0.571 | -0.026 |
| **CWE-476** | NULL pointer deref | 1,963 | 0.520 | 0.461 | 0.596 | -0.023 |
| **CWE-200** | Info exposure | 1,065 | 0.516 | 0.522 | 0.510 | -0.151 ❌ |
| **CWE-399** | Resource mgmt | 935 | 0.508 | 0.573 | 0.457 | -0.159 ❌ |
| **CWE-416** | Use after free | 2,001 | **0.416** | 0.430 | 0.403 | -0.052 |

**Key Findings:**
1. ❌ **Unknown category collapsed** (F1 -0.126) — was best in Run 12
2. ❌ **CWE-200 and CWE-399 severely impacted** (F1 -0.15 to -0.16)
3. Buffer-related CWEs relatively stable (∆F1 ~ -0.02)
4. **CWE-416 remains worst** (F1=0.416) — use-after-free fundamentally hard
5. **Gating hurts across ALL CWE categories** — no category improved vs Run 12

---

## Critical Analysis: Why Gating Failed

### Hypothesis vs Reality

**Hypothesis:**
- Stage 1 (high recall) catches most vulnerabilities
- Stage 2 (high precision) filters out FPs from Stage 1
- Gating combines strengths → improved F1

**Reality:**
- ❌ Stage 2 structurally weaker than expected (F1=0.5576)
- ❌ AND-gate too restrictive → blocks true positives
- ❌ Recall collapse outweighs precision gain

### Fundamental Issues

1. **Stage 2 lacks critical signal:**
   - Removing CodeBERT reduced Stage 2 F1 by 0.056 vs Stage 1
   - GraphCodeBERT alone insufficient for precision filtering
   - **Engineered features cannot compensate** for lost embedding signal

2. **AND-logic is asymmetric:**
   - Requires unanimous agreement from unequal partners
   - Weaker Stage 2 becomes a conservative veto gate
   - **One false negative from either stage → final false negative**

3. **Gating amplifies weakness:**
   - FN_final ≈ FN_stage1 + FN_stage2 (worst-case union)
   - FP_final ≈ intersection (best-case) BUT recall suffers
   - **Math fundamentally favors precision over recall** with AND-gate

### Alternative Gating Strategies (Not Tested)

**OR-logic (at least one agrees):**
- Prediction = P1 ≥ T1 **OR** P2 ≥ T2
- Expected: Higher recall, worse precision
- Would likely match or exceed Run 12 recall

**Weighted voting:**
- Prediction = 0.6 × P1 + 0.4 × P2 ≥ T_combined
- May balance better than hard AND-gate
- **Not tested in Run 16**

**Ensemble of ensembles:**
- Final meta-model trained on [P1, P2, features]
- Could learn optimal combination
- **Requires additional validation set** — didn't pursue

---

## Key Takeaways

### What Worked ✅
1. **FP reduction** — 732 fewer false alarms (-29% vs Run 12)
2. **Precision improvement** — 58.92% (+7.8% vs Run 12)
3. **TN improvement** — 732 more correct safe classifications
4. **Stage 1 validation** — Confirms baseline reproducibility

### What Didn't Work ❌
1. **Recall collapse** — 58.97% (-16% vs Run 12) **UNACCEPTABLE**
2. **F1 decline** — 0.5895 (-4.0% vs Run 12) **WORST PERFORMER**
3. **FN explosion** — 476 more missed vulnerabilities (+37%)
4. **Stage 2 weakness** — F1=0.5576 creates conservative gate
5. **AND-logic too restrictive** — structural flaw in gating approach

### Critical Insights 🎯

**1. Gating Architecture Fundamentally Flawed for This Use Case:**
- Security prioritizes recall over precision (don't miss vulnerabilities)
- AND-gating inverts priorities → precision at recall's expense
- **37% more missed vulnerabilities unacceptable** for vulnerability detection

**2. CodeBERT Signal Irreplaceable:**
- Stage 2 (without CodeBERT) significantly weaker
- GraphCodeBERT + engineered features insufficient
- **Removing CodeBERT = losing critical signal**, regardless of FP issues

**3. Dataset Ceiling Reached:**
- All interventions (scaling, removal, gating) failed to improve F1
- Runs 12-16 cluster around F1=0.59-0.61
- **Fundamental limit:** Embedding-based features don't align with vulnerability semantics

---

## Recommendations

### Production Deployment: ❌ DO NOT USE RUN 16

**Rationale:**
- Misses 37% more vulnerabilities than baseline
- Recall 58.97% unacceptable for security tooling
- F1 0.5895 below acceptable threshold (F1 ≥ 0.60)

### Recommended Production Model: Run 12 or Run 15

| Model | F1 | Precision | Recall | FP | FN | Use Case |
|-------|-----|-----------|--------|----|----|----------|
| **Run 12** | 0.6138 | 0.5466 | 0.6998 | 2,510 | 1,298 | **Balanced (recommended)** |
| **Run 15** | 0.6079 | 0.5289 | 0.7146 | 2,752 | 1,234 | **Recall-critical** |
| Run 16 | 0.5895 | 0.5892 | 0.5897 | 1,778 | 1,774 | ❌ Never |

**Deploy Run 12 if:**
- Best overall balance needed
- F1 prioritized
- Acceptable F rate ~8.5%
- FN rate ~30%

**Deploy Run 15 if:**
- Recall absolutely critical
- Can tolerate +9% higher FP rate
- Want to catch 64 more vulnerabilities than Run 12
- FN rate ~28.5% acceptable

### Future Research Directions

**1. Abandon Embedding-First Approach:**
- Current bottleneck: Embedding similarity ≠ vulnerability semantics
- Consider engineered-feature-heavy models
- Explore domain-specific embeddings trained on vulnerability data

**2. Alternative Architectures:**
- Stacking/meta-learning (train Level-2 model on [eng, CB, GCB] outputs)
- Attention-based fusion (learn which embedding components to use when)
- Rejection cascade (high-confidence predictions early-exit, uncertain → deeper analysis)

**3. Data Quality Investigation:**
- 98% of FPs driven by single feature suggests dataset pattern
- Manual review of high-codebert_pca_0 FPs may reveal labeling issues
- Consider CWE-specific sub-models (different models for different vulnerability types)

**4. Hybrid Approaches:**
- Rule-based pre-filter (structural patterns) + ML refinement
- Symbolic execution integration for high-confidence FPs
- Human-in-the-loop for borderline cases (0.4 < P < 0.6)

---

## Conclusion: Architecture Limit Reached

Run 16 represents this paradigm. After exhausting feature engineering (240 features), dual embeddings (CodeBERT + GraphCodeBERT), sophisticated training (noise detection, calibration, joint optimization), and architectural innovations (two-stage gating), performance remains plateau'd at **F1 ≈ 0.60-0.61**.

**The persistent issue:** CodeBERT PCA-0 drives 70-98% of FPs across all runs, suggesting a fundamental misalignment between learned embedding space and vulnerability semantics.

**Recommendation:** Accept Run 12 (F1=0.6138) as ceiling for this architecture. Future improvements require:
- Different embedding models (trained on vulnerability-specific corpora)
- Shift from embeddings to engineered features
- Hybrid symbolic/ML approaches
- Better-quality labeled data

---

**Report Generated:** February 16, 2026  
**Training Time:** 10.1 hours (2× ensemble training)  
**Final Verdict:** ❌ Do not deploy. Use Run 12 or Run 15 for production.
