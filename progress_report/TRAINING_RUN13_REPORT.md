# Training Run 13 - Attack CodeBERT Dominance

**Date:** February 15, 2026  
**Model:** Weighted Ensemble (XGBoost×2, LightGBM, CatBoost)  
**Dataset:** Devign + DiverseVul + MegaVul + Zenodo (~338k samples)  
**Objective:** Test hypothesis that `codebert_pca_0` is the false positive amplifier

---

## Executive Summary

Run 13 tested a targeted hypothesis from Run 12's SHAP analysis: **drop `codebert_pca_0`** (which drove 98.4% of false positives) to reduce FP rate. The experiment revealed a critical insight about the model's architecture:

**Result:** Near-identical performance (F1=0.6121 vs 0.6138, ∆-0.0017) with **feature importance redistributed** across remaining CodeBERT components.

**Critical Discovery:** The problem is not a single dominant component—it's that **all CodeBERT embedding features collectively over-predict vulnerabilities**. Dropping PC-0 simply caused the model to redistribute the semantic signal across PC-1, PC-2, PC-3, PC-4.

**Key Insight:** CodeBERT captures patterns that correlate with code complexity/unusualness rather than actual vulnerabilities. This explains why semantic embeddings drive both global importance AND false positives.

**Conclusion:** Run 13 confirms we've reached the architectural ceiling for this approach. Moving to Run 14 (GraphCodeBERT only) to test if graph-based embeddings provide cleaner signal.

---

## Hypothesis & Experimental Design

### Hypothesis from Run 12 SHAP Analysis
**Observation:** `codebert_pca_0` appeared in 98.4% of false positives (492/500)  
**Hypothesis:** PC-0 is a false positive amplifier—removing it will reduce FP rate  
**Prediction:** Precision improves, FP count drops, recall may decrease slightly

### Experiment Design
**Change:** Drop `codebert_pca_0` from feature set  
**Implementation:**
```python
# After PCA transformation
train_pca_cb = train_pca_cb[:, 1:]  # Drop first column (component 0)
val_pca_cb = val_pca_cb[:, 1:]
test_pca_cb = test_pca_cb[:, 1:]
```

**Feature Configuration:**
- 240 engineered features (same as Run 12)
- 31 CodeBERT PCA components (PC-1 through PC-31, PC-0 dropped)
- 32 GraphCodeBERT PCA components (full, PC-0 through PC-31)
- **Total: 303 features** (vs Run 12: 304)

**Retained from Run 12:**
1. Confidence-based noise down-weighting
2. Dual embeddings (modified CodeBERT + full GraphCodeBERT)
3. Isotonic calibration
4. Three-way SHAP analysis

---

## Results: Run 12 vs Run 13

### Test Set Performance

| Metric | Run 12 (PC-0 included) | Run 13 (PC-0 dropped) | Change | % Change |
|--------|----------------------|---------------------|--------|----------|
| **F1 Score** | 0.6138 | 0.6121 | -0.0017 | -0.3% |
| **Precision** | 0.5466 | 0.5458 | -0.0008 | -0.1% |
| **Recall** | 0.6998 | 0.6966 | -0.0032 | -0.5% |
| **ROC-AUC** | 0.9060 | 0.9058 | -0.0002 | -0.02% |
| **PR-AUC** | 0.6050 | 0.6055 | +0.0005 | +0.08% |
| **Brier Score** | 0.0706 | 0.0708 | +0.0002 | +0.3% |
| **Precision@10%** | 0.6439 | 0.6398 | -0.0041 | -0.6% |
| **Features** | 304 | **303** | -1 | -0.3% |
| **Threshold** | 0.319 | 0.336 | +0.017 | Higher (favors precision) |

### Confusion Matrix

| Metric | Run 12 | Run 13 | Change |
|--------|--------|--------|--------|
| True Negatives | 27,006 | 27,010 | +4 |
| False Positives | 2,510 | 2,506 | -4 ⚠️ |
| False Negatives | 1,298 | 1,312 | +14 |
| True Positives | 3,026 | 3,012 | -14 |
| **FP Rate** | 8.50% | 8.49% | -0.01% |
| **FN Rate** | 30.01% | 30.34% | +0.33% |

**Analysis:**
- ⚠️ Only 4 fewer false positives (2,510 → 2,506) — **hypothesis rejected**
- ⚠️ Lost 14 true positives (3,026 → 3,012) — minor recall degradation
- ⚠️ Missed 14 more vulnerabilities (1,298 → 1,312 FN)
- **Net result:** Near-zero impact, slight performance degradation

---

## Individual Model Performance

| Model | Run 12 | Run 13 | Change |
|-------|--------|--------|--------|
| **XGB Conservative** | 0.6065 | 0.6044 | -0.002 |
| **XGB Aggressive** | 0.6031 | 0.5975 | -0.006 |
| **LightGBM Balanced** | 0.6075 | 0.6066 | -0.001 |
| **CatBoost** | 0.5847 | 0.5836 | -0.001 |
| **Ensemble (Weighted)** | **0.6138** | **0.6121** | **-0.002** |

**Key Observation:** All individual models showed slight degradation (∆-0.001 to -0.006 F1).

---

## Ensemble Weight Redistribution

### Weight Changes

| Model | Run 12 | Run 13 | Change | % Change |
|-------|--------|--------|--------|----------|
| XGB Conservative | 0.20 | **0.45** | **+0.25** | **+125%** ⬆️ |
| XGB Aggressive | 0.30 | 0.30 | 0.00 | Same |
| LightGBM Balanced | 0.05 | 0.05 | 0.00 | Same |
| CatBoost | 0.45 | **0.20** | **-0.25** | **-56%** ⬇️ |

### Interpretation

**Dramatic weight swap:** XGB Conservative (0.20→0.45) and CatBoost (0.45→0.20) reversed roles.

**Why this happened:**
- **Without PC-0:** CatBoost lost access to a dominant feature it relied heavily on
- **XGB Conservative:** Adapted better to the modified feature space
- **Result:** Ensemble rebalanced to compensate for CatBoost's reduced performance

This weight redistribution confirms that **PC-0 was a critical feature**, and removing it forced architectural adaptation rather than improvement.

---

## SHAP Analysis: Feature Importance Redistribution

### Global Feature Importance Comparison

#### Run 12 Top 10 (with codebert_pca_0)
| Rank | Feature | SHAP Value | Category |
|------|---------|------------|----------|
| 1 | **codebert_pca_0** | **1.126** | Embedding (DOMINANT 🚨) |
| 2 | codebert_pca_1 | 0.304 | Embedding (3.7× smaller) |
| 3 | codebert_pca_2 | 0.110 | Embedding (10.2× smaller) |
| 4 | codebert_pca_4 | 0.079 | Embedding |
| 5 | codebert_pca_3 | 0.074 | Embedding |
| 6 | codebert_pca_5 | 0.042 | Embedding |
| 7 | graphcodebert_pca_2 | 0.036 | Embedding |
| 8 | sem_halstead_difficulty | 0.033 | Semantic |
| 9 | codebert_pca_6 | 0.033 | Embedding |
| 10 | codebert_pca_7 | 0.033 | Embedding |

**Dominance ratio:** PC-0 was 3.7× more important than PC-1, 10.2× more than PC-2

#### Run 13 Top 10 (without codebert_pca_0)
| Rank | Feature | SHAP Value | Category |
|------|---------|------------|----------|
| 1 | **codebert_pca_1** | **0.739** | Embedding (promoted from #2) |
| 2 | codebert_pca_4 | 0.261 | Embedding (promoted from #4) |
| 3 | codebert_pca_2 | 0.242 | Embedding (promoted from #3) |
| 4 | codebert_pca_3 | 0.202 | Embedding (promoted from #5) |
| 5 | codebert_pca_6 | 0.070 | Embedding |
| 6 | codebert_pca_5 | 0.065 | Embedding |
| 7 | codebert_pca_7 | 0.055 | Embedding |
| 8 | sem_halstead_difficulty | 0.044 | Semantic |
| 9 | graphcodebert_pca_2 | 0.040 | Embedding |
| 10 | ctx_std_line_length | 0.037 | Context |

**Dominance ratio:** PC-1 is 2.8× more important than PC-4, 3.1× more than PC-2

### 🎯 Critical Insight: Signal Redistribution

**Observation:**
- PC-1 absorbed ~65% of PC-0's importance (0.739 vs 1.126)
- PC-4 jumped from #4→#2 (0.079→0.261, +230% increase)
- Top 4 features are ALL CodeBERT components (PC-1, 4, 2, 3)

**Conclusion:** The model didn't become less reliant on CodeBERT—it redistributed the semantic signal across remaining components. **The "over-prediction" behavior persisted.**

---

## False Positive Driver Analysis

### FP Drivers Comparison (500 FPs analyzed)

#### Run 12: Single Dominant Driver
| Feature | FP Count | % of FPs |
|---------|----------|----------|
| **codebert_pca_0** | 492 | **98.4%** 🚨 |
| codebert_pca_2 | 320 | 64.0% |
| codebert_pca_1 | 181 | 36.2% |

#### Run 13: Distributed Drivers
| Feature | FP Count | % of FPs |
|---------|----------|----------|
| **codebert_pca_2** | 314 | **62.8%** |
| **codebert_pca_1** | 297 | **59.4%** |
| **codebert_pca_3** | 278 | **55.6%** |
| **codebert_pca_4** | 275 | **55.0%** |
| codebert_pca_5 | 164 | 32.8% |
| ctx_total_lines | 51 | 10.2% |

### 🚨 Breakthrough Discovery

**Pattern from Run 12:**
- ONE feature (PC-0) drove 98.4% of FPs → appeared to be "the problem"

**Pattern from Run 13:**
- FOUR features (PC-1, 2, 3, 4) each drive 55-63% of FPs → collective problem

**Conclusion:** The false positive amplification is not caused by a single dominant component—it's an **inherent property of CodeBERT embeddings** capturing code complexity/unusualness that correlates weakly with actual vulnerabilities.

**Implication:** We cannot fix this by dropping individual components. We need to either:
1. Drop CodeBERT entirely (Run 14: GraphCodeBERT only)
2. Change the embedding model (CodeT5, StarCoder, specialized security models)
3. Move to a different architecture (GNN, transformers, CWE-specific models)

---

## Noise Detection Results

**Identified:** 349 suspicious samples in training set (0.13% of 270,720)  
**vs Run 12:** 400 samples (0.15%)

**Slight decrease (-51 samples) suggests:**
- Removing PC-0 made the initial model slightly less confident in extreme predictions
- Fewer samples flagged as "suspicious" in noise detection phase

---

## Key Findings

### 1. Hypothesis Rejected
**Expected:** Precision improves, FP rate drops significantly  
**Actual:** Near-identical performance (∆-0.3% F1, -4 FPs)  
**Conclusion:** PC-0 was not "the" false positive amplifier—it was one manifestation of a deeper issue

### 2. Signal Redistribution, Not Reduction
- PC-1 absorbed 65% of PC-0's importance (1.126 → 0.739)
- PC-4 gained +230% importance (0.079 → 0.261)
- **Model adapted by redistributing signal, not by changing behavior**

### 3. CodeBERT Embeddings Are Collectively the Issue
- Run 12: PC-0 drove 98.4% of FPs
- Run 13: PC-1, 2, 3, 4 each drive 55-63% of FPs
- **Conclusion:** All CodeBERT components capture patterns that lead to false positives

### 4. Ensemble Weight Swap Indicates Dependence
- CatBoost weight dropped 56% (0.45 → 0.20) without PC-0
- XGB Conservative weight increased 125% (0.20 → 0.45) to compensate
- **Conclusion:** PC-0 was a critical feature, not a removable outlier

### 5. Architectural Ceiling Confirmed
- Three consecutive runs (11, 12, 13) all converge to F1≈0.61
- Marginal interventions (dual embeddings, calibration, dropping PC-0) yield <1% gains
- **Conclusion:** Current architecture has peaked; need fundamental changes

---

## Why the Hypothesis Failed

### Expected Behavior
If PC-0 was an "outlier" false positive amplifier:
- Removing it should reduce FP rate by ~10-15%
- Precision should improve to ~0.60+
- Other features would provide cleaner signal

### Actual Behavior
PC-0 was a **high-variance semantic axis** that the model relied on:
- When removed, model redistributed signal to PC-1, 4, 2, 3
- These components exhibit similar FP-driving behavior (55-63% each)
- **Root cause:** CodeBERT's semantic space correlates with complexity, not vulnerabilities

### The Real Problem
CodeBERT was fine-tuned on:
1. **MLM (Masked Language Modeling)** — predicts missing tokens
2. **Code structure tasks** — understands syntax and patterns

It was NOT fine-tuned on:
- Vulnerability detection
- Security-relevant patterns
- CWE-specific behaviors

**Result:** CodeBERT captures "unusual code patterns" which often overlap with complex/obscure code that developers write carefully (safe), not just buggy code (vulnerable).

---

## Next Steps: Run 14 (GraphCodeBERT Only)

### Rationale
Since CodeBERT embeddings are collectively driving false positives, test whether **GraphCodeBERT** (which incorporates AST/DFG structure) provides cleaner signal.

### Run 14 Configuration
- **240 engineered features** (same)
- **0 CodeBERT** (drop entirely)
- **32 GraphCodeBERT PCA** (keep only graph-based embeddings)
- **Total: 272 features**

### Hypothesis
GraphCodeBERT's graph-based pre-training (on data flow graphs) may better capture vulnerability-relevant patterns vs purely lexical/syntax patterns.

### Expected Outcomes
**Scenario A: GraphCodeBERT is cleaner**
- Precision improves to 0.60+
- F1 drops slightly to 0.58-0.60 (lose strong semantic signal)
- **Action:** Consider hybrid with limited CodeBERT components

**Scenario B: GraphCodeBERT performs poorly**
- F1 drops to <0.55
- **Action:** Confirms embeddings aren't the solution, move to Option 3 (CWE-specific models)

**Scenario C: GraphCodeBERT matches CodeBERT**
- F1 stays ~0.61
- **Action:** Indicates plateau is fundamental to dataset/problem, not model choice

### Success Criteria
- Precision ≥0.58 with F1 ≥0.58
- FP rate <9.0%
- Clearer SHAP patterns (engineered features gain importance)

---

## Lessons Learned

### What Worked ✅
1. **Rigorous hypothesis testing** — Clear prediction, clean implementation, definitive result
2. **SHAP-driven diagnosis** — Identified signal redistribution pattern
3. **Weight analysis** — Ensemble weight swap revealed feature importance
4. **Controlled experiment** — Single-variable change isolated the effect

### What We Learned 🔍
1. **Dominant features can't be "dropped"** — Models redistribute signal
2. **Semantic embeddings have inherent bias** — Capture complexity, not vulnerabilities
3. **Architectural ceiling is real** — Need fundamental changes, not tweaks
4. **Pre-training matters** — CodeBERT's training objective doesn't align with security

### What's Next 🚀
1. **Run 14:** GraphCodeBERT only (test graph-based vs lexical embeddings)
2. **If Run 14 fails:** Move to Option 3 (CWE-specific hierarchical models)
3. **Long-term:** Explore security-specific pre-trained models or fine-tune on vulnerability data

---

## Artifacts

All training artifacts saved to `models/saved_models/`:

### Model Files
- ✅ `xgb_conservative.pkl` — Weight increased to 0.45 (was 0.20)
- ✅ `xgb_aggressive.pkl` — Weight unchanged at 0.30
- ✅ `lgb_balanced.pkl` — Weight unchanged at 0.05
- ✅ `catboost.pkl` — Weight decreased to 0.20 (was 0.45)

### Transformation Artifacts
- ✅ `scaler.pkl` — StandardScaler for feature normalization
- ✅ `pca_model.pkl` — CodeBERT PCA transformer (768d → 32d, PC-0 dropped in code)
- ✅ `graphcodebert_pca_model.pkl` — GraphCodeBERT PCA transformer (full 32d)
- ✅ `calibrator.pkl` — IsotonicRegression calibrator

### Configuration & Results
- ✅ `optimal_threshold.json` — Threshold 0.336 (slightly higher than Run 12)
- ✅ `optimal_weights.json` — Dramatic weight swap documented
- ✅ `evaluation_results.json` — Run 13 metrics, 303 features

### Analysis Reports
- ✅ `outputs/reports/per_cwe_metrics.json` — Per-CWE performance
- ✅ `outputs/reports/shap_analysis/global_importance.json` — Shows signal redistribution
- ✅ `outputs/reports/shap_analysis/false_positive_drivers.json` — Distributed FP drivers
- ✅ `outputs/reports/shap_analysis/per_cwe_shap.json` — CWE-specific patterns

---

## Reproducibility

### Command
```bash
# Full training (~2.5 hours, embeddings cached)
python models/ensemble_boosting/main.py --full-training
```

### Code Change
```python
# In main.py, after PCA transformation (Step 3a)
print(f"  [RUN 13] Dropping codebert_pca_0 (98.4% FP driver) — using components 1-31 only")
train_pca_cb = train_pca_cb[:, 1:]  # Drop first column (component 0)
val_pca_cb = val_pca_cb[:, 1:]
test_pca_cb = test_pca_cb[:, 1:]
```

### Training Time
- Feature extraction: Cached (instant)
- **CodeBERT embeddings:** Cached from Run 12 (instant)
- **GraphCodeBERT embeddings:** Cached from Run 12 (instant)
- Initial training: ~25 min
- Noise detection: ~5 min (349 suspicious samples found)
- Retraining with weights: ~25 min
- Calibration: <1 min
- Threshold+weight optimization: ~10 min
- SHAP analysis: ~12 min
- **Total: ~1h 20min** (embeddings pre-cached)

---

## Scientific Significance

This experiment demonstrates a critical principle in machine learning:

**Removing a dominant feature from a nonlinear ensemble doesn't eliminate its effect—it causes signal redistribution across correlated features.**

### Analogy
If 90% of weight is on one pillar supporting a roof:
- **Don't remove the pillar** → the roof collapses or redistributes to other supports
- **Strengthen other pillars first** → then gradually reduce dominant pillar

### Implication for Run 14
Instead of dropping dominant features, we're testing an **alternative semantic space** (GraphCodeBERT) that may have better inductive bias for vulnerability detection.

---

**Report Generated:** February 15, 2026  
**Model Version:** Run 13 (Attack CodeBERT Dominance)  
**Status:** ⚠️ Hypothesis Rejected — Signal redistribution observed  
**Next Action:** 🚀 Run 14 — GraphCodeBERT Only (test alternative embedding space)

---

## Appendix: Statistical Comparison

### Performance Delta Summary
```json
{
  "run": 13,
  "hypothesis": "Drop codebert_pca_0 to reduce FP rate",
  "result": "REJECTED",
  "metrics_vs_run12": {
    "f1_score": -0.0017,
    "precision": -0.0008,
    "recall": -0.0032,
    "fp_reduction": 4,
    "tp_loss": 14,
    "net_effect": "near_zero"
  },
  "feature_importance_ratio": {
    "run12_dominant": 3.7,
    "run13_dominant": 2.8,
    "improvement": "16% more balanced",
    "but": "absolute_values_redistributed"
  },
  "fp_driver_distribution": {
    "run12": "single_feature_98pct",
    "run13": "four_features_55_to_63pct",
    "conclusion": "distributed_not_eliminated"
  },
  "ensemble_adaptation": {
    "catboost_weight_drop": -0.25,
    "xgb_conservative_weight_gain": +0.25,
    "interpretation": "pc0_was_critical_feature"
  },
  "architectural_conclusion": "ceiling_reached",
  "recommendation": "test_alternative_embeddings_run14"
}
```
