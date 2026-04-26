# LLM-VUL — Project Review Document

> **Purpose**: Comprehensive technical review of the LLM-VUL vulnerability detection system — what was built, how it works, all trained models, their architectures, results, and how everything fits together.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [System Architecture](#2-system-architecture)
3. [Dataset Pipeline](#3-dataset-pipeline)
4. [Model 1 — CodeBERT Full Fine-Tune](#4-model-1--codebert-full-fine-tune)
5. [Model 2 — Run 12 Gradient Boosting Ensemble](#5-model-2--run-12-gradient-boosting-ensemble)
6. [Model 3 — QLoRA CodeBERT Adapter](#6-model-3--qlora-codebert-adapter)
7. [Ensemble Run History](#7-ensemble-run-history)
8. [Production Pipeline (CombinedAnalyzer)](#8-production-pipeline-combinedanalyzer)
9. [API Layer](#9-api-layer)
10. [Frontend](#10-frontend)
11. [Metrics Comparison Table](#11-metrics-comparison-table)
12. [Key Design Decisions](#12-key-design-decisions)
13. [Known Limitations](#13-known-limitations)
14. [How to Run](#14-how-to-run)

---

## 1. Project Overview

LLM-VUL is a C/C++ vulnerability detection platform that combines:

- **Static analysis tools** (CppCheck, Flawfinder, Semgrep) — rule-based, finds known patterns
- **ML ensemble model** (XGBoost + LightGBM + CatBoost on 304 engineered features + embeddings)
- **QLoRA-fine-tuned CodeBERT** (deep-learning model, processes raw code tokens)

Users point the system at a GitHub repository URL. The system clones it, extracts all C/C++ functions, runs both static and ML analysis in parallel, and presents separate results for each detector through a React frontend.

**Language focus**: C (99.7% of training data) and C++ (0.3%).

---

## 2. System Architecture

```
GitHub Repo URL
      │
      ▼
┌─────────────────────────────────────┐
│  FastAPI Backend  (src/api/main.py)  │
│  POST /api/analyze/github            │
│  Background task → job polling       │
└──────────────┬──────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│                   CombinedAnalyzer                        │
│  (src/pipeline/combined_analyzer.py)                     │
│                                                          │
│  Phase 1: StaticAnalyzer                                 │
│    ├── CppCheck  (memory safety, buffer overflows)       │
│    ├── Flawfinder (dangerous function calls)             │
│    └── Semgrep   (pattern matching rules)                │
│                                                          │
│  Phase 2 (user-selected one of):                         │
│    ├── Run12Predictor  (ensemble, 304 features)          │
│    └── LoRAPredictor   (QLoRA CodeBERT adapter)          │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────┐
│  React + Vite Frontend       │
│  (frontend/ directory)       │
│  Shows static_results and    │
│  ml_results independently    │
└─────────────────────────────┘
```

**Key design choices:**

- Static analysis and ML results are **independent** — never merged or OR'd together in the current production code. Each shows its own findings with its own confidence scores.
- ML model is **user-selectable at scan time** via `ml_model: "ensemble" | "lora"` in the API request.
- Both ML models are **lazy-loaded** — neither loads until the first scan request, keeping startup fast.

---

## 3. Dataset Pipeline

### Sources

| Dataset         | Samples           | Notes                                                 |
| --------------- | ----------------- | ----------------------------------------------------- |
| DiverseVul      | 330,491           | Largest source — real CVE-fixed commits              |
| MegaVul         | 353,873           | Cross-project function-level labels                   |
| Devign          | 27,318            | Widely-used benchmark, Facebook/Devign paper          |
| Zenodo          | 7,131             | **Excluded from Run 12** — noisy single-liners |
| **Total** | **718,813** | Combined in `data/c_normalised.jsonl` (904 MB)      |

### Unified Schema (JSONL)

```json
{
  "id": "...",
  "dataset": "diversevul",
  "language": "c",
  "code": "void foo() { ... }",
  "label_binary": 0,
  "label_cwe": "CWE-119",
  "label_cve": "CVE-2021-..."
}
```

### Class Imbalance

| Class           | Count   | Percentage         |
| --------------- | ------- | ------------------ |
| Safe (0)        | 662,302 | 92.1%              |
| Vulnerable (1)  | 56,511  | 7.9%               |
| **Ratio** |         | **11.7 : 1** |

This imbalance is addressed differently by each model — see individual model sections.

### Pre-computed Embeddings

Both CodeBERT (768-dim → 32-dim PCA) and GraphCodeBERT (768-dim → 32-dim PCA) embeddings were pre-computed and cached in `data/processed/` to avoid recomputing during ensemble training. These files are large (~831 MB training split each).

---

## 4. Model 1 — CodeBERT Full Fine-Tune

### What it is

Standard full fine-tuning of `microsoft/codebert-base` (125M parameters) for binary vulnerability classification. **All 125M parameters** are updated during training.

### Training Configuration

| Parameter        | Value                                |
| ---------------- | ------------------------------------ |
| Base model       | `microsoft/codebert-base`          |
| Max token length | 256 tokens (covers 90.9% of samples) |
| Batch size       | 48                                   |
| Learning rate    | 2e-5                                 |
| Epochs           | 1 (based on saved summary)           |
| Warmup steps     | 300                                  |
| Optimizer        | AdamW                                |
| Mixed precision  | fp16                                 |
| Loss function    | Weighted CrossEntropyLoss            |
| Train samples    | 575,050                              |
| Val samples      | 71,881                               |
| Test samples     | 71,882                               |

### Class Imbalance Handling

- **WeightedRandomSampler** ensures each batch is balanced
- **Class weights in loss**: `safe_weight = 0.0786`, `vulnerable_weight = 0.3685`
- 2.5x reduction factor applied to prevent overly aggressive vulnerable predictions

### Artifacts

Located in `models/codebert_final/` and checkpoints in `models/codebert_checkpoint/`:

- `model.safetensors` — full fine-tuned weights
- `tokenizer.json`, `tokenizer_config.json` — tokenizer
- `training_summary.json` — hyperparameters and training loss (0.3491)
- Checkpoint at step 10,000 and final step 11,981

### Note

The full fine-tuned CodeBERT model's evaluation metrics from the current training_summary.json do not include F1/recall/precision — only training loss is recorded. The ensemble predictor uses **pre-computed CodeBERT embeddings** (not this fine-tuned model directly) as 32 PCA features in the 304-feature vector.

---

## 5. Model 2 — Run 12 Gradient Boosting Ensemble

### What it is

An ensemble of four gradient boosting models trained on a 304-dimensional feature vector that combines:

- **240 hand-engineered features** — code complexity, control flow, dangerous function counts, cyclomatic complexity, pointer arithmetic patterns, etc.
- **32 CodeBERT PCA features** — 768-dim CodeBERT embeddings compressed via PCA
- **32 GraphCodeBERT PCA features** — 768-dim GraphCodeBERT embeddings compressed via PCA

### Architecture — Four Models

| Model                | Key Config                                             | Characteristic                    |
| -------------------- | ------------------------------------------------------ | --------------------------------- |
| XGBoost Conservative | `max_depth=6`, `lr=0.02`, `scale_pos_weight=3.0` | High recall focus                 |
| XGBoost Aggressive   | `max_depth=10`, `lr=0.03`                          | High precision focus              |
| LightGBM Balanced    | `255 leaves`, `lr=0.02`                            | Speed + balanced trade-off        |
| CatBoost             | `depth=8`, `lr=0.03`                               | Handles categorical features well |

### Run 12 Data Config

- **Excludes zenodo** dataset (identified as low-quality single-line samples)
- Minimum code quality thresholds: 50 characters, 3 lines per sample
- **7:1 undersampling ratio** (safe:vulnerable) to address 18:1 raw imbalance

### Run 12 Optimal Weights (Production)

```
Stage 1 (recall-optimized): CatBoost=50%, LightGBM=20%, XGB-Agg=15%, XGB-Con=15%
Stage 2 (precision-optimized): LightGBM=40%, XGB-Agg=30%, XGB-Con=20%, CatBoost=10%
Threshold: 0.308
```

### Performance — Run 12 Full Dataset (from run15 non-test-mode)

| Metric              | Ensemble | XGB Conservative | XGB Aggressive | LightGBM | CatBoost |
| ------------------- | -------- | ---------------- | -------------- | -------- | -------- |
| **F1**        | 0.6079   | 0.6054           | 0.5999         | 0.6079   | 0.5651   |
| **Precision** | 0.5289   | 0.5122           | 0.5963         | 0.5194   | 0.4367   |
| **Recall**    | 0.7146   | 0.7401           | 0.6036         | 0.7327   | 0.8004   |
| **ROC-AUC**   | 0.9050   | —               | —             | —       | —       |

### Performance — Run 16 (Two-Stage Gated Ensemble)

Run 16 introduced a **two-stage gated architecture**:

- **Stage 1** (recall-optimized): catches as many vulnerabilities as possible
- **Stage 2** (precision-optimized): refines borderline cases
- **Gating thresholds**: T1=0.4, T2=0.2

| Metric              | Stage 1 Standalone | Stage 2 Standalone | Gated Ensemble |
| ------------------- | ------------------ | ------------------ | -------------- |
| **F1**        | 0.6139             | 0.5576             | 0.5895         |
| **Precision** | 0.5706             | 0.5172             | 0.5892         |
| **Recall**    | 0.6642             | 0.6048             | 0.5897         |
| **ROC-AUC**   | 0.9051             | 0.8644             | 0.8978         |
| FPR                 | 7.3%               | 8.3%               | 6.0%           |
| FNR                 | 33.6%              | 39.5%              | 41.0%          |

**Confusion Matrix (Run 16 Gated Ensemble on ~33,840 samples)**:

```
              Predicted Safe    Predicted Vuln
Actual Safe       27,738            1,778
Actual Vuln        1,774            2,550
```

### Trained Artifacts

Located in `models/saved_models/` (current) with archives for runs 12, 14, 15, 16:

- `xgb_conservative.pkl` (~13-30 MB depending on run)
- `xgb_aggressive.pkl`
- `lgb_balanced.pkl`
- `catboost.pkl`
- `pca_model.pkl` — CodeBERT 768→32 PCA
- `graphcodebert_pca_model.pkl` — GraphCodeBERT 768→32 PCA
- `scaler.pkl` — feature normalization
- `calibrator.pkl` — probability calibration
- `optimal_threshold.json` — best decision threshold
- `optimal_weights.json` — ensemble model weights
- `meta_model.pkl` — stacking meta-learner (Run 16+)

### Early Results (Run 1 baseline, 100-sample test)

| Metric    | Ensemble | XGB Conservative | CatBoost         |
| --------- | -------- | ---------------- | ---------------- |
| F1        | 0.6715   | **0.6861** | 0.6800           |
| Precision | 0.5349   | 0.5465           | 0.5152           |
| Recall    | 0.9020   | 0.9216           | **1.0000** |
| ROC-AUC   | 0.5630   | —               | —               |

---

## 6. Model 3 — QLoRA CodeBERT Adapter

### What it is

Parameter-efficient fine-tuning of `microsoft/codebert-base` using **LoRA (Low-Rank Adaptation)** with **4-bit NF4 quantization (QLoRA)**. Only 1.4% of parameters are trained — the LoRA adapter weights — while the base model is frozen in 4-bit.

### Why QLoRA

| Aspect              | Full Fine-Tune (Model 1) | QLoRA (Model 3)       |
| ------------------- | ------------------------ | --------------------- |
| Trainable params    | 125M (100%)              | 1.77M (1.4%)          |
| VRAM required       | ~18 GB                   | ~6 GB (RTX 4050)      |
| Training time       | Many hours               | ~18 hours on RTX 4050 |
| Max token length    | 256                      | 512                   |
| Inference quantized | No                       | No (full precision)   |

### LoRA Configuration

```
Base model:   microsoft/codebert-base
LoRA rank:    r = 16
LoRA alpha:   32 (scale = alpha/r = 2.0)
LoRA dropout: 0.05
Target modules: query, key, value, attention.output.dense
                (across all 12 RoBERTa layers)
Total LoRA pairs: 72
Trainable parameters: ~1,771,778 (1.40% of 126M)
```

**Important note**: `attention.output.dense` is used instead of just `"dense"` to avoid matching `classifier.dense`, which would cause a bitsandbytes 4-bit quantization assertion error at runtime.

### 4-bit Quantization Config

```
Quantization type:  NF4 (Normal Float 4 — optimal for Gaussian weight distributions)
Double quantization: Yes (saves ~0.4 GB extra VRAM)
Compute dtype:      bfloat16 (stable on Ampere/RTX 4050; fp16 causes NaN with QLoRA)
Classifier head:    EXCLUDED from quantization (stays in fp32)
```

### Training Hyperparameters

| Parameter                      | Value                                                      |
| ------------------------------ | ---------------------------------------------------------- |
| Batch size per device          | 4                                                          |
| Gradient accumulation          | 16 steps                                                   |
| **Effective batch size** | **64**                                               |
| Learning rate                  | 2e-4 (higher than full fine-tune — LoRA starts from zero) |
| Epochs                         | 5                                                          |
| LR scheduler                   | Cosine with 6% warmup                                      |
| Optimizer                      | Paged AdamW 8-bit                                          |
| Gradient checkpointing         | Yes (~40% VRAM savings)                                    |
| Total training steps           | 21,400                                                     |
| Total training time            | ~18 hours                                                  |

### Loss Function — Focal Loss

Standard cross-entropy ignores easy examples. Focal loss concentrates training on hard/uncertain cases:

```
FL(p_t) = -alpha_t × (1 - p_t)^gamma × log(p_t)

gamma = 2.0   (standard value — focuses on hard examples)
alpha = 0.75  (weights the VULNERABLE / positive class)
              [Note: inverted from RetinaNet's 0.25 because vulnerable is our minority class]
```

NaN guards: probability clamped to `[1e-7, 1-1e-7]` before log.

### Training Modes

| Mode       | Data             | Epochs | Purpose                                         |
| ---------- | ---------------- | ------ | ----------------------------------------------- |
| Validation | 10% (stratified) | 2      | Smoke test — verify pipeline and VRAM          |
| Full       | 100%             | 5      | Baseline training                               |
| Tuning     | 100%             | 3      | Iterative improvement based on confusion matrix |

Training uses `data/lora/train_dataset`, `val_dataset`, `test_dataset` (Arrow format, pre-split).

### Training Results (Actual Run)

| Metric           | Value            |
| ---------------- | ---------------- |
| F1 Score         | **0.7526** |
| Precision        | 0.641            |
| Recall           | **0.9113** |
| ROC-AUC          | 0.8663           |
| Val samples      | 34,233           |
| Training samples | 273,860          |
| Steps            | 21,400           |

**Confusion matrix (validation set)**:

```
              Predicted Safe    Predicted Vuln
Actual Safe       ?                 ?
Actual Vuln    1,281 (FN)       13,163 (TP)
```

Only 1,281 out of 14,444 vulnerable samples were missed.

### Threshold Analysis

The model outputs a probability. The threshold determines safe/vulnerable classification.

| Threshold      | F1               | Precision        | Recall           | Use Case                                         |
| -------------- | ---------------- | ---------------- | ---------------- | ------------------------------------------------ |
| **0.55** | **0.7528** | **0.6544** | **0.8861** | **Optimal F1 (production default)**        |
| 0.30           | ~0.62            | 0.4807           | 0.9943           | Security-critical (miss only 83 vulnerabilities) |
| 0.70           | Lower            | Higher           | Lower            | Precision-focused                                |

The saved `models/lora_adapter/threshold.json` stores the default = **0.55**.

At threshold 0.30: catches 14,361/14,444 vulnerable samples (only 83 missed) but generates 15,512 false positives.

### Sliding Window Inference

Functions longer than 512 tokens are processed in overlapping windows:

- Window size: 512 tokens
- Stride: 256 tokens (50% overlap)
- Aggregation: **maximum probability** across all windows

"Max" aggregation = conservative security policy: if ANY window looks vulnerable, the whole function is flagged.

### Inference Pipeline

File: `src/pipeline/lora_predictor.py`

```python
predictor = LoRAPredictor()
result = predictor.predict(code_string)
# Returns: {"is_vulnerable": bool, "confidence": float, "model": "lora"}
```

At inference: base model loaded in **full precision** (no 4-bit) with LoRA adapter weights attached via `PeftModel`. This means inference is accurate but requires more VRAM than training.

**Preprocessing** (must match training):

1. Strip single-line comments (`//`)
2. Strip multi-line comments (`/* */`)
3. Normalize whitespace

### Artifacts

Located in `models/lora_adapter/`:

- `adapter_config.json` — LoRA configuration
- `adapter_model.bin` — LoRA adapter weights (~28 MB)
- `training_summary.json` — training metrics and config
- `threshold.json` — `{"threshold": 0.55}`

---

## 7. Ensemble Run History

| Run | Architecture    | Key Change                                               | F1     | ROC-AUC |
| --- | --------------- | -------------------------------------------------------- | ------ | ------- |
| 1   | Basic ensemble  | Initial baseline (100-sample test)                       | 0.6715 | 0.5630  |
| 10  | 304-feature     | PCA embeddings added; full 768-dim showed no improvement | —     | —      |
| 12  | 304-feature     | Excluded zenodo, 7:1 undersampling, calibration          | ~0.614 | ~0.906  |
| 14  | 304-feature     | Quality thresholds + noise detection                     | stored | 0.8644  |
| 15  | 304-feature     | CodeBERT scaling factor 0.6; noise detection             | 0.6079 | 0.9050  |
| 16  | Two-stage gated | Stage 1 recall / Stage 2 precision gating                | 0.5895 | 0.8978  |

The **current production predictor** (`Run12Predictor`) loads from `models/saved_models/` which holds the most recently trained artifacts (currently pointing to run 16 architecture files).

---

## 8. Production Pipeline (CombinedAnalyzer)

File: `src/pipeline/combined_analyzer.py`

### Phase 1 — Static Analysis (always runs)

Calls `StaticAnalyzer.analyze_batch()` which runs CppCheck, Flawfinder, and Semgrep on each function. Extracts CWE IDs from findings. Returns per-function:

- `static_vulnerable: bool`
- `static_confidence: float`
- `static_findings: List[{tool, message, severity, cwe_id, cwe_name}]`
- `cwe_types: List[str]`

### Phase 2 — ML Analysis (user-selected)

**Option A: Ensemble (`ml_model="ensemble"`)**

- Loads `Run12Predictor` (lazy, once per server lifetime)
- Extracts 304 features per function
- Runs 4 models + calibration + threshold
- Default threshold: 0.308

**Option B: LoRA (`ml_model="lora"`)**

- Loads `LoRAPredictor` (lazy, ~15-30s first time)
- Preprocesses code, tokenizes, runs CodeBERT + LoRA adapter
- Default threshold: 0.55

### Severity Mapping

Both paths map confidence to severity:

| Confidence Range                    | Severity |
| ----------------------------------- | -------- |
| ≥ 0.85                             | CRITICAL |
| ≥ 0.65 (ensemble) / ≥ 0.65 (LoRA) | HIGH     |
| ≥ 0.40 (ensemble) / ≥ 0.45 (LoRA) | MEDIUM   |
| Below                               | LOW      |

---

## 9. API Layer

File: `src/api/main.py`

| Endpoint                          | Method | Description                                        |
| --------------------------------- | ------ | -------------------------------------------------- |
| `/health`                       | GET    | Liveness check                                     |
| `/api/analyze/github`           | POST   | Submit repo URL for analysis — returns `job_id` |
| `/api/analyze/status/{job_id}`  | GET    | Poll job progress (0-100%)                         |
| `/api/analyze/logs/{job_id}`    | GET    | Stream pipeline log entries                        |
| `/api/analyze/results/{job_id}` | GET    | Retrieve full results when job is `completed`    |

### Request Schema

```json
{
  "repo_url": "https://github.com/org/repo",
  "max_files": 1000,
  "confidence_threshold": 0.308,
  "ml_model": "ensemble"   // or "lora"
}
```

### Response Schema (results endpoint)

```json
{
  "job_id": "...",
  "status": "completed",
  "ml_model_used": "ensemble",
  "static_summary": { "total_functions", "vulnerable", "safe", "tool_counts", "cwe_frequency" },
  "ml_summary": { "total_functions", "vulnerable", "safe", "critical_count", "high_count", "medium_count", "low_count", "avg_ml_confidence" },
  "lora_summary": { ... },   // present only if ml_model="lora"
  "static_results": [...],   // per-function static findings
  "ml_results": [...],       // per-function ML predictions
  "report": { ... }
}
```

---

## 10. Frontend

Stack: **React + TypeScript + Vite + Tailwind CSS**

Located in `frontend/`

### Features

- Submit GitHub repository URL
- Choose ML model (Ensemble or LoRA) before scanning
- Real-time job progress polling
- **Separate tabs** for Static Analysis results and ML results — results are never merged
- Per-function details with code snippets, severity badges, CWE types
- Summary cards with counts (total, vulnerable, safe, severity breakdown)
- Virtualized result lists for large codebases

---

## 11. Metrics Comparison Table

| Model                          | F1               | Precision       | Recall           | ROC-AUC          | Notes                                 |
| ------------------------------ | ---------------- | --------------- | ---------------- | ---------------- | ------------------------------------- |
| Run 1 Ensemble (baseline)      | 0.6715           | 0.5349          | 0.9020           | 0.5630           | 100-sample test — small n            |
| Run 12 Ensemble (full dataset) | 0.6143           | 0.5466          | 0.6940           | 0.9060           | Production model, cited in old app.py |
| Run 15 Ensemble                | 0.6079           | 0.5289          | 0.7146           | 0.9050           | 33,840 sample eval                    |
| Run 16 Gated Ensemble          | 0.5895           | 0.5892          | 0.5897           | 0.8978           | Two-stage architecture                |
| **QLoRA CodeBERT**       | **0.7526** | **0.641** | **0.9113** | **0.8663** | **Best F1 and recall**          |

**QLoRA is the strongest model** with the highest F1 (0.7526) and recall (91.1%), though it is slower at inference and has moderate precision (64.1%).

---

## 12. Key Design Decisions

### Independent Results (not merged)

Static and ML results are shown separately. Previous architecture merged them with OR logic and boosted confidence when both agreed. The current architecture avoids this so users can independently assess static tool findings vs ML findings. This prevents false escalation and gives better diagnostic information.

### Lazy Model Loading

Neither the ensemble nor LoRA predictor loads at server startup. They load on first use. This means:

- Fast API startup
- LoRA first scan takes ~15-30s extra while adapter loads
- Memory: only the model that was actually requested is loaded

### LoRA over Full Fine-Tune (Memory Efficiency)

Full fine-tuning CodeBERT requires ~18 GB VRAM. QLoRA fits in 6 GB (RTX 4050) by quantizing frozen base weights to 4-bit and training only 1.77M adapter parameters. Achieves better results than the ensemble on validation data.

### Focal Loss over Weighted Cross-Entropy

The 11.7:1 class imbalance means standard cross-entropy focuses too heavily on easy "safe" examples. Focal loss (gamma=2.0) down-weights confident easy examples and forces the model to learn from hard/uncertain ones. Combined with alpha=0.75 weighting the vulnerable class.

### Max Aggregation for Sliding Windows

When a function exceeds 512 tokens, it is split into overlapping windows. The **maximum** vulnerability probability across windows is used (not average, not voting). This is the conservative security choice: any window looking risky flags the whole function. Average would dilute the signal.

### Zenodo Dataset Excluded from Ensemble Training

The zenodo dataset (7,131 samples) was found to consist mostly of single-line, low-quality, all-vulnerable samples that degraded model generalization. It is excluded from Run 12+ ensemble training but remains in the raw normalized dataset.

### Threshold Optimization

Both models have tuned thresholds rather than using the default 0.5:

- **Ensemble**: 0.308 (lower threshold → higher recall)
- **LoRA**: 0.55 (higher than default → better F1 balance; security mode at 0.30)

---

## 13. Known Limitations

| Limitation                         | Details                                                                                              |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **Language coverage**        | Trained on 99.7% C code — may generalize poorly to C++                                              |
| **Ensemble precision**       | ~52-57% precision means roughly half of ML-flagged functions are false positives                     |
| **LoRA precision**           | 64.1% precision — better but still ~35% false positive rate                                         |
| **Static tool availability** | CppCheck, Flawfinder, Semgrep must be separately installed and on PATH                               |
| **Long functions**           | Sliding window handles >512-token functions but max aggregation can over-flag                        |
| **Inference VRAM**           | LoRA runs in full fp32 at inference — requires more VRAM than training                              |
| **Single-label**             | Binary classification (safe/vulnerable) only — no multi-label CWE prediction                        |
| **Dataset bias**             | Training data from open-source C projects; may not generalize to embedded or proprietary code styles |
| **No CVE linkage**           | Model does not directly predict CVE IDs, only binary label + CWE from static tools                   |

---

## 14. How to Run

### Prerequisites

- Python 3.10+ with `venv` at `./venv/`
- Node.js 18+ and npm
- CUDA 12.4 (required for bitsandbytes on Windows — LoRA model)
- CppCheck, Semgrep installed and on PATH
- Models at `models/saved_models/` (ensemble) and `models/lora_adapter/` (LoRA)

### Start Backend

```bash
venv/Scripts/uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

- Health check: http://localhost:8000/health
- API docs: http://localhost:8000/docs

### Start Frontend

```bash
cd frontend
npm install     # first time only
npm run dev
```

- App: http://localhost:5173

### Quick Smoke Test

```bash
# Ensemble scan (faster, no GPU warmup)
curl -X POST http://localhost:8000/api/analyze/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/curl/curl","max_files":5,"confidence_threshold":0.308,"ml_model":"ensemble"}'

# LoRA scan (first run ~30s slower)
curl -X POST http://localhost:8000/api/analyze/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/curl/curl","max_files":5,"confidence_threshold":0.55,"ml_model":"lora"}'
```

### Key File Locations

| File                                    | Purpose                               |
| --------------------------------------- | ------------------------------------- |
| `src/api/main.py`                     | FastAPI entrypoint, all endpoints     |
| `src/pipeline/combined_analyzer.py`   | Orchestrates static + ML analysis     |
| `src/pipeline/run12_predictor.py`     | Ensemble model inference wrapper      |
| `src/pipeline/lora_predictor.py`      | LoRA CodeBERT inference wrapper       |
| `src/train/lora_config.py`            | All QLoRA hyperparameters             |
| `src/train/train_lora.py`             | QLoRA training script                 |
| `src/train/evaluate_lora.py`          | Threshold optimization and evaluation |
| `models/ensemble_boosting/train.py`   | Ensemble training script              |
| `models/ensemble_boosting/RESULTS.md` | Ensemble run results                  |
| `models/saved_models/`                | Production ensemble artifacts         |
| `models/lora_adapter/`                | LoRA adapter weights + threshold      |
| `models/codebert_final/`              | Full fine-tuned CodeBERT              |
| `data/c_normalised.jsonl`             | Combined normalized dataset (904 MB)  |

---

*Document generated April 2026. Reflects the system state at the end of the LoRA integration phase.*
