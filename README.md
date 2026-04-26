# LLM-VUL — C/C++ Vulnerability Detection Platform

AI-powered vulnerability detection for C/C++ code using a hybrid pipeline of static analysis tools and machine learning models (gradient boosting ensemble + QLoRA CodeBERT).

---

## System Architecture

```
GitHub Repo URL
      │
      ▼
┌─────────────────────────────────────┐
│  FastAPI Backend  (src/api/main.py)  │
│  POST /api/analyze/github            │
│  Background job → polling            │
└──────────────┬──────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│                   CombinedAnalyzer                        │
│  (src/pipeline/combined_analyzer.py)                     │
│                                                          │
│  Phase 1: StaticAnalyzer (always runs)                   │
│    ├── CppCheck  — memory safety, buffer overflows       │
│    ├── Flawfinder — dangerous function calls             │
│    └── Semgrep   — pattern matching rules                │
│                                                          │
│  Phase 2: ML model (user-selectable)                     │
│    ├── Run12 Ensemble  (XGBoost + LightGBM + CatBoost)   │
│    └── LoRA CodeBERT   (QLoRA fine-tuned adapter)        │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────┐
│  React + Vite Frontend       │
│  Separate tabs for static    │
│  and ML results              │
└─────────────────────────────┘
```

Static and ML results are kept **independent** — never merged or OR'd together. Each shows its own findings with its own confidence scores so you can assess them separately.

---

## Models

### Model 1 — Run 12 Gradient Boosting Ensemble

Four gradient boosting models trained on a **304-dimensional feature vector**:

- 240 hand-engineered features (code complexity, control flow, dangerous function counts, cyclomatic complexity, pointer arithmetic)
- 32 CodeBERT PCA features (768-dim → 32-dim)
- 32 GraphCodeBERT PCA features (768-dim → 32-dim)

| Sub-model            | Weight | Characteristic               |
| -------------------- | ------ | ---------------------------- |
| XGBoost Conservative | 15%    | High recall focus            |
| XGBoost Aggressive   | 40%    | Balanced precision/recall    |
| LightGBM Balanced    | 30%    | Speed + balance              |
| CatBoost             | 15%    | Handles categorical features |

**Production threshold**: 0.308 (tuned for recall)

**Performance (Run 15, ~33,840 test samples)**:

| Metric    | Score  |
| --------- | ------ |
| F1        | 0.6079 |
| Precision | 52.9%  |
| Recall    | 71.5%  |
| ROC-AUC   | 0.9050 |

### Model 2 — QLoRA CodeBERT Adapter

Parameter-efficient fine-tuning of `microsoft/codebert-base` using LoRA with 4-bit NF4 quantization. Only 1.77M parameters trained (1.4% of 126M).

**Configuration**: `r=16`, `alpha=32`, target modules: `query, key, value, attention.output.dense` across all 12 layers. Trained with Focal Loss (`gamma=2.0`, `alpha=0.75`).

**Production threshold**: 0.55 (security mode: 0.30)

**Performance (validation set, 34,233 samples)**:

| Metric    | Score            |
| --------- | ---------------- |
| F1        | **0.7526** |
| Precision | 64.1%            |
| Recall    | **91.1%**  |
| ROC-AUC   | 0.8663           |

Functions longer than 512 tokens are processed with overlapping sliding windows (stride=256); the **maximum probability** across windows is used (conservative security policy).

### Model Comparison

| Model                    | F1               | Precision       | Recall          | ROC-AUC          |
| ------------------------ | ---------------- | --------------- | --------------- | ---------------- |
| Run 12 Ensemble          | 0.6143           | 55.1%           | 69.4%           | 0.9060           |
| Run 15 Ensemble          | 0.6079           | 52.9%           | 71.5%           | 0.9050           |
| Run 16 Gated Ensemble    | 0.5895           | 58.9%           | 59.0%           | 0.8978           |
| **QLoRA CodeBERT** | **0.7526** | **64.1%** | **91.1%** | **0.8663** |

**QLoRA is the strongest model** — best F1 and recall. The ensemble is faster at inference and does not require a GPU.

---

## Dataset

Training data is a combined normalised dataset from three sources:

| Dataset         | Samples           | Notes                                                            |
| --------------- | ----------------- | ---------------------------------------------------------------- |
| DiverseVul      | 330,491           | Real CVE-fixed commits                                           |
| MegaVul         | 353,873           | Cross-project function-level labels                              |
| Devign          | 27,318            | Widely-used benchmark                                            |
| Zenodo          | 7,131             | **Excluded from ensemble training** — noisy single-liners |
| **Total** | **718,813** | Combined in `data/c_normalised.jsonl` (904 MB)                 |

**Class distribution**: 92.1% safe (662,302) vs 7.9% vulnerable (56,511) — 11.7:1 ratio.

**Language focus**: 99.7% C, 0.3% C++.

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

### Download

The full dataset is available on Google Drive:

> **Dataset link**: *(coming soon — will be updated with Google Drive link)*

## Setup

### Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- CUDA 12.4 (required for LoRA model on Windows — bitsandbytes dependency)
- CppCheck installed and on PATH (static analysis)
- Semgrep installed and on PATH (static analysis)

### Backend

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

Start the API server:

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

- Health check: http://localhost:8000/health
- API docs (Swagger): http://localhost:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

App runs at http://localhost:5173

---

## API Reference

| Endpoint                          | Method | Description                           |
| --------------------------------- | ------ | ------------------------------------- |
| `/health`                       | GET    | Liveness check                        |
| `/api/analyze/github`           | POST   | Submit repo URL — returns `job_id` |
| `/api/analyze/status/{job_id}`  | GET    | Poll job progress (0–100%)           |
| `/api/analyze/logs/{job_id}`    | GET    | Stream pipeline log entries           |
| `/api/analyze/results/{job_id}` | GET    | Retrieve full results when completed  |

### Request

```json
{
  "repo_url": "https://github.com/org/repo",
  "max_files": 1000,
  "confidence_threshold": 0.308,
  "ml_model": "ensemble"
}
```

`ml_model` accepts `"ensemble"` (Run 12, fast, no GPU) or `"lora"` (QLoRA CodeBERT, best accuracy, needs GPU for reasonable speed).

### Quick smoke test

```bash
# Ensemble scan
curl -X POST http://localhost:8000/api/analyze/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/curl/curl","max_files":5,"ml_model":"ensemble"}'

# LoRA scan (first run ~30s slower — model loading)
curl -X POST http://localhost:8000/api/analyze/github \
  -H "Content-Type: application/json" \
  -d '{"repo_url":"https://github.com/curl/curl","max_files":5,"ml_model":"lora","confidence_threshold":0.55}'
```

---

## Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Specific test modules
python -m pytest tests/test_api.py -v
python -m pytest tests/test_static_analysis.py -v
python -m pytest tests/test_ingestion.py -v
python -m pytest tests/test_combined_analyzer.py -v
python -m pytest tests/test_code_parser.py -v

# Model tests (skip automatically if models/ not present)
python -m pytest tests/test_ensemble_predictor.py -v
python -m pytest tests/test_lora_predictor.py -v
```

Tests for the ensemble and LoRA predictors are automatically skipped when model files are not present — no models are required to run the full test suite.

---

## Known Limitations

| Limitation             | Details                                                                   |
| ---------------------- | ------------------------------------------------------------------------- |
| Language coverage      | Trained on 99.7% C — may generalise poorly to C++                        |
| Ensemble precision     | ~53–57% precision — roughly half of ML flags are false positives        |
| LoRA precision         | 64.1% — better but ~35% false positive rate                              |
| Static tool dependency | CppCheck, Flawfinder, Semgrep must be installed separately                |
| Long functions         | Sliding window can over-flag due to max aggregation                       |
| LoRA VRAM              | Runs in fp32 at inference — requires more VRAM than training             |
| Single-label only      | Binary classification — no multi-label CWE prediction                    |
| Dataset bias           | Open-source C projects — may not generalise to embedded/proprietary code |

---

## License

MIT License
