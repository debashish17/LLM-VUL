<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stars][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

<!-- PROJECT LOGO / HEADER -->
<br />
<div align="center">
  <h1 align="center">LLM-VUL</h1>

  <p align="center">
    AI-powered C/C++ vulnerability detection — hybrid static analysis + ML pipeline
    <br />
    <a href="#system-architecture"><strong>Explore the architecture »</strong></a>
    <br />
    <br />
    <a href="#getting-started">Quick Start</a>
    &middot;
    <a href="#api-reference">API Docs</a>
    &middot;
    <a href="https://github.com/debashish17/LLM-VUL/issues/new?labels=bug">Report Bug</a>
    &middot;
    <a href="https://github.com/debashish17/LLM-VUL/issues/new?labels=enhancement">Request Feature</a>
  </p>
</div>

---

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li><a href="#about-the-project">About The Project</a></li>
    <li><a href="#system-architecture">System Architecture</a></li>
    <li>
      <a href="#models">Models</a>
      <ul>
        <li><a href="#model-1--run-12-gradient-boosting-ensemble">Run 12 Ensemble</a></li>
        <li><a href="#model-2--qlora-codebert-adapter">QLoRA CodeBERT</a></li>
        <li><a href="#model-comparison">Model Comparison</a></li>
      </ul>
    </li>
    <li><a href="#dataset">Dataset</a></li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#backend">Backend</a></li>
        <li><a href="#frontend">Frontend</a></li>
      </ul>
    </li>
    <li><a href="#api-reference">API Reference</a></li>
    <li><a href="#running-tests">Running Tests</a></li>
    <li><a href="#known-limitations">Known Limitations</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

---

<!-- ABOUT THE PROJECT -->
## About The Project

LLM-VUL is a vulnerability detection platform for C/C++ codebases that combines traditional static analysis with state-of-the-art ML models. Point it at any GitHub repository and receive independent findings from both layers — no merging, no OR logic, just clear separate signals you can assess on their own merits.

**Why this approach?**
- Static tools (CppCheck, Flawfinder, Semgrep) catch deterministic pattern violations with zero ML overhead
- The gradient boosting ensemble runs fast on CPU with strong ROC-AUC (0.905)
- QLoRA CodeBERT achieves **F1 0.75 / Recall 91%** using only 1.4% of the model's parameters — best accuracy when a GPU is available
- Results are always kept independent so you can tune trust levels per layer

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- ARCHITECTURE -->
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
│  Phase 1 — StaticAnalyzer (always runs)                  │
│    ├── CppCheck    memory safety, buffer overflows        │
│    ├── Flawfinder  dangerous function calls               │
│    └── Semgrep     pattern matching rules                 │
│                                                          │
│  Phase 2 — ML model (user-selectable)                    │
│    ├── Run12 Ensemble  (XGBoost + LightGBM + CatBoost)   │
│    └── LoRA CodeBERT   (QLoRA fine-tuned adapter)        │
└──────────────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────┐
│  React + Vite Frontend       │
│  Separate tabs per layer     │
└─────────────────────────────┘
```

> Static and ML results are always **independent** — never merged. Each layer surfaces its own findings with its own confidence scores.

### Built With

* [![Python][Python-badge]][Python-url]
* [![FastAPI][FastAPI-badge]][FastAPI-url]
* [![React][React-badge]][React-url]
* [![TypeScript][TS-badge]][TS-url]
* [![PyTorch][PyTorch-badge]][PyTorch-url]
* [![scikit-learn][sklearn-badge]][sklearn-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- MODELS -->
## Models

### Model 1 — Run 12 Gradient Boosting Ensemble

Four gradient boosting sub-models trained on a **304-dimensional feature vector**:

| Feature block            | Dimensions | Description                                                    |
|--------------------------|------------|----------------------------------------------------------------|
| Hand-engineered          | 240        | Complexity, control flow, dangerous function counts, pointer arithmetic |
| CodeBERT PCA             | 32         | 768-dim embeddings → 32-dim                                   |
| GraphCodeBERT PCA        | 32         | 768-dim embeddings → 32-dim                                   |

| Sub-model              | Weight | Characteristic            |
|------------------------|--------|---------------------------|
| XGBoost Conservative   | 15%    | High recall focus         |
| XGBoost Aggressive     | 40%    | Balanced precision/recall |
| LightGBM Balanced      | 30%    | Speed + balance           |
| CatBoost               | 15%    | Categorical handling      |

**Production threshold**: `0.308` (tuned for recall)

**Performance — Run 15, ~33,840 test samples**

| Metric    | Score  |
|-----------|--------|
| F1        | 0.6079 |
| Precision | 52.9%  |
| Recall    | 71.5%  |
| ROC-AUC   | 0.9050 |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

### Model 2 — QLoRA CodeBERT Adapter

Parameter-efficient fine-tuning of `microsoft/codebert-base` with LoRA + 4-bit NF4 quantization. Only **1.77M parameters trained** (1.4% of 126M total).

**LoRA config**: `r=16`, `alpha=32` — target modules: `query, key, value, attention.output.dense` across all 12 layers. Trained with Focal Loss (`γ=2.0`, `α=0.75`).

**Production threshold**: `0.55` &nbsp;|&nbsp; Security mode: `0.30`

**Performance — validation set, 34,233 samples**

| Metric    | Score        |
|-----------|--------------|
| F1        | **0.7526**   |
| Precision | 64.1%        |
| Recall    | **91.1%**    |
| ROC-AUC   | 0.8663       |

> Functions longer than 512 tokens use overlapping sliding windows (stride=256). The **maximum probability across windows** is taken — conservative security policy.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

### Model Comparison

| Model                 | F1           | Precision    | Recall       | ROC-AUC      |
|-----------------------|--------------|--------------|--------------|--------------|
| Run 12 Ensemble       | 0.6143       | 55.1%        | 69.4%        | 0.9060       |
| Run 15 Ensemble       | 0.6079       | 52.9%        | 71.5%        | 0.9050       |
| Run 16 Gated Ensemble | 0.5895       | 58.9%        | 59.0%        | 0.8978       |
| **QLoRA CodeBERT**    | **0.7526**   | **64.1%**    | **91.1%**    | **0.8663**   |

**QLoRA is the strongest model** — best F1 and recall. The ensemble is faster and does not require a GPU.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- DATASET -->
## Dataset

Training data combines three public vulnerability datasets into a single normalised corpus.

| Dataset       | Samples         | Notes                                            |
|---------------|-----------------|--------------------------------------------------|
| DiverseVul    | 330,491         | Real CVE-fixed commits                           |
| MegaVul       | 353,873         | Cross-project function-level labels              |
| Devign        | 27,318          | Widely-used benchmark                            |
| Zenodo        | 7,131           | **Excluded from ensemble** — noisy single-liners |
| **Total**     | **718,813**     | `data/c_normalised.jsonl` (904 MB)               |

**Class distribution**: 92.1% safe (662,302) vs 7.9% vulnerable (56,511) — 11.7:1 ratio  
**Language split**: 99.7% C, 0.3% C++

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

> **Dataset link**: *(coming soon)*

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.10+ | Backend runtime |
| Node.js 18+ | Frontend build |
| CUDA 12.4 | Required for LoRA model on Windows (bitsandbytes) |
| CppCheck | Must be on PATH |
| Semgrep | Must be on PATH |

### Backend

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

Start the API server:

```bash
uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload
```

| URL | Purpose |
|-----|---------|
| http://localhost:8000/health | Liveness check |
| http://localhost:8000/docs | Swagger UI |

### Frontend

```bash
cd frontend
npm install
npm run dev
```

App runs at **http://localhost:5173**

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- API REFERENCE -->
## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Liveness check |
| `/api/analyze/github` | POST | Submit repo URL — returns `job_id` |
| `/api/analyze/status/{job_id}` | GET | Poll job progress (0–100%) |
| `/api/analyze/logs/{job_id}` | GET | Stream pipeline log entries |
| `/api/analyze/results/{job_id}` | GET | Retrieve full results when completed |

### Request Body

```json
{
  "repo_url": "https://github.com/org/repo",
  "max_files": 1000,
  "confidence_threshold": 0.308,
  "ml_model": "ensemble"
}
```

`ml_model` accepts `"ensemble"` (Run 12, fast, no GPU) or `"lora"` (QLoRA CodeBERT, best accuracy, GPU recommended).

### Quick Smoke Test

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

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- TESTS -->
## Running Tests

```bash
# Full suite
python -m pytest tests/ -v

# Individual modules
python -m pytest tests/test_api.py -v
python -m pytest tests/test_static_analysis.py -v
python -m pytest tests/test_ingestion.py -v
python -m pytest tests/test_combined_analyzer.py -v
python -m pytest tests/test_code_parser.py -v

# Model tests (auto-skipped when model files are absent)
python -m pytest tests/test_ensemble_predictor.py -v
python -m pytest tests/test_lora_predictor.py -v
```

> Ensemble and LoRA predictor tests are automatically skipped when model files are not present — no models required to run the full test suite.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- LIMITATIONS -->
## Known Limitations

| Limitation | Details |
|------------|---------|
| Language coverage | Trained on 99.7% C — may generalise poorly to C++ |
| Ensemble precision | ~53–57% — roughly half of ML flags are false positives |
| LoRA precision | 64.1% — better, but ~35% false positive rate remains |
| Static tool dependency | CppCheck, Flawfinder, Semgrep must be installed separately |
| Long functions | Sliding window can over-flag due to max aggregation |
| LoRA VRAM | Runs in fp32 at inference — requires more VRAM than training |
| Single-label only | Binary classification — no multi-label CWE prediction |
| Dataset bias | Open-source C projects — may not generalise to embedded/proprietary code |

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- CONTACT -->
## Contact

Debashish — [ddev54081@gmail.com](mailto:ddev54081@gmail.com)

Project Link: [https://github.com/debashish17/LLM-VUL](https://github.com/debashish17/LLM-VUL)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

---

<!-- MARKDOWN LINKS & BADGES -->
[contributors-shield]: https://img.shields.io/github/contributors/debashish17/LLM-VUL.svg?style=for-the-badge
[contributors-url]: https://github.com/debashish17/LLM-VUL/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/debashish17/LLM-VUL.svg?style=for-the-badge
[forks-url]: https://github.com/debashish17/LLM-VUL/network/members
[stars-shield]: https://img.shields.io/github/stars/debashish17/LLM-VUL.svg?style=for-the-badge
[stars-url]: https://github.com/debashish17/LLM-VUL/stargazers
[issues-shield]: https://img.shields.io/github/issues/debashish17/LLM-VUL.svg?style=for-the-badge
[issues-url]: https://github.com/debashish17/LLM-VUL/issues
[license-shield]: https://img.shields.io/github/license/debashish17/LLM-VUL.svg?style=for-the-badge
[license-url]: https://github.com/debashish17/LLM-VUL/blob/main/LICENSE

[Python-badge]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://python.org
[FastAPI-badge]: https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi
[FastAPI-url]: https://fastapi.tiangolo.com
[React-badge]: https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB
[React-url]: https://reactjs.org
[TS-badge]: https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white
[TS-url]: https://typescriptlang.org
[PyTorch-badge]: https://img.shields.io/badge/PyTorch-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white
[PyTorch-url]: https://pytorch.org
[sklearn-badge]: https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white
[sklearn-url]: https://scikit-learn.org
