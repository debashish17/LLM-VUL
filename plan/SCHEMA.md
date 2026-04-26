# Unified Data Schema for Vulnerability Detection

## Overview
This document defines the canonical schema for all vulnerability datasets used in the LLM-VUL project. All raw datasets (Zenodo, DiverseVul, Devign) will be normalized to this schema before training.

## Canonical Schema

```json
{
  "id": "diversevul_123456789",
  "dataset": "diversevul",
  "language": "c",
  "code": "int vulnerable_func() { return buffer_overflow(); }",
  "label_binary": 1,
  "label_cwe": "CWE-787",
  "label_cve": "CVE-2023-1234"
}
```

## Field Specifications

| Field | Type | Required | Why | For Training |
|-------|------|----------|-----|--------------|
| `id` | string | ✓ | Unique identifier per record. Enables tracking and tracing to source. | No (metadata) |
| `dataset` | string | ✓ | Source dataset (zenodo, diversevul, devign). For provenance and bias analysis. | No (metadata) |
| `language` | string | ✓ | Programming language: c, cpp, python, php, java. Currently: c, cpp only. | No (for filtering) |
| `code` | string | ✓ | Code snippet. **Primary feature** for the model. | **YES** |
| `label_binary` | int | ✓ | Binary label: 0 (safe) or 1 (vulnerable). **Ground truth**. | **YES** |
| `label_cwe` | string or null | ✗ | CWE ID (e.g., "CWE-787"). Optional; metadata. | No (optional) |
| `label_cve` | string or null | ✗ | CVE ID (e.g., "CVE-2023-1234"). Optional; metadata. | No (optional) |

## Key Decisions & Rationale

### 1. **Minimal 7-Field Schema**
- Dropped: file_path, context, notes, patch, line_from, line_to, etc.
- Reason: Not needed for initial binary classification. Reduces clutter.

### 2. **`code` is the Only Feature**
- Primary input to the model.
- **Must be non-empty** for all training records.

### 3. **`label_binary` is Ground Truth**
- Integer (0 or 1), not boolean.
- Vulnerable=1, Safe=0.

### 4. **`label_cwe` & `label_cve` are Optional**
- Not all vulnerabilities have CVE.
- DiverseVul lacks CVE data.
- Use `null` if missing (not empty string).

### 5. **Language Normalization**
- Lowercase: `c`, `cpp`
- Map `c++` → `cpp`
- Current scope: C/C++ only

### 6. **No Computed Fields**
- No `code_length` — can compute on-the-fly if needed.
- Keep schema stable.

## Processing Rules

**Data Cleaning:**
1. Remove records with empty `code` (whitespace-only = empty)
2. Normalize `language` to lowercase
3. Ensure `label_binary` is int (0 or 1)
4. Coerce CWE/CVE to string or null

**Validation:**
- Required: id, dataset, language, code, label_binary
- Optional: label_cwe, label_cve
- All records must have exactly 7 fields

**Output:**
- Format: JSON Lines (`.jsonl`)
- Encoding: UTF-8
- No duplicates

## Fields NOT Included (Why)

| Field | Reason |
|-------|--------|
| `context` | Commit message — not a feature |
| `file_path` | Metadata only |
| `notes` | Metadata only |
| `patch` | Diffs not used |
| `line_from`, `line_to` | Not used for whole-function classification |
| `code_length` | Can compute on-the-fly |
| `cwe_name`, `cwe_description`, `cwe_url` | Metadata only |

## Training Split

1. **Merge all datasets** (C/C++ only)
2. **Stratified split:**
   - Train: 70%
   - Val: 15%
   - Test: 15%
3. **Stratify by `label_binary`** to maintain vulnerable:safe ratio

---

**Status:** Finalized for implementation
