"""
One-time data preparation for QLoRA LoRA fine-tuning.
Run once, never re-run between training runs.

Pipeline:
  1. SHA-256 deduplication
  2. Language filter (c only)
  3. Undersample safe class to 1:3 ratio
  4. Strip comments + normalize whitespace
  5. Sliding window chunking (window=512, stride=256)
  6. Pre-tokenize (max_length=512)
  7. Stratified 80/10/10 split
  8. save_to_disk()

Usage:
  python scripts/prepare_lora_data.py
  python scripts/prepare_lora_data.py --debug-n 1000   # quick smoke test on 1000 records
"""

import argparse
import hashlib
import json
import random
import re
import sys
from pathlib import Path

from datasets import Dataset
from sklearn.model_selection import train_test_split
from transformers import AutoTokenizer


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
INPUT_FILE = "data/c_normalised.jsonl"
OUTPUT_DIR = "data/lora"
MODEL_NAME = "microsoft/codebert-base"
MAX_LENGTH = 512
WINDOW = 512
STRIDE = 256
TARGET_RATIO = 3       # safe : vulnerable = 3:1
SEED = 42
TRAIN_SPLIT = 0.80
VAL_SPLIT = 0.10
# TEST_SPLIT = 0.10 (implicit)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dedup_hash(code: str) -> str:
    normalized = re.sub(r"\s+", " ", code).strip()
    return hashlib.sha256(normalized.encode()).hexdigest()


def _strip_comments(code: str) -> str:
    """Remove C/C++ line and block comments with a simple state machine."""
    result = []
    i = 0
    in_string = False
    in_char = False
    while i < len(code):
        c = code[i]
        # Handle string literals
        if c == '"' and not in_char:
            in_string = not in_string
            result.append(c)
            i += 1
            continue
        if c == "'" and not in_string:
            in_char = not in_char
            result.append(c)
            i += 1
            continue
        if in_string or in_char:
            result.append(c)
            i += 1
            continue
        # Line comment
        if c == "/" and i + 1 < len(code) and code[i + 1] == "/":
            while i < len(code) and code[i] != "\n":
                i += 1
            continue
        # Block comment
        if c == "/" and i + 1 < len(code) and code[i + 1] == "*":
            i += 2
            while i + 1 < len(code) and not (code[i] == "*" and code[i + 1] == "/"):
                i += 1
            i += 2  # skip */
            continue
        result.append(c)
        i += 1
    return "".join(result)


def _preprocess(code: str) -> str:
    code = _strip_comments(code)
    code = re.sub(r"\s+", " ", code).strip()
    return code


def _sliding_window_chunks(token_ids: list[int], window: int, stride: int) -> list[list[int]]:
    """Split token_ids into overlapping chunks. Excludes special tokens in slicing."""
    chunks = []
    start = 0
    while start < len(token_ids):
        end = min(start + window, len(token_ids))
        chunks.append(token_ids[start:end])
        if end == len(token_ids):
            break
        start += stride
    return chunks


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main(debug_n: int | None = None):
    random.seed(SEED)
    out_dir = Path(OUTPUT_DIR)
    out_dir.mkdir(parents=True, exist_ok=True)

    stats = {}

    # ------------------------------------------------------------------
    # Step 0: Load
    # ------------------------------------------------------------------
    print("\n[0] Loading JSONL...")
    input_path = Path(INPUT_FILE)
    if not input_path.exists():
        print(f"  FAIL: {INPUT_FILE} not found")
        sys.exit(1)

    records = []
    with open(input_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if debug_n and i >= debug_n:
                break
            record = json.loads(line.strip())
            records.append(record)
            if (i + 1) % 100_000 == 0:
                print(f"  Loaded {i + 1:,} records...")

    stats["0_loaded"] = len(records)
    print(f"  Loaded: {len(records):,}")

    # ------------------------------------------------------------------
    # Step 1: SHA-256 deduplication (before language filter)
    # ------------------------------------------------------------------
    print("\n[1] Deduplication...")
    seen = set()
    deduped = []
    for r in records:
        h = _dedup_hash(r["code"])
        if h not in seen:
            seen.add(h)
            deduped.append(r)

    stats["1_after_dedup"] = len(deduped)
    dropped = len(records) - len(deduped)
    print(f"  After dedup: {len(deduped):,} (dropped {dropped:,} duplicates)")

    # ------------------------------------------------------------------
    # Step 2: Language filter — C only
    # ------------------------------------------------------------------
    print("\n[2] Language filter (c only)...")
    c_only = [r for r in deduped if r.get("language") == "c"]
    stats["2_c_only"] = len(c_only)
    dropped = len(deduped) - len(c_only)
    print(f"  After filter: {len(c_only):,} (dropped {dropped:,} non-C records)")

    vuln = [r for r in c_only if r["label_binary"] == 1]
    safe = [r for r in c_only if r["label_binary"] == 0]
    print(f"  Vulnerable: {len(vuln):,} | Safe: {len(safe):,} | Ratio: 1:{len(safe)/max(len(vuln),1):.1f}")

    # ------------------------------------------------------------------
    # Step 3: Undersample safe to 1:3 ratio
    # ------------------------------------------------------------------
    print(f"\n[3] Undersampling safe class to 1:{TARGET_RATIO} ratio...")
    target_safe = min(len(safe), TARGET_RATIO * len(vuln))
    random.shuffle(safe)
    safe_sampled = safe[:target_safe]
    balanced = vuln + safe_sampled
    random.shuffle(balanced)

    stats["3_after_undersample"] = len(balanced)
    stats["3_vulnerable"] = len(vuln)
    stats["3_safe"] = len(safe_sampled)
    print(f"  Vulnerable: {len(vuln):,} | Safe (sampled): {len(safe_sampled):,} | Total: {len(balanced):,}")

    # ------------------------------------------------------------------
    # Step 4: Preprocess (strip comments, normalize whitespace)
    # ------------------------------------------------------------------
    print("\n[4] Preprocessing code...")
    for r in balanced:
        r["code"] = _preprocess(r["code"])

    print(f"  Preprocessed {len(balanced):,} samples")

    # ------------------------------------------------------------------
    # Step 5: Sliding window chunking
    # ------------------------------------------------------------------
    print("\n[5] Sliding window chunking (window=512, stride=256)...")
    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)

    chunks_codes = []
    chunks_labels = []
    single_count = 0
    multi_count = 0

    for r in balanced:
        # Tokenize without truncation to measure true length
        token_ids = tokenizer.encode(r["code"], add_special_tokens=False)

        if len(token_ids) <= MAX_LENGTH - 2:  # -2 for [CLS] and [SEP]
            chunks_codes.append(r["code"])
            chunks_labels.append(r["label_binary"])
            single_count += 1
        else:
            # Sliding window over raw token ids (without special tokens)
            windows = _sliding_window_chunks(token_ids, window=MAX_LENGTH - 2, stride=STRIDE)
            for w in windows:
                # Decode chunk back to string so tokenizer handles special tokens
                chunk_text = tokenizer.decode(w, skip_special_tokens=True)
                chunks_codes.append(chunk_text)
                chunks_labels.append(r["label_binary"])
            multi_count += 1

    stats["5_single_chunks"] = single_count
    stats["5_multi_chunks"] = multi_count
    stats["5_total_chunks"] = len(chunks_codes)
    print(f"  Single-chunk functions: {single_count:,}")
    print(f"  Multi-chunk functions:  {multi_count:,}")
    print(f"  Total chunks:           {len(chunks_codes):,}")

    # ------------------------------------------------------------------
    # Step 6: Pre-tokenize all chunks
    # ------------------------------------------------------------------
    print("\n[6] Pre-tokenizing all chunks (max_length=512)...")

    dataset = Dataset.from_dict({"text": chunks_codes, "label": chunks_labels})

    def tokenize_fn(examples):
        return tokenizer(
            examples["text"],
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length",
        )

    dataset = dataset.map(tokenize_fn, batched=True, remove_columns=["text"])
    print(f"  Tokenized: {len(dataset):,} samples")
    print(f"  Features: {dataset.column_names}")

    # ------------------------------------------------------------------
    # Step 7: Stratified 80/10/10 split
    # ------------------------------------------------------------------
    print("\n[7] Stratified 80/10/10 split...")
    all_labels = dataset["label"]

    train_idx, temp_idx = train_test_split(
        range(len(dataset)),
        train_size=TRAIN_SPLIT,
        stratify=all_labels,
        random_state=SEED,
    )
    temp_labels = [all_labels[i] for i in temp_idx]
    val_size = VAL_SPLIT / (1 - TRAIN_SPLIT)
    val_idx_local, test_idx_local = train_test_split(
        range(len(temp_idx)),
        train_size=val_size,
        stratify=temp_labels,
        random_state=SEED,
    )
    val_idx = [temp_idx[i] for i in val_idx_local]
    test_idx = [temp_idx[i] for i in test_idx_local]

    train_ds = dataset.select(train_idx)
    val_ds = dataset.select(val_idx)
    test_ds = dataset.select(test_idx)

    stats["7_train"] = len(train_ds)
    stats["7_val"] = len(val_ds)
    stats["7_test"] = len(test_ds)

    print(f"  Train: {len(train_ds):,}")
    print(f"  Val:   {len(val_ds):,}")
    print(f"  Test:  {len(test_ds):,}")

    # ------------------------------------------------------------------
    # Step 8: Save to disk
    # ------------------------------------------------------------------
    print("\n[8] Saving datasets to disk...")
    train_ds.save_to_disk(str(out_dir / "train_dataset"))
    val_ds.save_to_disk(str(out_dir / "val_dataset"))
    test_ds.save_to_disk(str(out_dir / "test_dataset"))

    # Save prep stats for reproducibility audit
    stats_path = out_dir / "prep_stats.json"
    with open(stats_path, "w") as f:
        json.dump(stats, f, indent=2)

    print(f"  Train  → {out_dir}/train_dataset/")
    print(f"  Val    → {out_dir}/val_dataset/")
    print(f"  Test   → {out_dir}/test_dataset/")
    print(f"  Stats  → {stats_path}")

    print("\n" + "=" * 60)
    print("DATA PREPARATION COMPLETE")
    print("=" * 60)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug-n",
        type=int,
        default=None,
        help="Only load first N records (for smoke testing)",
    )
    args = parser.parse_args()
    main(debug_n=args.debug_n)
