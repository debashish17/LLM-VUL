"""
Evaluation script for trained LoRA adapter.
Runs threshold search and saves optimal threshold to models/lora_adapter/threshold.json.

Usage:
  python src/train/evaluate_lora.py
  python src/train/evaluate_lora.py --split test   # evaluate on test set
  python src/train/evaluate_lora.py --split val    # evaluate on val set (default)
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
from datasets import load_from_disk
from peft import PeftModel
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from transformers import AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding, Trainer, TrainingArguments

sys.path.insert(0, str(Path(__file__).parent))
from lora_config import BASE_MODEL, LORA_PATHS, NUM_LABELS


def load_model_and_tokenizer(adapter_path: str):
    print(f"  Loading base CodeBERT...")
    base = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=NUM_LABELS,
    )
    print(f"  Attaching LoRA adapter from {adapter_path}...")
    model = PeftModel.from_pretrained(base, adapter_path)
    model.eval()

    tokenizer = AutoTokenizer.from_pretrained(adapter_path)
    return model, tokenizer


def get_predictions(model, tokenizer, dataset):
    """Run inference and return (logits, labels)."""
    # Use HF Trainer just for efficient batched prediction
    args = TrainingArguments(
        output_dir="outputs/tmp_eval",
        per_device_eval_batch_size=16,
        fp16=False,
        bf16=False,
        dataloader_num_workers=0,
        report_to=[],
    )
    trainer = Trainer(
        model=model,
        args=args,
        data_collator=DataCollatorWithPadding(tokenizer),
    )
    result = trainer.predict(dataset)
    logits = result.predictions
    labels = result.label_ids
    return logits, labels


def threshold_search(logits, labels, thresholds=None):
    """Sweep thresholds and return table of precision/recall/F1."""
    if thresholds is None:
        thresholds = [round(t, 2) for t in np.arange(0.30, 0.75, 0.05)]

    # Use vulnerable-class probability as score
    probs = torch.softmax(torch.tensor(logits, dtype=torch.float32), dim=-1).numpy()
    vuln_probs = probs[:, 1]

    rows = []
    for t in thresholds:
        preds = (vuln_probs >= t).astype(int)
        f1 = f1_score(labels, preds, zero_division=0)
        prec = precision_score(labels, preds, zero_division=0)
        rec = recall_score(labels, preds, zero_division=0)
        rows.append({"threshold": t, "precision": prec, "recall": rec, "f1": f1})

    return rows, vuln_probs


def print_threshold_table(rows):
    print(f"\n  {'threshold':>10} | {'precision':>9} | {'recall':>6} | {'F1':>6}")
    print(f"  {'-'*10}-+-{'-'*9}-+-{'-'*6}-+-{'-'*6}")
    for r in rows:
        print(f"  {r['threshold']:>10.2f} | {r['precision']:>9.4f} | {r['recall']:>6.4f} | {r['f1']:>6.4f}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=["val", "test"], default="val")
    parser.add_argument("--adapter", default=LORA_PATHS["adapter_dir"])
    args = parser.parse_args()

    adapter_path = args.adapter
    split_key = f"{args.split}_dataset"
    dataset_path = LORA_PATHS[split_key]

    print("=" * 70)
    print(f"LORA EVALUATION — split: {args.split.upper()}")
    print("=" * 70)

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------
    print(f"\n[1] Loading dataset from {dataset_path}...")
    dataset = load_from_disk(dataset_path)
    print(f"  Samples: {len(dataset):,}")

    print("\n[2] Loading model...")
    model, tokenizer = load_model_and_tokenizer(adapter_path)

    # ------------------------------------------------------------------
    # Predict
    # ------------------------------------------------------------------
    print("\n[3] Running inference...")
    logits, labels = get_predictions(model, tokenizer, dataset)
    print(f"  Got logits shape: {logits.shape}")

    # ------------------------------------------------------------------
    # AUC-ROC (threshold-independent)
    # ------------------------------------------------------------------
    probs = torch.softmax(torch.tensor(logits, dtype=torch.float32), dim=-1).numpy()
    vuln_probs = probs[:, 1]
    try:
        auc = roc_auc_score(labels, vuln_probs)
    except ValueError:
        auc = 0.0
    print(f"\n  ROC-AUC (threshold-independent): {auc:.4f}")

    # ------------------------------------------------------------------
    # Threshold search
    # ------------------------------------------------------------------
    print("\n[4] Threshold search (0.30 → 0.70, step 0.05)...")
    rows, vuln_probs = threshold_search(logits, labels)
    print_threshold_table(rows)

    # Best F1 threshold
    best_f1_row = max(rows, key=lambda r: r["f1"])
    # Best recall-biased threshold (security: catch more vulnerabilities)
    # Pick lowest threshold where recall >= 0.75 (or fallback to best F1)
    recall_biased = next(
        (r for r in sorted(rows, key=lambda x: x["threshold"]) if r["recall"] >= 0.75),
        best_f1_row,
    )

    print(f"\n  Best F1 threshold:     {best_f1_row['threshold']:.2f} → F1={best_f1_row['f1']:.4f}")
    print(f"  Recall-biased (≥0.75): {recall_biased['threshold']:.2f} → recall={recall_biased['recall']:.4f}, prec={recall_biased['precision']:.4f}")
    print(f"\n  Security recommendation: use {recall_biased['threshold']:.2f} (biases toward catching all vulnerabilities)")

    chosen_threshold = recall_biased["threshold"]

    # ------------------------------------------------------------------
    # Final confusion matrix at chosen threshold
    # ------------------------------------------------------------------
    print(f"\n[5] Confusion matrix at threshold={chosen_threshold:.2f}...")
    preds = (vuln_probs >= chosen_threshold).astype(int)
    cm = confusion_matrix(labels, preds)
    f1 = f1_score(labels, preds, zero_division=0)
    prec = precision_score(labels, preds, zero_division=0)
    rec = recall_score(labels, preds, zero_division=0)

    tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)
    print(f"\n  {'':12} Pred Safe  Pred Vuln")
    print(f"  Actual Safe  {tn:9,}  {fp:9,}   (FP={fp:,})")
    print(f"  Actual Vuln  {fn:9,}  {tp:9,}   (FN={fn:,})")
    print(f"\n  F1={f1:.4f}  Precision={prec:.4f}  Recall={rec:.4f}  AUC={auc:.4f}")

    # ------------------------------------------------------------------
    # Run 3 guidance
    # ------------------------------------------------------------------
    print("\n[6] Run 3 trigger analysis:")
    if prec < 0.50:
        print("  -> LOW PRECISION (false positives high):")
        print(f"     Try raising threshold from {chosen_threshold:.2f} to {chosen_threshold+0.10:.2f} first.")
        print("     If still low: set focal_alpha=0.60 in lora_config.py, rerun --mode tuning.")
    if rec < 0.60:
        print("  -> LOW RECALL (missing vulnerabilities):")
        print("     Check prep_stats.json — did sliding window generate multi-chunk samples?")
        print("     Fix: set r=24 in lora_config.py, or focal_alpha=0.85, rerun --mode tuning.")
    if f1 < 0.50:
        print("  -> F1 < 0.50: data pipeline issue likely.")
        print("     Verify: dataset['label'] has both 0 and 1 values in both splits.")
    if f1 >= 0.70:
        print(f"  -> F1={f1:.4f} >= 0.70. Accept this model.")
        print("     Save threshold and integrate into CombinedAnalyzer.")

    # ------------------------------------------------------------------
    # Save threshold + results
    # ------------------------------------------------------------------
    threshold_path = Path(adapter_path) / "threshold.json"
    with open(threshold_path, "w") as f:
        json.dump({"threshold": chosen_threshold, "strategy": "recall_biased"}, f, indent=2)
    print(f"\n  Threshold saved to {threshold_path}")

    # Full results
    Path("outputs").mkdir(exist_ok=True)
    results = {
        "split": args.split,
        "adapter": adapter_path,
        "threshold": chosen_threshold,
        "threshold_strategy": "recall_biased",
        "f1": round(f1, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "auc_roc": round(auc, 4),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        "threshold_search": rows,
    }
    results_path = LORA_PATHS["eval_results"]
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Full results saved to {results_path}")

    print("\n" + "=" * 70)
    print("EVALUATION COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    main()
