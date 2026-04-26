"""
QLoRA fine-tuning script for CodeBERT vulnerability detection.

Usage:
  python src/train/train_lora.py --mode validation   # 10% data, 2 epochs (smoke test)
  python src/train/train_lora.py --mode full          # full data, 5 epochs (baseline)
  python src/train/train_lora.py --mode tuning        # full data, 3 epochs (Run 3+)

Modes:
  validation  Run 1: verify pipeline, VRAM, loss direction. Takes 15-20 min.
              Success: no OOM, loss decreasing, F1 > 0.30
  full        Run 2: baseline training on full dataset. Takes 3-4 hours.
              Success: F1 >= 0.70 on val. Evaluate confusion matrix after.
  tuning      Run 3: targeted improvement based on Run 2 confusion matrix.
              Success: F1 strictly better than Run 2 model.
"""

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from datasets import load_from_disk
from peft import get_peft_model
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    DataCollatorWithPadding,
    Trainer,
    TrainingArguments,
)

# Add src to path so lora_config import works from any cwd
sys.path.insert(0, str(Path(__file__).parent))
from lora_config import (
    BASE_MODEL,
    BNB_CONFIG,
    FOCAL_CONFIG,
    LORA_CONFIG,
    LORA_PATHS,
    LORA_TRAIN_CONFIG,
    LORA_TUNING_OVERRIDES,
    LORA_VALIDATION_OVERRIDES,
    NUM_LABELS,
    print_config,
)


# ---------------------------------------------------------------------------
# Focal Loss Trainer
# ---------------------------------------------------------------------------

class FocalLossTrainer(Trainer):
    """HF Trainer with Focal Loss instead of standard cross-entropy."""

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        labels = inputs.pop("labels")
        outputs = model(**inputs)
        logits = outputs.logits

        gamma = FOCAL_CONFIG["gamma"]
        alpha = FOCAL_CONFIG["alpha"]

        # Softmax probabilities
        probs = torch.softmax(logits, dim=-1)
        # p_t: probability of the true class for each sample
        p_t = probs[range(len(labels)), labels]
        # Clamp to avoid log(0) → NaN
        p_t = p_t.clamp(min=1e-7, max=1 - 1e-7)

        # alpha_t: alpha for positive (vulnerable) class, (1-alpha) for negative
        alpha_t = torch.where(labels == 1,
                              torch.full_like(p_t, alpha),
                              torch.full_like(p_t, 1 - alpha))

        # Focal weight: down-weight easy examples
        focal_weight = alpha_t * (1 - p_t) ** gamma

        # Per-sample cross-entropy, then apply focal weight
        ce_loss = F.cross_entropy(logits, labels, reduction="none")
        loss = (focal_weight * ce_loss).mean()

        # Guard against NaN (can happen early in training)
        if torch.isnan(loss):
            raise RuntimeError(
                "Focal loss is NaN. Check label alignment and class distribution."
            )

        return (loss, outputs) if return_outputs else loss


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=1)

    f1 = f1_score(labels, preds, zero_division=0)
    precision = precision_score(labels, preds, zero_division=0)
    recall = recall_score(labels, preds, zero_division=0)

    # AUC-ROC using vulnerable-class logit as score
    try:
        vuln_scores = logits[:, 1]
        auc = roc_auc_score(labels, vuln_scores)
    except ValueError:
        auc = 0.0

    return {"f1": f1, "precision": precision, "recall": recall, "auc_roc": auc}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["validation", "full", "tuning"],
        required=True,
        help="Training mode: validation | full | tuning",
    )
    args = parser.parse_args()
    mode = args.mode

    print("=" * 70)
    print(f"LORA TRAINING — mode: {mode.upper()}")
    print("=" * 70)
    print_config()

    # ------------------------------------------------------------------
    # Load datasets
    # ------------------------------------------------------------------
    print("\n[1] Loading datasets...")
    train_ds = load_from_disk(LORA_PATHS["train_dataset"])
    val_ds = load_from_disk(LORA_PATHS["val_dataset"])
    print(f"  Train: {len(train_ds):,} | Val: {len(val_ds):,}")

    if mode == "validation":
        # 10% of train, stratified
        n = max(1, len(train_ds) // 10)
        # Simple stratified subset: take every 10th sample (already shuffled by data prep)
        indices = list(range(0, len(train_ds), 10))[:n]
        train_ds = train_ds.select(indices)
        print(f"  Validation mode: using {len(train_ds):,} training samples (10%)")

    # Check label distribution
    labels = train_ds["label"]
    n_vuln = sum(1 for l in labels if l == 1)
    n_safe = sum(1 for l in labels if l == 0)
    print(f"  Train label dist: safe={n_safe:,} ({100*n_safe/len(labels):.1f}%) | vuln={n_vuln:,} ({100*n_vuln/len(labels):.1f}%)")

    # ------------------------------------------------------------------
    # Load tokenizer
    # ------------------------------------------------------------------
    print("\n[2] Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)

    # ------------------------------------------------------------------
    # Load model with 4-bit quantization
    # ------------------------------------------------------------------
    print("\n[3] Loading CodeBERT with 4-bit NF4 quantization...")
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=NUM_LABELS,
        quantization_config=BNB_CONFIG,
    )
    print(f"  Base model loaded in 4-bit NF4")

    # Apply LoRA
    model = get_peft_model(model, LORA_CONFIG)
    trainable, total = model.get_nb_trainable_parameters()
    pct = 100 * trainable / total
    print(f"  LoRA applied: {trainable:,} trainable / {total:,} total ({pct:.2f}%)")

    if trainable < 500_000:
        print("  WARN: Trainable params unexpectedly low — check target_modules")

    # ------------------------------------------------------------------
    # Training arguments
    # ------------------------------------------------------------------
    print("\n[4] Building TrainingArguments...")
    config = dict(LORA_TRAIN_CONFIG)

    if mode == "validation":
        config.update(LORA_VALIDATION_OVERRIDES)
    elif mode == "tuning":
        config.update(LORA_TUNING_OVERRIDES)

    training_args = TrainingArguments(**config)
    print(f"  Epochs: {training_args.num_train_epochs} | LR: {training_args.learning_rate}")
    print(f"  Batch: {training_args.per_device_train_batch_size} × {training_args.gradient_accumulation_steps} = {training_args.per_device_train_batch_size * training_args.gradient_accumulation_steps} effective")

    # ------------------------------------------------------------------
    # Trainer
    # ------------------------------------------------------------------
    print("\n[5] Creating FocalLossTrainer...")
    trainer = FocalLossTrainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        processing_class=tokenizer,
        compute_metrics=compute_metrics,
        data_collator=DataCollatorWithPadding(tokenizer),
    )

    # ------------------------------------------------------------------
    # Train
    # ------------------------------------------------------------------
    print("\n[6] Training...")
    print("=" * 70)
    train_result = trainer.train()
    print("=" * 70)
    print("TRAINING COMPLETE")

    # ------------------------------------------------------------------
    # Post-training: confusion matrix on val set
    # ------------------------------------------------------------------
    print("\n[7] Evaluating on validation set...")
    val_preds = trainer.predict(val_ds)
    preds = np.argmax(val_preds.predictions, axis=1)
    val_labels = val_ds["label"]

    cm = confusion_matrix(val_labels, preds)
    f1 = f1_score(val_labels, preds, zero_division=0)
    prec = precision_score(val_labels, preds, zero_division=0)
    rec = recall_score(val_labels, preds, zero_division=0)

    print(f"\n  Confusion Matrix (rows=actual, cols=predicted):")
    print(f"  {'':12} Pred Safe  Pred Vuln")
    print(f"  Actual Safe  {cm[0][0]:9,}  {cm[0][1]:9,}")
    print(f"  Actual Vuln  {cm[1][0]:9,}  {cm[1][1]:9,}")
    print(f"\n  F1={f1:.4f}  Precision={prec:.4f}  Recall={rec:.4f}")

    # Run 3 trigger guidance
    print("\n  Run 3 trigger analysis:")
    if prec < 0.50:
        print("  -> LOW PRECISION: Model over-triggering.")
        print("     First try: raise inference threshold by 0.10 (free, no retraining).")
        print("     If still low: reduce focal_alpha 0.75 -> 0.60 in lora_config.py, re-run tuning.")
    if rec < 0.60:
        print("  -> LOW RECALL: Model missing vulnerabilities.")
        print("     Check sliding window worked (verify multi-chunk functions in prep_stats.json).")
        print("     If OK: increase r from 16 -> 24 in lora_config.py, or raise focal_alpha -> 0.85.")
    if f1 >= 0.70:
        print("  -> F1 >= 0.70: Strong result. Run threshold tuning (evaluate_lora.py) before accepting.")
    elif f1 >= 0.50:
        print("  -> F1 0.50-0.70: Proceed to Run 3 with targeted fix from confusion matrix above.")
    else:
        print("  -> F1 < 0.50: Debug data pipeline before Run 3.")
        print("     Check: assert dataset['label'].unique() == {0, 1} in both splits.")

    # ------------------------------------------------------------------
    # Save adapter
    # ------------------------------------------------------------------
    print(f"\n[8] Saving LoRA adapter to {LORA_PATHS['adapter_dir']}...")
    Path(LORA_PATHS["adapter_dir"]).mkdir(parents=True, exist_ok=True)
    model.save_pretrained(LORA_PATHS["adapter_dir"])
    tokenizer.save_pretrained(LORA_PATHS["adapter_dir"])

    # Save training summary
    summary = {
        "mode": mode,
        "base_model": BASE_MODEL,
        "trainable_params": trainable,
        "total_params": total,
        "trainable_pct": round(pct, 4),
        "train_samples": len(train_ds),
        "val_samples": len(val_ds),
        "epochs": training_args.num_train_epochs,
        "learning_rate": training_args.learning_rate,
        "val_f1": round(f1, 4),
        "val_precision": round(prec, 4),
        "val_recall": round(rec, 4),
        "training_loss": round(float(train_result.training_loss), 4) if hasattr(train_result, "training_loss") else None,
    }
    summary_path = Path(LORA_PATHS["adapter_dir"]) / "training_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"  Adapter saved.")
    print(f"  Training summary saved to {summary_path}")
    print(f"\n  Next step: python src/train/evaluate_lora.py")
    print("=" * 70)


if __name__ == "__main__":
    main()
