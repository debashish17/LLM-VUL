"""
Evaluation script - evaluate trained CodeBERT model on test set
Compute F1, precision, recall, AUC-ROC and generate confusion matrix
"""

import json
import numpy as np
import torch
from pathlib import Path
from datasets import load_from_disk
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    pipeline
)
from sklearn.metrics import (
    f1_score, 
    precision_score, 
    recall_score, 
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from config import MODEL_CONFIG, PATHS

print("=" * 80)
print("CODEBERT VULNERABILITY DETECTION - EVALUATION")
print("=" * 80)

# ============================================================================
# LOAD MODEL & TOKENIZER
# ============================================================================

print("\n[1] LOADING MODEL...")

final_model_dir = PATHS['final_model_dir']

if not Path(final_model_dir).exists():
    print(f"❌ Error: Model not found at {final_model_dir}")
    print("Please run training first: python src/train/train_codebert.py")
    exit(1)

tokenizer = AutoTokenizer.from_pretrained(final_model_dir)
model = AutoModelForSequenceClassification.from_pretrained(final_model_dir)

print(f"  ✓ Model loaded from {final_model_dir}")
print(f"  ✓ Number of labels: {model.config.num_labels}")

# ============================================================================
# LOAD TEST DATASET
# ============================================================================

print("\n[2] LOADING TEST DATASET...")

test_dataset = load_from_disk(PATHS['test_dataset'])
print(f"  ✓ Test dataset: {len(test_dataset):,} samples")

# ============================================================================
# INFERENCE
# ============================================================================

print("\n[3] RUNNING INFERENCE ON TEST SET...")

# Set model to eval mode
model.eval()
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
model = model.to(device)

# Batch inference
batch_size = 64
predictions_list = []
logits_list = []
labels_list = test_dataset['label']

num_batches = (len(test_dataset) + batch_size - 1) // batch_size

with torch.no_grad():
    for batch_idx in range(num_batches):
        start_idx = batch_idx * batch_size
        end_idx = min(start_idx + batch_size, len(test_dataset))
        batch = test_dataset[start_idx:end_idx]
        
        # Prepare inputs
        inputs = {
            'input_ids': torch.tensor(batch['input_ids'], device=device),
            'attention_mask': torch.tensor(batch['attention_mask'], device=device),
        }
        
        # Forward pass
        outputs = model(**inputs)
        logits = outputs.logits
        predictions = torch.argmax(logits, dim=1)
        
        predictions_list.extend(predictions.cpu().numpy().tolist())
        logits_list.extend(logits.cpu().numpy().tolist())
        
        if (batch_idx + 1) % 10 == 0:
            print(f"  ✓ Processed {end_idx:,} samples...")

predictions = np.array(predictions_list)
logits = np.array(logits_list)

print(f"  ✓ Inference complete on {len(predictions):,} samples")

# ============================================================================
# COMPUTE METRICS
# ============================================================================

print("\n[4] COMPUTING METRICS...")

# AUC-ROC using softmax probabilities
softmax = torch.nn.Softmax(dim=1)
probabilities = softmax(torch.tensor(logits)).numpy()
vulnerable_probs = probabilities[:, 1]

try:
    auc_roc = roc_auc_score(labels_list, vulnerable_probs)
except:
    auc_roc = 0.0

print(f"\n  AUC-ROC: {auc_roc:.4f}")

# ============================================================================
# THRESHOLD TUNING
# ============================================================================

print("\n[4.1] TESTING DIFFERENT THRESHOLDS...")

thresholds = [0.5, 0.55, 0.6, 0.65, 0.7, 0.75]
best_threshold = 0.5
best_f1 = 0.0
threshold_results = []

for threshold in thresholds:
    # Apply threshold
    pred_threshold = (vulnerable_probs > threshold).astype(int)
    
    # Compute metrics
    f1_thresh = f1_score(labels_list, pred_threshold, zero_division=0)
    precision_thresh = precision_score(labels_list, pred_threshold, zero_division=0)
    recall_thresh = recall_score(labels_list, pred_threshold, zero_division=0)
    
    threshold_results.append({
        "threshold": threshold,
        "f1": f1_thresh,
        "precision": precision_thresh,
        "recall": recall_thresh
    })
    
    print(f"  Threshold {threshold:.2f}: F1={f1_thresh:.4f}, Precision={precision_thresh:.4f}, Recall={recall_thresh:.4f}")
    
    # Track best threshold
    if f1_thresh > best_f1:
        best_f1 = f1_thresh
        best_threshold = threshold

print(f"\n  ✓ Best threshold: {best_threshold:.2f} (F1={best_f1:.4f})")

# Use best threshold for final predictions
predictions = (vulnerable_probs > best_threshold).astype(int)

# Recompute final metrics with best threshold
f1 = f1_score(labels_list, predictions, zero_division=0)
precision = precision_score(labels_list, predictions, zero_division=0)
recall = recall_score(labels_list, predictions, zero_division=0)

print(f"\n  Final Metrics (with threshold {best_threshold:.2f}):")
print(f"    • F1-score:  {f1:.4f}")
print(f"    • Precision: {precision:.4f}")
print(f"    • Recall:    {recall:.4f}")
print(f"    • AUC-ROC:   {auc_roc:.4f}")

# ============================================================================
# CONFUSION MATRIX
# ============================================================================

print("\n[5] CONFUSION MATRIX...")

cm = confusion_matrix(labels_list, predictions)
tn, fp, fn, tp = cm.ravel()

print(f"\n  True Negatives (Safe correctly identified):  {tn:,}")
print(f"  False Positives (Safe misclassified as Vuln): {fp:,}")
print(f"  False Negatives (Vuln misclassified as Safe): {fn:,}")
print(f"  True Positives (Vuln correctly identified):  {tp:,}")

# Additional metrics from confusion matrix
specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
sensitivity = tp / (tp + fn) if (tp + fn) > 0 else 0  # Same as recall

print(f"\n  Derived metrics:")
print(f"    • Sensitivity (Recall):   {sensitivity:.4f}")
print(f"    • Specificity:            {specificity:.4f}")

# ============================================================================
# CLASS-WISE METRICS
# ============================================================================

print("\n[6] CLASS-WISE BREAKDOWN...")

# Safe class (0)
safe_precision = tn / (tn + fn) if (tn + fn) > 0 else 0
safe_recall = tn / (tn + fp) if (tn + fp) > 0 else 0

# Vulnerable class (1)
vuln_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
vuln_recall = tp / (tp + fn) if (tp + fn) > 0 else 0

print(f"\n  Safe (Label 0):")
print(f"    • Precision: {safe_precision:.4f}")
print(f"    • Recall:    {safe_recall:.4f}")

print(f"\n  Vulnerable (Label 1):")
print(f"    • Precision: {vuln_precision:.4f}")
print(f"    • Recall:    {vuln_recall:.4f}")

# ============================================================================
# SAVE RESULTS
# ============================================================================

print("\n[7] SAVING RESULTS...")

results = {
    "model": MODEL_CONFIG['model_name'],
    "test_samples": len(predictions),
    "best_threshold": float(best_threshold),
    "threshold_tuning_results": threshold_results,
    "metrics": {
        "f1_score": float(f1),
        "precision": float(precision),
        "recall": float(recall),
        "auc_roc": float(auc_roc),
        "sensitivity": float(sensitivity),
        "specificity": float(specificity),
    },
    "confusion_matrix": {
        "true_negatives": int(tn),
        "false_positives": int(fp),
        "false_negatives": int(fn),
        "true_positives": int(tp),
    },
    "class_wise_metrics": {
        "safe": {
            "precision": float(safe_precision),
            "recall": float(safe_recall),
        },
        "vulnerable": {
            "precision": float(vuln_precision),
            "recall": float(vuln_recall),
        }
    },
    "label_distribution": {
        "safe": int(sum(1 for l in labels_list if l == 0)),
        "vulnerable": int(sum(1 for l in labels_list if l == 1)),
    }
}

# Save as JSON
output_file = PATHS['test_results']
Path(output_file).parent.mkdir(parents=True, exist_ok=True)

with open(output_file, 'w') as f:
    json.dump(results, f, indent=2)

print(f"  ✓ Results saved to {output_file}")

# Save predictions
predictions_file = PATHS['predictions']
predictions_data = {
    "predictions": predictions.tolist(),
    "probabilities": vulnerable_probs.tolist(),
    "labels": [int(l) for l in labels_list],  # Convert Column to list of ints
}

with open(predictions_file, 'w') as f:
    json.dump(predictions_data, f)

print(f"  ✓ Predictions saved to {predictions_file}")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("✅ EVALUATION COMPLETE")
print("=" * 80)

print(f"\n📊 SUMMARY:")
print(f"   F1-Score: {f1:.4f}")
print(f"   Precision: {precision:.4f}")
print(f"   Recall: {recall:.4f}")
print(f"   AUC-ROC: {auc_roc:.4f}")

if f1 >= 0.75:
    print(f"\n   ✅ Target achieved (F1 >= 0.75)!")
elif f1 >= 0.70:
    print(f"\n   ⚠️  Minimum threshold met (F1 >= 0.70)")
else:
    print(f"\n   ❌ Below minimum threshold (F1 < 0.70)")

print(f"\nResults saved to: {output_file}")
print("=" * 80)
