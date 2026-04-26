"""
Data loading and preprocessing pipeline
Loads JSONL, creates stratified train/val/test splits, tokenizes with CodeBERT
"""

import json
import numpy as np
from pathlib import Path
from collections import Counter

from datasets import Dataset
from transformers import AutoTokenizer
from sklearn.model_selection import train_test_split

from config import DATA_CONFIG, MODEL_CONFIG, PATHS, DEVICE_CONFIG

print("=" * 80)
print("DATA LOADING PIPELINE")
print("=" * 80)

# ============================================================================
# 1. LOAD JSONL FILE
# ============================================================================

print("\n[1] Loading JSONL file...")

input_file = Path(PATHS["input_file"])
if not input_file.exists():
    raise FileNotFoundError(f"File not found: {input_file}")

records = []
with open(input_file, 'r', encoding='utf-8') as f:
    for i, line in enumerate(f):
        record = json.loads(line.strip())
        records.append(record)
        if (i + 1) % 100000 == 0:
            print(f"  ✓ Loaded {i + 1:,} records")

print(f"  ✓ Total records loaded: {len(records):,}")

# ============================================================================
# 2. EXTRACT CODE AND LABELS
# ============================================================================

print("\n[2] Extracting code and labels...")

codes = [r['code'] for r in records]
labels = [r['label_binary'] for r in records]

print(f"  ✓ Codes: {len(codes):,}")
print(f"  ✓ Labels: {len(labels):,}")

# Check label distribution
label_counts = Counter(labels)
print(f"\n  Label distribution:")
for label, count in sorted(label_counts.items()):
    pct = (count / len(labels)) * 100
    label_name = "Safe" if label == 0 else "Vulnerable"
    print(f"    • {label_name} ({label}): {count:,} ({pct:.1f}%)")

# ============================================================================
# 3. CREATE HUGGINGFACE DATASET
# ============================================================================

print("\n[3] Creating HuggingFace Dataset...")

dataset_dict = {
    'text': codes,
    'label': labels
}

dataset = Dataset.from_dict(dataset_dict)
print(f"  ✓ Dataset created: {len(dataset):,} samples")
print(f"  ✓ Features: {dataset.column_names}")

# ============================================================================
# 4. STRATIFIED TRAIN/VAL/TEST SPLIT
# ============================================================================

print("\n[4] Creating stratified train/val/test split...")

# First split: train (80%) and temp (20%)
train_indices, temp_indices = train_test_split(
    range(len(dataset)),
    train_size=DATA_CONFIG['train_split'],
    test_size=(1 - DATA_CONFIG['train_split']),
    stratify=labels,
    random_state=DATA_CONFIG['seed']
)

# Second split: val (10%) and test (10%) from temp
temp_labels = [labels[i] for i in temp_indices]
val_size = DATA_CONFIG['val_split'] / (1 - DATA_CONFIG['train_split'])

val_indices_local, test_indices_local = train_test_split(
    range(len(temp_indices)),
    train_size=val_size,
    test_size=(1 - val_size),
    stratify=temp_labels,
    random_state=DATA_CONFIG['seed']
)

val_indices = [temp_indices[i] for i in val_indices_local]
test_indices = [temp_indices[i] for i in test_indices_local]

print(f"  ✓ Train set: {len(train_indices):,} ({len(train_indices)/len(dataset)*100:.1f}%)")
print(f"  ✓ Val set:   {len(val_indices):,} ({len(val_indices)/len(dataset)*100:.1f}%)")
print(f"  ✓ Test set:  {len(test_indices):,} ({len(test_indices)/len(dataset)*100:.1f}%)")

# Verify stratification
print(f"\n  Verifying stratification (label distribution per split):")
for split_name, indices in [("Train", train_indices), ("Val", val_indices), ("Test", test_indices)]:
    split_labels = [labels[i] for i in indices]
    split_counts = Counter(split_labels)
    safe_pct = (split_counts[0] / len(split_labels)) * 100
    vuln_pct = (split_counts[1] / len(split_labels)) * 100
    print(f"    • {split_name}: {safe_pct:.1f}% safe, {vuln_pct:.1f}% vulnerable")

# Create dataset splits
train_dataset = dataset.select(train_indices)
val_dataset = dataset.select(val_indices)
test_dataset = dataset.select(test_indices)

print(f"\n  ✓ Splits created successfully")

# ============================================================================
# 5. TOKENIZATION
# ============================================================================

print("\n[5] Tokenizing datasets...")

tokenizer = AutoTokenizer.from_pretrained(MODEL_CONFIG['tokenizer_name'])
print(f"  ✓ Loaded tokenizer: {MODEL_CONFIG['tokenizer_name']}")

def tokenize_function(examples):
    """Tokenize code with truncation and padding"""
    return tokenizer(
        examples['text'],
        truncation=True,
        max_length=MODEL_CONFIG['max_length'],
        padding='max_length'
    )

# Tokenize all splits
print("  Tokenizing train set...")
train_dataset = train_dataset.map(tokenize_function, batched=True, remove_columns=['text'])

print("  Tokenizing val set...")
val_dataset = val_dataset.map(tokenize_function, batched=True, remove_columns=['text'])

print("  Tokenizing test set...")
test_dataset = test_dataset.map(tokenize_function, batched=True, remove_columns=['text'])

print(f"  ✓ Tokenization complete")
print(f"    • Train features: {train_dataset.column_names}")

# ============================================================================
# 6. SAVE DATASETS
# ============================================================================

print("\n[6] Saving datasets...")

train_dataset.save_to_disk(PATHS['train_dataset'])
val_dataset.save_to_disk(PATHS['val_dataset'])
test_dataset.save_to_disk(PATHS['test_dataset'])

print(f"  ✓ Train dataset saved to {PATHS['train_dataset']}")
print(f"  ✓ Val dataset saved to {PATHS['val_dataset']}")
print(f"  ✓ Test dataset saved to {PATHS['test_dataset']}")

# ============================================================================
# 7. SAMPLE WEIGHTS FOR WEIGHTED SAMPLING
# ============================================================================

print("\n[7] Computing sample weights for WeightedRandomSampler...")

num_safe = len([l for l in labels if l == 0])
num_vulnerable = len([l for l in labels if l == 1])

# Weight vulnerable samples higher (with reduction factor for less aggressive predictions)
vulnerable_weight = num_safe / num_vulnerable / 2.5  # Reduce by 2.5x for better precision
safe_weight = 1.0

train_labels = [labels[i] for i in train_indices]
sample_weights = [safe_weight if l == 0 else vulnerable_weight for l in train_labels]

print(f"  Safe weight: {safe_weight:.4f}")
print(f"  Vulnerable weight: {vulnerable_weight:.4f}")
print(f"  Weight reduction factor: 2.5x")
print(f"  Sample weights computed for {len(sample_weights):,} training samples")

# Save weights for use in training
import pickle
weights_file = "data/sample_weights.pkl"
with open(weights_file, 'wb') as f:
    pickle.dump(sample_weights, f)
print(f"  ✓ Sample weights saved to {weights_file}")

# ============================================================================
# SUMMARY
# ============================================================================

print("\n" + "=" * 80)
print("DATA PIPELINE COMPLETE")
print("=" * 80)
print(f"\n✓ Total records processed: {len(records):,}")
print(f"✓ Train set: {len(train_dataset):,}")
print(f"✓ Val set: {len(val_dataset):,}")
print(f"✓ Test set: {len(test_dataset):,}")
print(f"✓ Tokenized with max length: {MODEL_CONFIG['max_length']}")
print(f"\nReady for training!")
print("=" * 80)
