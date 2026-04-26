"""
Configuration for CodeBERT vulnerability detection training
"""

import torch

# ============================================================================
# DATASET CONFIGURATION
# ============================================================================

DATA_CONFIG = {
    "input_file": "data/c_normalised.jsonl",
    "train_split": 0.80,
    "val_split": 0.10,
    "test_split": 0.10,
    "seed": 42,
}

# ============================================================================
# MODEL CONFIGURATION
# ============================================================================

MODEL_CONFIG = {
    "model_name": "microsoft/codebert-base",
    "num_labels": 2,  # Binary classification: safe (0) or vulnerable (1)
    "max_length": 256,  # Reduced from 512 (90.9% of code < 256 tokens)
    "tokenizer_name": "microsoft/codebert-base",
}

# ============================================================================
# TRAINING CONFIGURATION
# ============================================================================

TRAINING_CONFIG = {
    "output_dir": "models/codebert_checkpoint",
    "num_train_epochs": 3,  # Start with 2, update to 3 if needed after evaluation
    "per_device_train_batch_size": 48,
    "per_device_eval_batch_size": 96,
    "learning_rate": 2e-5,
    "warmup_steps": 300,
    "weight_decay": 0.01,
    "evaluation_strategy": "steps",
    "eval_steps": 10000,
    "save_strategy": "steps",
    "save_steps": 10000,
    "logging_steps": 100,
    "save_total_limit": 2,  # Keep only 2 best checkpoints
    "metric_for_best_model": "f1",
    "greater_is_better": True,
    "load_best_model_at_end": True,
    "fp16": True,  # Mixed precision training (faster, less memory)
    "seed": 42,
    "dataloader_num_workers": 2,
    "gradient_accumulation_steps": 1,
}

# ============================================================================
# CLASS IMBALANCE CONFIGURATION
# ============================================================================

CLASS_IMBALANCE_CONFIG = {
    "use_weighted_sampling": True,  # WeightedRandomSampler for balanced batches
    "use_class_weights": True,  # Class weights in loss function
    "safe_label": 0,
    "vulnerable_label": 1,
}

# ============================================================================
# DEVICE & HARDWARE
# ============================================================================

DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
DEVICE_CONFIG = {
    "device": DEVICE,
    "device_name": torch.cuda.get_device_name(0) if torch.cuda.is_available() else "CPU",
    "device_memory_gb": torch.cuda.get_device_properties(0).total_memory / 1e9 if torch.cuda.is_available() else 0,
}

# ============================================================================
# PATHS
# ============================================================================

PATHS = {
    "input_file": DATA_CONFIG["input_file"],
    "train_dataset": "data/train_dataset.arrow",
    "val_dataset": "data/val_dataset.arrow",
    "test_dataset": "data/test_dataset.arrow",
    "checkpoint_dir": TRAINING_CONFIG["output_dir"],
    "final_model_dir": "models/codebert_final",
    "training_log": "outputs/training_log.csv",
    "test_results": "outputs/test_results.json",
    "predictions": "outputs/predictions.json",
}

# ============================================================================
# PRINT CONFIGURATION
# ============================================================================

def print_config():
    """Print all configuration settings"""
    print("=" * 80)
    print("CODEBERT VULNERABILITY DETECTION - TRAINING CONFIGURATION")
    print("=" * 80)
    
    print("\n[DATA]")
    print(f"  Input file: {DATA_CONFIG['input_file']}")
    print(f"  Train/Val/Test split: {DATA_CONFIG['train_split']:.0%}/{DATA_CONFIG['val_split']:.0%}/{DATA_CONFIG['test_split']:.0%}")
    
    print("\n[MODEL]")
    print(f"  Model: {MODEL_CONFIG['model_name']}")
    print(f"  Max length: {MODEL_CONFIG['max_length']} tokens")
    print(f"  Labels: {MODEL_CONFIG['num_labels']} (safe=0, vulnerable=1)")
    
    print("\n[TRAINING]")
    print(f"  Batch size: {TRAINING_CONFIG['per_device_train_batch_size']}")
    print(f"  Learning rate: {TRAINING_CONFIG['learning_rate']}")
    print(f"  Epochs: {TRAINING_CONFIG['num_train_epochs']}")
    print(f"  Warmup steps: {TRAINING_CONFIG['warmup_steps']}")
    print(f"  Mixed precision (fp16): {TRAINING_CONFIG['fp16']}")
    
    print("\n[CLASS IMBALANCE]")
    print(f"  Weighted sampling: {CLASS_IMBALANCE_CONFIG['use_weighted_sampling']}")
    print(f"  Class weights: {CLASS_IMBALANCE_CONFIG['use_class_weights']}")
    
    print("\n[HARDWARE]")
    print(f"  Device: {DEVICE_CONFIG['device_name']}")
    if torch.cuda.is_available():
        print(f"  GPU Memory: {DEVICE_CONFIG['device_memory_gb']:.1f} GB")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    print_config()
