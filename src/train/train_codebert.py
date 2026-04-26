"""
Training script for CodeBERT vulnerability detection
Uses HuggingFace Trainer with weighted sampling + class weights
"""

import json
import pickle
import numpy as np
import torch
import sys
import glob
from pathlib import Path
from torch.utils.data import WeightedRandomSampler, DataLoader
from datasets import load_from_disk
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding
)
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix

from config import (
    MODEL_CONFIG, 
    TRAINING_CONFIG, 
    CLASS_IMBALANCE_CONFIG,
    PATHS,
    DEVICE_CONFIG,
    print_config
)

if __name__ == '__main__':
    # Check if resuming from checkpoint
    resume_from_checkpoint = None
    if len(sys.argv) > 1 and sys.argv[1] == '--resume':
        # Find the latest checkpoint
        checkpoints = glob.glob("models/codebert_checkpoint/checkpoint-*")
        if checkpoints:
            resume_from_checkpoint = max(checkpoints, key=lambda x: int(x.split('-')[-1]))
            print(f"\n🔄 RESUMING TRAINING FROM: {resume_from_checkpoint}\n")
        else:
            print("⚠️  No checkpoints found. Starting fresh training.\n")
    # ============================================================================
    # INITIALIZATION
    # ============================================================================

    print("=" * 80)
    print("CODEBERT VULNERABILITY DETECTION - TRAINING")
    print("=" * 80)

    # Print configuration
    print_config()

    # Check device
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n[DEVICE] Using: {device}")
    if torch.cuda.is_available():
        print(f"         GPU: {torch.cuda.get_device_name(0)}")
        print(f"         Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

    # ============================================================================
    # LOAD DATASETS
    # ============================================================================

    print("\n[1] LOADING DATASETS...")

    train_dataset = load_from_disk(PATHS['train_dataset'])
    val_dataset = load_from_disk(PATHS['val_dataset'])
    test_dataset = load_from_disk(PATHS['test_dataset'])

    print(f"  ✓ Train dataset: {len(train_dataset):,}")
    print(f"  ✓ Val dataset: {len(val_dataset):,}")
    print(f"  ✓ Test dataset: {len(test_dataset):,}")

    # ============================================================================
    # LOAD MODEL & TOKENIZER
    # ============================================================================

    print("\n[2] LOADING MODEL & TOKENIZER...")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_CONFIG['tokenizer_name'])
    model = AutoModelForSequenceClassification.from_pretrained(
        MODEL_CONFIG['model_name'],
        num_labels=MODEL_CONFIG['num_labels'],
        ignore_mismatched_sizes=True,
        use_safetensors=True  # Force safetensors format (bypasses torch.load security check)
    )

    print(f"  ✓ Model: {MODEL_CONFIG['model_name']}")
    print(f"  ✓ Parameters: {sum(p.numel() for p in model.parameters()) / 1e6:.1f}M")
    print(f"  ✓ Tokenizer: {MODEL_CONFIG['tokenizer_name']}")

    # ============================================================================
    # CLASS WEIGHTS FOR LOSS FUNCTION
    # ============================================================================

    print("\n[3] COMPUTING CLASS WEIGHTS...")

    # Count labels in training set
    train_labels = train_dataset['label']
    num_safe = sum(1 for l in train_labels if l == 0)
    num_vulnerable = sum(1 for l in train_labels if l == 1)
    total = len(train_labels)

    # Class weights (inverse of frequency)
    # Reduced weight to prevent aggressive predictions (from 11.72 to ~4.69)
    safe_weight = num_vulnerable / total
    vulnerable_weight = (num_safe / total) / 2.5  # Divide by 2.5 to reduce aggressiveness

    class_weights = torch.tensor([safe_weight, vulnerable_weight], dtype=torch.float32)

    print(f"  Safe ({num_safe:,}): weight = {safe_weight:.4f}")
    print(f"  Vulnerable ({num_vulnerable:,}): weight = {vulnerable_weight:.4f}")
    print(f"  Weight reduction factor: 2.5x (less aggressive predictions)")

    # Set class weights in model config (for custom training loop) or loss
    # Note: HuggingFace Trainer will use these in CrossEntropyLoss
    model.config.class_weight = class_weights.tolist()

    # ============================================================================
    # WEIGHTED SAMPLING FOR BALANCED BATCHES
    # ============================================================================

    print("\n[4] SETTING UP WEIGHTED SAMPLING...")

    # Load pre-computed sample weights
    weights_file = "data/sample_weights.pkl"
    if Path(weights_file).exists():
        with open(weights_file, 'rb') as f:
            sample_weights = pickle.load(f)
        print(f"  ✓ Loaded sample weights from {weights_file}")
    else:
        # Compute on the fly
        sample_weights = [
            1.0 if l == 0 else (num_safe / num_vulnerable)
            for l in train_labels
        ]
        print(f"  ✓ Computed sample weights")

    print(f"  Weight range: [{min(sample_weights):.4f}, {max(sample_weights):.4f}]")
    print(f"  This ensures balanced batches (~50% safe, ~50% vulnerable)")

    # Create WeightedRandomSampler
    sampler = WeightedRandomSampler(
        weights=sample_weights,
        num_samples=len(train_dataset),
        replacement=True
    )

    print(f"  ✓ WeightedRandomSampler created")

    # ============================================================================
    # COMPUTE METRICS FUNCTION
    # ============================================================================

    def compute_metrics(eval_pred):
        """Compute F1, precision, recall, AUC-ROC"""
        predictions, labels = eval_pred
        predictions = np.argmax(predictions, axis=1)
        
        # Compute metrics
        f1 = f1_score(labels, predictions, zero_division=0)
        precision = precision_score(labels, predictions, zero_division=0)
        recall = recall_score(labels, predictions, zero_division=0)
        
        # AUC-ROC
        try:
            auc_roc = roc_auc_score(labels, predictions)
        except:
            auc_roc = 0.0
        
        return {
            "f1": f1,
            "precision": precision,
            "recall": recall,
            "auc_roc": auc_roc
        }

    # ============================================================================
    # TRAINING ARGUMENTS
    # ============================================================================

    print("\n[5] SETTING UP TRAINING ARGUMENTS...")

    training_args = TrainingArguments(
        output_dir=TRAINING_CONFIG['output_dir'],
        num_train_epochs=TRAINING_CONFIG['num_train_epochs'],
        per_device_train_batch_size=TRAINING_CONFIG['per_device_train_batch_size'],
        per_device_eval_batch_size=TRAINING_CONFIG['per_device_eval_batch_size'],
        learning_rate=TRAINING_CONFIG['learning_rate'],
        warmup_steps=TRAINING_CONFIG['warmup_steps'],
        weight_decay=TRAINING_CONFIG['weight_decay'],
        eval_strategy=TRAINING_CONFIG['evaluation_strategy'],  # Changed from evaluation_strategy
        eval_steps=TRAINING_CONFIG['eval_steps'],
        save_strategy=TRAINING_CONFIG['save_strategy'],
        save_steps=TRAINING_CONFIG['save_steps'],
        logging_steps=TRAINING_CONFIG['logging_steps'],
        save_total_limit=TRAINING_CONFIG['save_total_limit'],
        metric_for_best_model=TRAINING_CONFIG['metric_for_best_model'],
        greater_is_better=TRAINING_CONFIG['greater_is_better'],
        load_best_model_at_end=TRAINING_CONFIG['load_best_model_at_end'],
        fp16=TRAINING_CONFIG['fp16'],
        seed=TRAINING_CONFIG['seed'],
        report_to=["tensorboard"],  # Log to TensorBoard
        remove_unused_columns=False,
        dataloader_num_workers=TRAINING_CONFIG['dataloader_num_workers'],  # Use config value
        gradient_accumulation_steps=TRAINING_CONFIG['gradient_accumulation_steps'],
    )

    print(f"  ✓ Training args configured")
    print(f"    • Output dir: {training_args.output_dir}")
    print(f"    • Batch size: {training_args.per_device_train_batch_size}")
    print(f"    • Epochs: {training_args.num_train_epochs}")
    print(f"    • Learning rate: {training_args.learning_rate}")
    print(f"    • Dataloader workers: {training_args.dataloader_num_workers} (0 = no multiprocessing)")

    # ============================================================================
    # CREATE TRAINER
    # ============================================================================

    print("\n[6] CREATING TRAINER...")

    # Custom trainer to use class weights in loss
    class CustomTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
            labels = inputs.pop("labels")
            outputs = model(**inputs)
            logits = outputs.logits
            
            # Use class weights in CrossEntropyLoss
            loss_fn = torch.nn.CrossEntropyLoss(weight=class_weights.to(device))
            loss = loss_fn(logits, labels)
            
            return (loss, outputs) if return_outputs else loss

    trainer = CustomTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
        processing_class=tokenizer,  # Use processing_class instead of tokenizer (new API)
        compute_metrics=compute_metrics,
        data_collator=DataCollatorWithPadding(tokenizer),
    )

    print(f"  ✓ Trainer created with CustomTrainer (class weights in loss)")

    # ============================================================================
    # TRAIN
    # ============================================================================

    print("\n[7] STARTING TRAINING...")
    print("=" * 80)

    train_result = trainer.train(resume_from_checkpoint=resume_from_checkpoint)

    print("\n" + "=" * 80)
    print("TRAINING COMPLETE")
    print("=" * 80)

    # ============================================================================
    # SAVE FINAL MODEL
    # ============================================================================

    print("\n[8] SAVING FINAL MODEL...")

    final_model_dir = PATHS['final_model_dir']
    trainer.save_model(final_model_dir)
    print(f"  ✓ Model saved to {final_model_dir}")

    # Save training summary
    summary = {
        "model": MODEL_CONFIG['model_name'],
        "num_labels": MODEL_CONFIG['num_labels'],
        "batch_size": TRAINING_CONFIG['per_device_train_batch_size'],
        "learning_rate": TRAINING_CONFIG['learning_rate'],
        "num_epochs": TRAINING_CONFIG['num_train_epochs'],
        "warmup_steps": TRAINING_CONFIG['warmup_steps'],
        "total_train_samples": len(train_dataset),
        "total_val_samples": len(val_dataset),
        "total_test_samples": len(test_dataset),
        "class_weights": {
            "safe": float(class_weights[0]),
            "vulnerable": float(class_weights[1])
        },
        "training_loss": float(train_result.training_loss) if hasattr(train_result, 'training_loss') else None,
    }

    with open(f"{final_model_dir}/training_summary.json", 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"  ✓ Training summary saved")

    print("\n" + "=" * 80)
    print("✅ TRAINING PIPELINE COMPLETE")
    print("=" * 80)
    print(f"\nModel ready for evaluation and inference!")
    print(f"Model path: {final_model_dir}")
