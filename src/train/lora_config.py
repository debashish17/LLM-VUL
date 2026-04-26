"""
Centralized configuration for QLoRA fine-tuning of CodeBERT.
All hyperparameters live here — do not scatter them across training scripts.
"""

import torch
from peft import LoraConfig, TaskType  # peft==0.18.1
from transformers import BitsAndBytesConfig  # bitsandbytes==0.49.2

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
LORA_PATHS = {
    "train_dataset": "data/lora/train_dataset",
    "val_dataset": "data/lora/val_dataset",
    "test_dataset": "data/lora/test_dataset",
    "checkpoint_dir": "models/lora_checkpoint",
    "adapter_dir": "models/lora_adapter",
    "eval_results": "outputs/lora_eval.json",
}

# ---------------------------------------------------------------------------
# Base model
# ---------------------------------------------------------------------------
BASE_MODEL = "microsoft/codebert-base"
NUM_LABELS = 2   # 0=safe, 1=vulnerable
MAX_LENGTH = 512

# ---------------------------------------------------------------------------
# 4-bit NF4 quantization config (QLoRA)
#
# Notes:
#   - NF4: information-theoretically optimal for normally-distributed weights
#   - double_quant: quantizes the quantization constants, saves ~0.4 GB extra
#   - bfloat16 compute: stable on Ampere (RTX 4050); do NOT use float16 with QLoRA
# ---------------------------------------------------------------------------
BNB_CONFIG = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",
    bnb_4bit_use_double_quant=True,
    bnb_4bit_compute_dtype=torch.bfloat16,
    llm_int8_skip_modules=["classifier"],  # keep classifier head in fp32, not 4-bit
)

# ---------------------------------------------------------------------------
# LoRA adapter config
#
# target_modules: substring-matched across all 12 RoBERTa layers.
#   "query", "key", "value" → attention projections (Q/K/V)
#   "dense"                 → attention output + intermediate + output dense layers
#   Total: 72 LoRA pairs → ~1.77M trainable params (~1.4% of 125M)
#
# target_modules uses full suffix paths to avoid matching classifier.dense.
# "dense" as a substring also matches classifier.dense inside the classification
# head, which causes a bitsandbytes 4-bit quant state assertion error at runtime.
# Using "attention.output.dense" restricts LoRA to encoder layers only.
# The classifier head is unfrozen manually in train_lora.py after get_peft_model().
# ---------------------------------------------------------------------------
LORA_CONFIG = LoraConfig(
    r=16,
    lora_alpha=32,            # scale = alpha/r = 2.0 (standard 2× rule)
    lora_dropout=0.05,
    bias="none",
    task_type=TaskType.SEQ_CLS,
    target_modules=["query", "key", "value", "attention.output.dense"],
)

# ---------------------------------------------------------------------------
# Training hyperparameters
#
# Key decisions:
#   - batch=4, grad_accum=16  → effective batch size 64 (stable for transformers)
#   - lr=2e-4                 → LoRA adapters start from zero and need faster movement
#   - cosine LR + 6% warmup   → empirically best for transformer fine-tuning
#   - bf16=True, fp16=False   → QLoRA uses bfloat16 internally; mixing fp16 causes NaN
#   - optim=paged_adamw_8bit  → paged to CPU RAM when not needed (VRAM safety buffer)
#   - gradient_checkpointing  → saves ~40% VRAM at ~20% compute cost; non-optional at 6GB
#   - dataloader_num_workers=0 → Windows: multiprocessing spawn hangs with HF datasets
# ---------------------------------------------------------------------------
LORA_TRAIN_CONFIG = {
    "output_dir": LORA_PATHS["checkpoint_dir"],
    "per_device_train_batch_size": 4,
    "per_device_eval_batch_size": 8,
    "gradient_accumulation_steps": 16,
    "learning_rate": 2e-4,
    "num_train_epochs": 5,
    "warmup_steps": 100,
    "lr_scheduler_type": "cosine",
    "gradient_checkpointing": True,
    "optim": "paged_adamw_8bit",
    "fp16": False,
    "bf16": True,
    "metric_for_best_model": "f1",
    "greater_is_better": True,
    "load_best_model_at_end": True,
    "save_total_limit": 2,
    "eval_strategy": "epoch",
    "save_strategy": "epoch",
    "logging_steps": 50,
    "seed": 42,
    "dataloader_num_workers": 0,
    "remove_unused_columns": False,
    "report_to": ["tensorboard"],
}

# Validation-mode overrides (10% data, 2 epochs — pipeline smoke test)
LORA_VALIDATION_OVERRIDES = {
    "num_train_epochs": 2,
    "logging_steps": 10,
    "eval_strategy": "epoch",
    "save_strategy": "epoch",
}

# Tuning-mode overrides (Run 3 — targeted adjustment)
LORA_TUNING_OVERRIDES = {
    "num_train_epochs": 3,
}

# ---------------------------------------------------------------------------
# Focal loss
#
# alpha=0.75: weights the POSITIVE (vulnerable) class.
#   NOTE: the original RetinaNet paper uses alpha=0.25 which weights the
#   NEGATIVE class. We invert this because vulnerable is our minority class.
# gamma=2.0: standard value, focuses learning on hard/uncertain examples.
# ---------------------------------------------------------------------------
FOCAL_CONFIG = {
    "gamma": 2.0,
    "alpha": 0.75,
}


def print_config():
    print("=" * 70)
    print("LORA TRAINING CONFIGURATION")
    print("=" * 70)
    print(f"\n  Base model : {BASE_MODEL}")
    print(f"  Max length : {MAX_LENGTH}")
    print(f"  LoRA rank  : {LORA_CONFIG.r}")
    print(f"  LoRA alpha : {LORA_CONFIG.lora_alpha}")
    print(f"  LoRA target: {LORA_CONFIG.target_modules}")
    print(f"\n  Batch size : {LORA_TRAIN_CONFIG['per_device_train_batch_size']}")
    print(f"  Grad accum : {LORA_TRAIN_CONFIG['gradient_accumulation_steps']}")
    print(f"  Eff. batch : {LORA_TRAIN_CONFIG['per_device_train_batch_size'] * LORA_TRAIN_CONFIG['gradient_accumulation_steps']}")
    print(f"  LR         : {LORA_TRAIN_CONFIG['learning_rate']}")
    print(f"  Epochs     : {LORA_TRAIN_CONFIG['num_train_epochs']}")
    print(f"  Optimizer  : {LORA_TRAIN_CONFIG['optim']}")
    print(f"\n  Focal gamma: {FOCAL_CONFIG['gamma']}")
    print(f"  Focal alpha: {FOCAL_CONFIG['alpha']} (weights vulnerable class)")
    print("=" * 70)
