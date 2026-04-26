"""
Canary script — verify QLoRA environment before any training run.
Run this before every training session.
Expected output: ~1.77M trainable params (~1.4% of 125M)
"""

import sys
import torch


def check_cuda():
    print("[1] CUDA check...")
    if not torch.cuda.is_available():
        print("  FAIL: CUDA not available. Training requires a CUDA-capable GPU.")
        sys.exit(1)
    print(f"  OK: {torch.cuda.get_device_name(0)}")
    total_mb = torch.cuda.get_device_properties(0).total_memory / 1e6
    print(f"  OK: {total_mb:.0f} MB VRAM")
    print(f"  OK: CUDA {torch.version.cuda}")
    print(f"  OK: torch {torch.__version__}")


def check_bitsandbytes():
    print("\n[2] bitsandbytes check...")
    try:
        import bitsandbytes as bnb
        print(f"  OK: bitsandbytes {bnb.__version__}")
    except ImportError as e:
        print(f"  FAIL: bitsandbytes not installed — {e}")
        print("  Run: pip install bitsandbytes==0.45.3")
        sys.exit(1)

    # Verify GPU quantization actually works (not just import)
    try:
        _ = bnb.nn.Linear4bit(16, 16)
        print("  OK: Linear4bit layer created successfully")
    except Exception as e:
        print(f"  FAIL: bitsandbytes GPU quantization failed — {e}")
        print("  Likely cause: system CUDA toolkit not installed.")
        print("  Fix: install CUDA Toolkit 12.x from https://developer.nvidia.com/cuda-downloads")
        sys.exit(1)


def check_peft():
    print("\n[3] PEFT check...")
    try:
        import peft
        print(f"  OK: peft {peft.__version__}")
    except ImportError as e:
        print(f"  FAIL: peft not installed — {e}")
        print("  Run: pip install peft==0.14.0")
        sys.exit(1)


def check_qlora_pipeline():
    print("\n[4] QLoRA pipeline check (load CodeBERT + apply LoRA)...")
    try:
        from transformers import AutoModelForSequenceClassification, BitsAndBytesConfig
        from peft import get_peft_model, LoraConfig, TaskType

        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
            llm_int8_skip_modules=["classifier"],  # keep classifier head in fp32
        )

        print("  Loading CodeBERT in 4-bit NF4...")
        model = AutoModelForSequenceClassification.from_pretrained(
            "microsoft/codebert-base",
            num_labels=2,
            quantization_config=bnb_config,
        )
        print("  OK: CodeBERT loaded in 4-bit")

        lora_config = LoraConfig(
            r=16,
            lora_alpha=32,
            lora_dropout=0.05,
            bias="none",
            task_type=TaskType.SEQ_CLS,
            target_modules=["query", "key", "value", "attention.output.dense"],
        )

        model = get_peft_model(model, lora_config)
        trainable, total = model.get_nb_trainable_parameters()
        pct = 100 * trainable / total

        print(f"  OK: LoRA applied")
        print(f"  OK: Trainable params: {trainable:,} / {total:,} ({pct:.2f}%)")

        if trainable < 1_000_000:
            print(f"  WARN: Trainable param count seems low. Expected ~1.77M.")
        elif trainable > 5_000_000:
            print(f"  WARN: Trainable param count seems high. Expected ~1.77M.")
        else:
            print(f"  OK: Trainable param count in expected range (~1.77M)")

    except Exception as e:
        print(f"  FAIL: QLoRA pipeline error — {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


def main():
    print("=" * 60)
    print("QLoRA ENVIRONMENT VERIFICATION")
    print("=" * 60)

    check_cuda()
    check_bitsandbytes()
    check_peft()
    check_qlora_pipeline()

    print("\n" + "=" * 60)
    print("ALL CHECKS PASSED — environment is ready for QLoRA training")
    print("=" * 60)


if __name__ == "__main__":
    main()
