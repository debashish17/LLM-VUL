"""
Continue training from the last checkpoint for an additional epoch
Run this after evaluating the 2-epoch model if F1 < 0.70
"""

import os
import glob
from pathlib import Path

# Find the latest checkpoint
checkpoint_dir = "models/codebert_checkpoint"
checkpoints = glob.glob(f"{checkpoint_dir}/checkpoint-*")

if not checkpoints:
    print("❌ No checkpoints found! Train the model first.")
    exit(1)

# Get the most recent checkpoint (highest step number)
latest_checkpoint = max(checkpoints, key=lambda x: int(x.split('-')[-1]))

print("=" * 80)
print("CONTINUE TRAINING FROM CHECKPOINT")
print("=" * 80)
print(f"\n📁 Resuming from: {latest_checkpoint}")
print(f"⚠️  Make sure config.py has num_train_epochs = 3")
print(f"\nTo continue training:")
print(f"  1. Update config.py: num_train_epochs = 3")
print(f"  2. Run the command below:\n")

# Print the command to continue training
print(f"python src/train/train_codebert.py --resume_from_checkpoint {latest_checkpoint}")
print("\n" + "=" * 80)
