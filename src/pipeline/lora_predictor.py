"""
LoRA adapter inference wrapper for vulnerability detection.
Matches the interface of Run12Predictor for easy integration into CombinedAnalyzer.

Handles:
  - Loading the frozen CodeBERT base + LoRA adapter weights
  - Code preprocessing (comment stripping, whitespace normalization)
  - Sliding window inference for functions > 512 tokens
  - Threshold-based binary prediction (threshold loaded from adapter dir)
"""

import json
import re
from pathlib import Path

import torch
from peft import PeftModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

ADAPTER_DIR = "models/lora_adapter"
BASE_MODEL = "microsoft/codebert-base"
MAX_LENGTH = 512
WINDOW = 512
STRIDE = 256
NUM_LABELS = 2
DEFAULT_THRESHOLD = 0.50  # fallback if threshold.json not found


# ---------------------------------------------------------------------------
# Preprocessing (matches prepare_lora_data.py)
# ---------------------------------------------------------------------------

def _strip_comments(code: str) -> str:
    result = []
    i = 0
    in_string = False
    in_char = False
    while i < len(code):
        c = code[i]
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
        if c == "/" and i + 1 < len(code) and code[i + 1] == "/":
            while i < len(code) and code[i] != "\n":
                i += 1
            continue
        if c == "/" and i + 1 < len(code) and code[i + 1] == "*":
            i += 2
            while i + 1 < len(code) and not (code[i] == "*" and code[i + 1] == "/"):
                i += 1
            i += 2
            continue
        result.append(c)
        i += 1
    return "".join(result)


def _preprocess(code: str) -> str:
    code = _strip_comments(code)
    return re.sub(r"\s+", " ", code).strip()


# ---------------------------------------------------------------------------
# LoRAPredictor
# ---------------------------------------------------------------------------

class LoRAPredictor:
    """
    Wraps a trained QLoRA CodeBERT adapter for vulnerability inference.

    Usage:
        predictor = LoRAPredictor()
        result = predictor.predict("void f() { char buf[10]; gets(buf); }")
        # {'is_vulnerable': True, 'confidence': 0.87, 'model': 'lora_adapter'}
    """

    def __init__(self, adapter_path: str = ADAPTER_DIR):
        self.adapter_path = adapter_path
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        # Load threshold from adapter directory
        threshold_file = Path(adapter_path) / "threshold.json"
        if threshold_file.exists():
            with open(threshold_file) as f:
                self.threshold = json.load(f)["threshold"]
        else:
            self.threshold = DEFAULT_THRESHOLD

        # Load base CodeBERT + attach adapter (no quantization at inference time)
        base = AutoModelForSequenceClassification.from_pretrained(
            BASE_MODEL,
            num_labels=NUM_LABELS,
        )
        self.model = PeftModel.from_pretrained(base, adapter_path)
        self.model.eval()
        self.model.to(self.device)

        self.tokenizer = AutoTokenizer.from_pretrained(adapter_path)

    def predict(self, code: str) -> dict:
        """
        Predict whether code is vulnerable.

        Returns:
            {
                'is_vulnerable': bool,
                'confidence': float,  # probability of vulnerable class
                'model': 'lora_adapter'
            }
        """
        code = _preprocess(code)
        token_ids = self.tokenizer.encode(code, add_special_tokens=False)

        if len(token_ids) <= MAX_LENGTH - 2:
            prob = self._forward_text(code)
        else:
            prob = self._sliding_window_predict(token_ids)

        is_vulnerable = prob >= self.threshold
        return {
            "is_vulnerable": bool(is_vulnerable),
            "confidence": round(float(prob), 4),
            "model": "lora_adapter",
        }

    def _forward_text(self, text: str) -> float:
        """Tokenize and run a single forward pass. Returns vulnerable probability."""
        inputs = self.tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=MAX_LENGTH,
            padding="max_length",
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}

        with torch.no_grad():
            logits = self.model(**inputs).logits
            prob = torch.softmax(logits, dim=-1)[0][1].item()

        return prob

    def _sliding_window_predict(self, token_ids: list) -> float:
        """
        Run sliding window over long function, return max vulnerable probability.
        Vulnerable if ANY window looks vulnerable (conservative for security).
        """
        probs = []
        start = 0
        window = MAX_LENGTH - 2  # -2 for [CLS] and [SEP]

        while start < len(token_ids):
            end = min(start + window, len(token_ids))
            chunk_ids = token_ids[start:end]
            chunk_text = self.tokenizer.decode(chunk_ids, skip_special_tokens=True)
            probs.append(self._forward_text(chunk_text))
            if end == len(token_ids):
                break
            start += STRIDE

        return max(probs)
