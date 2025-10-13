"""
Vulnerability Detection Model - Production Ready
Handles model loading and inference
"""
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from pathlib import Path
from typing import Dict, List, Optional, Union
import logging
import json

logger = logging.getLogger(__name__)


class VulnerabilityDetector:
    """Production-ready vulnerability detection model"""
    
    def __init__(self, model_path: str = "models/production/vuln_detector"):
        """
        Initialize detector with trained model
        
        Args:
            model_path: Path to saved model directory
        """
        self.model_path = Path(model_path)
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.tokenizer = None
        self.config = None
        
        logger.info(f"Using device: {self.device}")
        
        # Load model if path exists
        if self.model_path.exists():
            self.load_model()
    
    def load_model(self):
        """Load model and tokenizer from checkpoint"""
        try:
            logger.info(f"Loading model from {self.model_path}")
            
            self.tokenizer = AutoTokenizer.from_pretrained(str(self.model_path))
            self.model = AutoModelForSequenceClassification.from_pretrained(
                str(self.model_path)
            )
            self.model.to(self.device)
            self.model.eval()
            
            # Load metrics if available
            metrics_path = self.model_path / "metrics.json"
            if metrics_path.exists():
                with open(metrics_path, 'r') as f:
                    self.config = json.load(f)
            
            logger.info("✅ Model loaded successfully")
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            raise
    
    def predict(self, code: str, return_probabilities: bool = False) -> Dict:
        """
        Predict if code is vulnerable
        
        Args:
            code: Source code string
            return_probabilities: Include probability scores
            
        Returns:
            Prediction dictionary with vulnerability status and confidence
        """
        if self.model is None:
            raise RuntimeError("Model not loaded. Call load_model() first.")
        
        try:
            # Tokenize
            inputs = self.tokenizer(
                code,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=512
            ).to(self.device)
            
            # Predict
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probs = torch.softmax(logits, dim=-1)
                prediction = torch.argmax(probs, dim=-1).item()
                confidence = probs[0][prediction].item()
            
            result = {
                'vulnerable': bool(prediction),
                'confidence': float(confidence),
            }
            
            if return_probabilities:
                result['probability_safe'] = float(probs[0][0])
                result['probability_vulnerable'] = float(probs[0][1])
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'vulnerable': False,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def predict_batch(self, codes: List[str], batch_size: int = 16) -> List[Dict]:
        """
        Predict vulnerabilities for multiple code samples
        
        Args:
            codes: List of source code strings
            batch_size: Batch size for inference
            
        Returns:
            List of prediction dictionaries
        """
        if self.model is None:
            raise RuntimeError("Model not loaded")
        
        results = []
        
        for i in range(0, len(codes), batch_size):
            batch = codes[i:i + batch_size]
            
            # Tokenize batch
            inputs = self.tokenizer(
                batch,
                return_tensors="pt",
                padding=True,
                truncation=True,
                max_length=512
            ).to(self.device)
            
            # Predict
            with torch.no_grad():
                outputs = self.model(**inputs)
                probs = torch.softmax(outputs.logits, dim=-1)
                predictions = torch.argmax(probs, dim=-1)
            
            # Convert to results
            for j, pred in enumerate(predictions):
                results.append({
                    'vulnerable': bool(pred.item()),
                    'confidence': float(probs[j][pred].item()),
                    'probability_safe': float(probs[j][0]),
                    'probability_vulnerable': float(probs[j][1])
                })
        
        return results
    
    def get_model_info(self) -> Dict:
        """Get model information and metrics"""
        info = {
            'model_path': str(self.model_path),
            'device': str(self.device),
            'loaded': self.model is not None
        }
        
        if self.config:
            info['metrics'] = self.config
        
        return info


# Singleton instance
_detector_instance = None

def get_detector(model_path: str = "models/production/vuln_detector") -> VulnerabilityDetector:
    """Get or create global detector instance"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = VulnerabilityDetector(model_path)
    return _detector_instance


# CLI test
if __name__ == "__main__":
    detector = VulnerabilityDetector()
    
    test_codes = [
        "query = 'SELECT * FROM users WHERE id=' + user_id",
        "query = 'SELECT * FROM users WHERE id=?'; execute(query, (user_id,))"
    ]
    
    print("Testing vulnerability detection:\n")
    for i, code in enumerate(test_codes, 1):
        result = detector.predict(code, return_probabilities=True)
        print(f"Test {i}:")
        print(f"  Code: {code[:50]}...")
        print(f"  Vulnerable: {result['vulnerable']}")
        print(f"  Confidence: {result['confidence']:.2%}")
        print()