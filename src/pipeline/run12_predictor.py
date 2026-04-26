"""
Run 12 Vulnerability Predictor - Wrapper for 304-feature ensemble model
Handles: 240 engineered + 32 CodeBERT + 32 GraphCodeBERT features
Uses the trained ensemble from models/ensemble_boosting/
"""

import numpy as np
import pickle
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from models.ensemble_boosting.feature_engineer import FeatureEngineer
from models.ensemble_boosting.embedding_generator import EmbeddingGenerator

logger = logging.getLogger(__name__)

class Run12Predictor:
    """
    Run 12 vulnerability prediction using pre-trained ensemble models.
    Extracts features exactly as the demo does for consistency.
    """
    
    def __init__(self, models_dir: str = None):
        """
        Initialize Run 12 predictor with trained models.
        
        Args:
            models_dir: Path to models/saved_models directory (auto-detected if None)
        """
        if models_dir is None:
            models_dir = str(Path(__file__).parent.parent.parent / 'models' / 'saved_models')
        
        self.models_dir = Path(models_dir)
        self._load_models()
    
    def _load_models(self):
        """Load all Run 12 artifacts from disk."""
        logger.info("Loading Run 12 models (304 features: 240 engineered + 32 CodeBERT + 32 GraphCodeBERT)...")
        
        # Load 4 ensemble models
        self.models = {}
        model_names = ['xgb_conservative', 'xgb_aggressive', 'lgb_balanced', 'catboost']
        
        for name in model_names:
            model_path = self.models_dir / f'{name}.pkl'
            with open(model_path, 'rb') as f:
                self.models[name] = pickle.load(f)
            logger.info(f"  ✓ {name}")
        
        # Load preprocessing artifacts
        with open(self.models_dir / 'scaler.pkl', 'rb') as f:
            self.scaler = pickle.load(f)
        
        with open(self.models_dir / 'pca_model.pkl', 'rb') as f:
            self.pca_codebert = pickle.load(f)
        
        with open(self.models_dir / 'graphcodebert_pca_model.pkl', 'rb') as f:
            self.pca_graphcodebert = pickle.load(f)
        
        with open(self.models_dir / 'calibrator.pkl', 'rb') as f:
            self.calibrator = pickle.load(f)
        
        # Load weights and threshold
        with open(self.models_dir / 'optimal_weights.json', 'r') as f:
            weights_config = json.load(f)
        
        # Handle both formats: {weights: {...}} and direct {model: weight, ...}
        if 'weights' in weights_config:
            self.weights = weights_config['weights']
        else:
            # Assume direct format (backward compatibility)
            self.weights = {k: v for k, v in weights_config.items() if k not in ['threshold', 'val_f1', 'calibrated', 'noise_detection', 'graphcodebert', 'n_features']}
        
        # Get threshold 
        if 'threshold' in weights_config:
            self.threshold = weights_config['threshold']
        else:
            self.threshold = 0.308
        
        logger.info(f"Model weights: {list(self.weights.keys())}")
        logger.info(f"Threshold: {self.threshold}")
        
        # Initialize feature extractors
        self.feature_eng = FeatureEngineer()
        
        self.codebert_gen = EmbeddingGenerator(
            config_override={
                'model_name': 'models/codebert_final',
                'batch_size': 8,
                'max_length': 512
            }
        )
        self.codebert_gen.load_model()
        
        self.graphcodebert_gen = EmbeddingGenerator(
            config_override={
                'model_name': 'models/graphcodebert-base',
                'batch_size': 8,
                'max_length': 512
            }
        )
        self.graphcodebert_gen.load_model()
        
        logger.info("Model loading complete!")
    
    def _extract_features(self, codes: List[str]) -> np.ndarray:
        """
        Extract 304 features (240 engineered + 32 CodeBERT + 32 GraphCodeBERT).
        
        Args:
            codes: List of code strings
            
        Returns:
            Feature matrix (n_samples, 304)
        """
        # Step 1: Engineered features (240)
        logger.info("Extracting engineered features...")
        records = [{'func': code, 'target': 0} for code in codes]
        # Disable show_progress over stdout since it messes with the frontend streaming
        features = self.feature_eng.extract_from_records(records, show_progress=False)
        
        # Step 2: CodeBERT embeddings (32 via PCA)
        logger.info("Generating CodeBERT embeddings...")
        batch_size = 8
        codebert_embeddings = []
        for i in range(0, len(codes), batch_size):
            batch = codes[i:i+batch_size]
            batch_emb = self.codebert_gen.generate_batch_embeddings(batch)
            codebert_embeddings.append(batch_emb)
        codebert_embeddings = np.vstack(codebert_embeddings)
        codebert_pca = self.pca_codebert.transform(codebert_embeddings)
        
        # Step 3: GraphCodeBERT embeddings (32 via PCA)
        logger.info("Generating GraphCodeBERT embeddings...")
        graphcodebert_embeddings = []
        for i in range(0, len(codes), batch_size):
            batch = codes[i:i+batch_size]
            batch_emb = self.graphcodebert_gen.generate_batch_embeddings(batch)
            graphcodebert_embeddings.append(batch_emb)
        graphcodebert_embeddings = np.vstack(graphcodebert_embeddings)
        graphcodebert_pca = self.pca_graphcodebert.transform(graphcodebert_embeddings)
        
        # Step 4: Combine all features (304 total)
        all_features = np.hstack([features, codebert_pca, graphcodebert_pca])
        
        # Step 5: Scale
        all_features_scaled = self.scaler.transform(all_features)
        
        return all_features_scaled
    
    def predict(self, codes: List[str], threshold: float = None) -> List[Dict[str, Any]]:
        """
        Predict vulnerabilities for a list of code snippets.
        
        Args:
            codes: List of code strings
            threshold: Classification threshold (uses optimal if None)
            
        Returns:
            List of prediction dicts with:
                - is_vulnerable: bool
                - confidence: float (0-1)
                - label: str ('VULNERABLE' or 'SAFE')
                - individual_models: dict of model scores
        """
        if threshold is None:
            threshold = self.threshold
        
        # Extract features
        features_scaled = self._extract_features(codes)
        
        # Get predictions from all models
        proba_ensemble = np.zeros(len(codes))
        individual_scores = {}
        
        # Pre-load CUDA tensor to feed GPU-bound XGBoost directly and avoid DMatrix CPU->GPU fallback warning
        import torch
        has_cuda = torch.cuda.is_available()
        features_cuda = torch.tensor(features_scaled, dtype=torch.float32, device='cuda:0') if has_cuda else None
        
        for model_name, model in self.models.items():
            if model_name not in self.weights:
                raise KeyError(f"Model '{model_name}' not found in weights. Available: {list(self.weights.keys())}")
            weight = self.weights[model_name]
            
            if model_name.startswith('xgb') and has_cuda:
                try:
                    # Pass the GPU-bound tensor to XGBoost to satisfy device mismatch
                    proba_raw = model.predict_proba(features_cuda)
                    if hasattr(proba_raw, 'cpu'):
                        proba_raw = proba_raw.cpu().numpy()
                    proba = proba_raw[:, 1]
                except Exception as e:
                    logger.warning(f"CUDA prediction failed for {model_name}, falling back to CPU: {e}")
                    proba = model.predict_proba(features_scaled)[:, 1]
            else:
                proba = model.predict_proba(features_scaled)[:, 1]
                
            proba_ensemble += weight * proba
            individual_scores[model_name] = proba
        
        # Calibrate probabilities
        logger.info("Calibrating probabilities...")
        proba_calibrated = self.calibrator.transform(proba_ensemble.reshape(-1, 1)).flatten()
        
        # Generate predictions
        predictions = (proba_calibrated >= threshold).astype(int)
        
        # Build results
        results = []
        for idx, (code, pred, conf) in enumerate(zip(codes, predictions, proba_calibrated)):
            results.append({
                'code': code,
                'is_vulnerable': bool(pred),
                'confidence': float(conf),
                'label': 'VULNERABLE' if pred == 1 else 'SAFE',
                'threshold': threshold,
                'individual_models': {
                    name: float(individual_scores[name][idx]) 
                    for name in self.models.keys()
                }
            })
        
        return results
    
    def predict_single(self, code: str, threshold: float = None) -> Dict[str, Any]:
        """
        Predict vulnerability for a single code snippet.
        
        Args:
            code: Code string
            threshold: Classification threshold (uses optimal if None)
            
        Returns:
            Single prediction dict
        """
        results = self.predict([code], threshold)
        return results[0]
