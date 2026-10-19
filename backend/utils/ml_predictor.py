"""
ML Model Predictor
Uses trained models to classify network flows
"""
import joblib
import logging
import numpy as np
from pathlib import Path
from typing import Dict, Optional, Tuple
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class NetworkDNN(nn.Module):
    """PyTorch DNN for network traffic classification"""
    def __init__(self, input_size=46, num_classes=8):
        super(NetworkDNN, self).__init__()
        self.fc1 = nn.Linear(input_size, 128)
        self.bn1 = nn.LayerNorm(128)
        self.fc2 = nn.Linear(128, 64)
        self.bn2 = nn.LayerNorm(64)
        self.fc3 = nn.Linear(64, 32)
        self.bn3 = nn.LayerNorm(32)
        self.fc4 = nn.Linear(32, num_classes)
        self.dropout = nn.Dropout(0.3)
        
    def forward(self, x):
        x = torch.relu(self.bn1(self.fc1(x)))
        x = self.dropout(x)
        x = torch.relu(self.bn2(self.fc2(x)))
        x = self.dropout(x)
        x = torch.relu(self.bn3(self.fc3(x)))
        x = self.dropout(x)
        x = self.fc4(x)
        return x


class MLPredictor:
    """Predicts network traffic classification using trained models"""
    
    def __init__(self, models_dir: str = 'models'):
        self.models_dir = Path(models_dir)
        self.rf_model = None
        self.dnn_model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = []
        self.is_loaded = False
        
    def load_models(self) -> bool:
        """Load trained ML models from disk"""
        try:
            # Load Random Forest
            rf_path = self.models_dir / 'network_rf_model.pkl'
            if rf_path.exists():
                self.rf_model = joblib.load(rf_path)
                # Fix scikit-learn version incompatibility (1.3.2 -> 1.5.2)
                # Remove monotonic_cst attribute if it exists
                if hasattr(self.rf_model, 'monotonic_cst'):
                    delattr(self.rf_model, 'monotonic_cst')
                # Also check for DecisionTreeClassifier inside RandomForest
                if hasattr(self.rf_model, 'estimators_'):
                    for estimator in self.rf_model.estimators_:
                        if hasattr(estimator, 'monotonic_cst'):
                            delattr(estimator, 'monotonic_cst')
                logger.info("Loaded Random Forest model")
            else:
                logger.warning(f"RF model not found: {rf_path}")

            # Skip DNN for now - use RF only (93% accuracy)
            # DNN model has architecture mismatch - requires retraining
            self.dnn_model = None
            logger.info("Using Random Forest model only (93% accuracy)")

            # Load scaler
            scaler_path = self.models_dir / 'network_scaler.pkl'
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                logger.info("Loaded scaler")
            else:
                logger.warning(f"Scaler not found: {scaler_path}")

            # Load label encoder
            encoder_path = self.models_dir / 'network_label_encoder.pkl'
            if encoder_path.exists():
                self.label_encoder = joblib.load(encoder_path)
                logger.info("Loaded label encoder")
            else:
                logger.warning(f"Label encoder not found: {encoder_path}")

            # Load feature names from model info
            model_info_path = self.models_dir / 'network_model_info.json'
            if model_info_path.exists():
                import json
                with open(model_info_path) as f:
                    model_info = json.load(f)
                    self.feature_names = model_info.get('features', [])
                logger.info(f"Loaded {len(self.feature_names)} feature names")

            self.is_loaded = (self.rf_model is not None) or (self.dnn_model is not None)
            return self.is_loaded

        except Exception as e:
            logger.error(f"Error loading models: {e}")
            return False
    
    def predict(self, features: Dict) -> Dict:
        """
        Predict classification for flow features
        
        Args:
            features: Dictionary of flow features
            
        Returns:
            Dictionary with prediction results
        """
        if not self.is_loaded:
            logger.warning("Models not loaded, cannot predict")
            return {
                'prediction': 'UNKNOWN',
                'confidence': 0,
                'is_anomaly': False,
                'anomaly_score': 0,
                'model': 'not_loaded'
            }
        
        try:
            # Convert features to feature vector in correct order
            feature_vector = self._features_to_vector(features)
            
            if feature_vector is None:
                logger.error("Could not convert features to vector")
                return {
                    'prediction': 'UNKNOWN',
                    'confidence': 0,
                    'is_anomaly': False,
                    'anomaly_score': 0,
                    'model': 'feature_error'
                }
            
            # Scale features
            if self.scaler:
                feature_vector = self.scaler.transform([feature_vector])[0]
            
            # Get predictions from both models
            rf_result = self._predict_rf(feature_vector)
            dnn_result = self._predict_dnn(feature_vector)
            
            # Use RF only (DNN skipped due to architecture mismatch)
            # RF has 93% accuracy, which is sufficient
            if rf_result:
                best_label = max(rf_result, key=rf_result.get)
                confidence = rf_result[best_label]
                
                # Convert numeric label to string if label encoder is available
                if self.label_encoder and isinstance(best_label, (int, np.integer)):
                    try:
                        best_label = self.label_encoder.inverse_transform([best_label])[0]
                    except:
                        best_label = str(best_label)
                else:
                    best_label = str(best_label)
                
                is_anomaly = best_label != 'BENIGN'
                
                return {
                    'prediction': best_label,
                    'confidence': confidence * 100,
                    'is_anomaly': is_anomaly,
                    'anomaly_score': confidence if is_anomaly else 0,
                    'model': 'random_forest',
                    'rf_prediction': rf_result
                }
            else:
                return {
                    'prediction': 'UNKNOWN',
                    'confidence': 0,
                    'is_anomaly': False,
                    'anomaly_score': 0,
                    'model': 'prediction_failed'
                }
                
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return {
                'prediction': 'ERROR',
                'confidence': 0,
                'is_anomaly': False,
                'anomaly_score': 0,
                'model': 'error',
                'error': str(e)
            }
    
    def _features_to_vector(self, features: Dict) -> Optional[np.ndarray]:
        """Convert feature dict to numpy array in correct order"""
        try:
            # Map our feature names to model's expected feature names
            # This is a critical mapping - must match training schema
            
            feature_map = {
                # Our extracted features -> Model expected features
                'Flow Duration': 'Flow Duration',
                'Total Fwd Packets': 'Total Fwd Packets',
                'Total Backward Packets': 'Total Backward Packets',
                'Total Length of Fwd Packets': 'Total Length of Fwd Packets',
                'Total Length of Bwd Packets': 'Total Length of Bwd Packets',
                'Fwd Packet Length Max': 'Fwd Packet Length Max',
                'Fwd Packet Length Mean': 'Fwd Packet Length Mean',
                'Fwd Packet Length Std': 'Fwd Packet Length Std',
                'Bwd Packet Length Max': 'Bwd Packet Length Max',
                'Bwd Packet Length Mean': 'Bwd Packet Length Mean',
                'Bwd Packet Length Std': 'Bwd Packet Length Std',
                'Flow Bytes/s': 'Flow Bytes/s',
                'Flow Packets/s': 'Flow Packets/s',
                'Flow IAT Mean': 'Flow IAT Mean',
                'Flow IAT Std': 'Flow IAT Std',
                'Flow IAT Max': 'Flow IAT Max',
                'Flow IAT Min': 'Flow IAT Min',
                'Fwd IAT Total': 'Fwd IAT Total',
                'Fwd IAT Mean': 'Fwd IAT Mean',
                'Fwd IAT Std': 'Fwd IAT Std',
                'Fwd IAT Max': 'Fwd IAT Max',
                'Fwd IAT Min': 'Fwd IAT Min',
                'Bwd IAT Total': 'Bwd IAT Total',
                'Bwd IAT Mean': 'Bwd IAT Mean',
                'Bwd IAT Std': 'Bwd IAT Std',
                'Bwd IAT Max': 'Bwd IAT Max',
                'Bwd IAT Min': 'Bwd IAT Min',
                'Fwd PSH Flags': 'Fwd PSH Flags',
                'Bwd PSH Flags': 'Bwd PSH Flags',
                'Fwd URG Flags': 'Fwd URG Flags',
                'Bwd URG Flags': 'Bwd URG Flags',
                'Fwd Header Length': 'Fwd Header Length',
                'Bwd Header Length': 'Bwd Header Length',
                'Fwd Packets/s': 'Fwd Packets/s',
                'Bwd Packets/s': 'Bwd Packets/s',
                'Min Packet Length': 'Min Packet Length',
                'Max Packet Length': 'Max Packet Length',
                'Packet Length Mean': 'Packet Length Mean',
                'Packet Length Std': 'Packet Length Std',
                'Packet Length Variance': 'Packet Length Variance',
                'FIN Flag Count': 'FIN Flag Count',
                'SYN Flag Count': 'SYN Flag Count',
                'RST Flag Count': 'RST Flag Count',
                'PSH Flag Count': 'PSH Flag Count',
                'ACK Flag Count': 'ACK Flag Count',
                'URG Flag Count': 'URG Flag Count',
                'Down/Up Ratio': 'Down/Up Ratio',
                'Average Packet Size': 'Average Packet Size',
                'Avg Fwd Segment Size': 'Avg Fwd Segment Size',
                'Avg Bwd Segment Size': 'Avg Bwd Segment Size',
                'Subflow Fwd Packets': 'Subflow Fwd Packets',
                'Subflow Fwd Bytes': 'Subflow Fwd Bytes',
                'Subflow Bwd Packets': 'Subflow Bwd Packets',
                'Subflow Bwd Bytes': 'Subflow Bwd Bytes',
                'Active Mean': 'Active Mean',
                'Active Std': 'Active Std',
                'Active Max': 'Active Max',
                'Active Min': 'Active Min',
                'Idle Mean': 'Idle Mean',
                'Idle Std': 'Idle Std',
                'Idle Max': 'Idle Max',
                'Idle Min': 'Idle Min',
            }
            
            # Build vector in model's expected order
            vector = []
            for expected_feature in self.feature_names:
                # Find matching extracted feature
                value = 0  # Default
                for extracted_name, expected_name in feature_map.items():
                    if expected_name == expected_feature and extracted_name in features:
                        value = features[extracted_name]
                        break
                vector.append(value)
            
            return np.array(vector, dtype=np.float64)
            
        except Exception as e:
            logger.error(f"Error converting features to vector: {e}")
            return None
    
    def _predict_rf(self, features: np.ndarray) -> Optional[Dict]:
        """Random Forest prediction"""
        if self.rf_model is None:
            return None
        try:
            # Fix scikit-learn version incompatibility
            # Remove monotonic_cst attribute if it exists before prediction
            if hasattr(self.rf_model, 'monotonic_cst'):
                delattr(self.rf_model, 'monotonic_cst')
            if hasattr(self.rf_model, 'estimators_'):
                for estimator in self.rf_model.estimators_:
                    if hasattr(estimator, 'monotonic_cst'):
                        delattr(estimator, 'monotonic_cst')
            
            probs = self.rf_model.predict_proba([features])[0]
            classes = self.rf_model.classes_
            return dict(zip(classes, probs))
        except Exception as e:
            logger.error(f"RF prediction error: {e}")
            return None
    
    def _predict_dnn(self, features: np.ndarray) -> Optional[Dict]:
        """DNN prediction"""
        if self.dnn_model is None:
            return None
        try:
            with torch.no_grad():
                input_tensor = torch.FloatTensor(features).unsqueeze(0)
                output = self.dnn_model(input_tensor)
                probs = torch.softmax(output, dim=1)[0].numpy()
                classes = ['BENIGN', 'BOTNET', 'BRUTE_FORCE', 'DDOS', 'DOS', 'INFILTRATION', 'PORT_SCAN', 'WEB_ATTACK']
                return dict(zip(classes, probs))
        except Exception as e:
            logger.error(f"DNN prediction error: {e}")
            return None


# Global predictor instance
_predictor: Optional[MLPredictor] = None


def get_predictor() -> MLPredictor:
    """Get or create global predictor"""
    global _predictor
    if _predictor is None:
        _predictor = MLPredictor()
        _predictor.load_models()
    return _predictor


def set_predictor(predictor: MLPredictor):
    """Set global predictor (for testing)"""
    global _predictor
    _predictor = predictor
