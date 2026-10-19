"""
Network IDS Scorer — CyberDefense-AI
======================================
Loaded after training the network_ids_model_training.ipynb notebook.
Uses RF + DNN + Isolation Forest ensemble to classify network flows.

Input: dict of CICFlowMeter-style features extracted from live traffic
Output: prediction, confidence, anomaly_score, risk_contribution

Auto-discovers trained models in the same directory.
Falls back gracefully if models are not yet trained.
"""

import os
import sys
import json
import pickle
import joblib
import numpy as np
from datetime import datetime
from typing import Optional
import importlib


# Custom unpickler to handle BinaryRFAnomalyAdapter class lookup
class CustomUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if name == 'BinaryRFAnomalyAdapter':
            return BinaryRFAnomalyAdapter
        return super().find_class(module, name)

MODELS_DIR = os.path.dirname(os.path.abspath(__file__))


# ── BinaryRFAnomalyAdapter ─────────────────────────────────
# Required to unpickle network_anomaly_model.pkl (trained in notebook)
class BinaryRFAnomalyAdapter:
    """Wraps binary RF to match IsolationForest API."""
    def __init__(self, rf):
        self._rf = rf

    def predict(self, X):
        # IF convention: -1=anomaly(attack), 1=normal(benign)
        preds = self._rf.predict(X)
        return np.where(preds == 1, -1, 1)

    def score_samples(self, X):
        # IF convention: higher score = more normal
        attack_prob = self._rf.predict_proba(X)[:, 1]
        return 1.0 - attack_prob

    def __getstate__(self): return self.__dict__
    def __setstate__(self, state): self.__dict__.update(state)


# ── Model state ───────────────────────────────────────────
_rf_model      = None
_dl_model      = None
_scaler        = None
_label_encoder = None
_anomaly_model = None
_anomaly_model_compatible = False
_model_info    = None
_features      = None
_loaded        = False

# ── NSL-KDD supplementary model ──────────────────────────
_nsl_rf     = None
_nsl_scaler = None
_nsl_le     = None
_nsl_info   = None
_nsl_loaded = False


def _load_models():
    global _rf_model, _dl_model, _scaler, _label_encoder, _anomaly_model
    global _anomaly_model_compatible, _model_info, _features, _loaded

    # Patch sklearn for version compatibility
    try:
        from sklearn.tree import DecisionTreeClassifier
        if not hasattr(DecisionTreeClassifier, 'monotonic_cst'):
            DecisionTreeClassifier.monotonic_cst = None
    except Exception:
        pass

    info_path = os.path.join(MODELS_DIR, 'network_model_info.json')
    if not os.path.exists(info_path):
        print("[INFO] Network IDS models not trained yet — run network_ids_model_training.ipynb first")
        return False

    try:
        with open(info_path) as f:
            _model_info = json.load(f)
        _features = _model_info.get('features', [])

        # RF
        with open(os.path.join(MODELS_DIR, 'network_rf_model.pkl'), 'rb') as f:
            _rf_model = joblib.load(f)

        # Patch sklearn version incompatibility (model trained on 1.3.2, running on newer)
        # DecisionTreeClassifier gained 'monotonic_cst' in 1.4+ — backfill it if missing
        try:
            for _est in _rf_model.estimators_:
                if not hasattr(_est, 'monotonic_cst'):
                    _est.monotonic_cst = None
        except Exception:
            pass  # Handle if structure is different

        # Scaler
        with open(os.path.join(MODELS_DIR, 'network_scaler.pkl'), 'rb') as f:
            _scaler = joblib.load(f)

        # Patch sklearn version incompatibility for StandardScaler
        if not hasattr(_scaler, 'n_features_in_'):
            _scaler.n_features_in_ = None

        # Label encoder
        with open(os.path.join(MODELS_DIR, 'network_label_encoder.pkl'), 'rb') as f:
            _label_encoder = joblib.load(f)

        # Patch sklearn version incompatibility for LabelEncoder
        if not hasattr(_label_encoder, 'n_features_in_'):
            _label_encoder.n_features_in_ = None

        # Anomaly model
        anom_path = os.path.join(MODELS_DIR, 'network_anomaly_model.pkl')
        if os.path.exists(anom_path):
            with open(anom_path, 'rb') as f:
                _anomaly_model = CustomUnpickler(f).load()
            anomaly_features = getattr(
                getattr(_anomaly_model, '_rf', _anomaly_model),
                'n_features_in_',
                None,
            )
            _anomaly_model_compatible = anomaly_features == len(_features)
            if not _anomaly_model_compatible:
                print(
                    "[WARN] Network anomaly model feature schema does not match "
                    "the network classifier; anomaly scoring is disabled"
                )

        # DNN (optional)
        try:
            import torch
            import torch.nn as nn

            dl_info_path = os.path.join(MODELS_DIR, 'network_dl_model_info.json')
            dl_path      = os.path.join(MODELS_DIR, 'network_dl_model.pth')
            if os.path.exists(dl_path) and os.path.exists(dl_info_path):
                with open(dl_info_path) as f:
                    dl_info = json.load(f)

                # LayerNorm architecture — matches the trained model exactly
                class NetworkIDSNet(nn.Module):
                    def __init__(self, input_dim, num_classes):
                        super().__init__()
                        self.network = nn.Sequential(
                            nn.Linear(input_dim, 512), nn.LayerNorm(512), nn.GELU(), nn.Dropout(0.30),
                            nn.Linear(512, 256),       nn.LayerNorm(256), nn.GELU(), nn.Dropout(0.25),
                            nn.Linear(256, 128),       nn.LayerNorm(128), nn.GELU(), nn.Dropout(0.20),
                            nn.Linear(128, 64),        nn.LayerNorm(64),  nn.GELU(), nn.Dropout(0.15),
                            nn.Linear(64, 32),         nn.GELU(),
                            nn.Linear(32, num_classes)
                        )
                    def forward(self, x):
                        return self.network(x)

                _dl_model = NetworkIDSNet(dl_info['input_dim'], dl_info['num_classes'])

                raw_state = torch.load(dl_path, map_location='cpu')
                # Remap legacy 'net.' prefix keys if needed
                if any(k.startswith('net.') for k in raw_state):
                    raw_state = {k.replace('net.', 'network.', 1): v for k, v in raw_state.items()}

                _dl_model.load_state_dict(raw_state, strict=True)
                _dl_model.eval()
        except Exception as e:
            print(f"[INFO] DNN not loaded: {e}")

        _loaded = True
        classes = _label_encoder.classes_.tolist() if _label_encoder else []
        print("[OK] Network IDS models loaded!")
        print(f"   RF accuracy : {_model_info.get('rf_accuracy', '?')}%")
        print(f"   Classes     : {classes}")
        print(f"   Features    : {len(_features)}")
        return True

    except Exception as e:
        print(f"[WARN] Network IDS model load error: {e}")
        return False


def _load_nsl_models():
    global _nsl_rf, _nsl_scaler, _nsl_le, _nsl_info, _nsl_loaded

    info_path = os.path.join(MODELS_DIR, 'network_nslkdd_info.json')
    if not os.path.exists(info_path):
        return False
    try:
        with open(info_path) as f:
            _nsl_info = json.load(f)
        with open(os.path.join(MODELS_DIR, 'network_nslkdd_model.pkl'), 'rb') as f:
            _nsl_rf = joblib.load(f)

        # Patch sklearn version incompatibility (model trained on 1.3.2, running on newer)
        for _est in _nsl_rf.estimators_:
            if not hasattr(_est, 'monotonic_cst'):
                _est.monotonic_cst = None
        with open(os.path.join(MODELS_DIR, 'network_nslkdd_scaler.pkl'), 'rb') as f:
            _nsl_scaler = joblib.load(f)

        # Patch sklearn version incompatibility for StandardScaler
        if not hasattr(_nsl_scaler, 'n_features_in_'):
            _nsl_scaler.n_features_in_ = None

        with open(os.path.join(MODELS_DIR, 'network_nslkdd_encoder.pkl'), 'rb') as f:
            _nsl_le = joblib.load(f)

        # Patch sklearn version incompatibility for LabelEncoder
        if not hasattr(_nsl_le, 'n_features_in_'):
            _nsl_le.n_features_in_ = None
        _nsl_loaded = True
        print(f"[OK] NSL-KDD model loaded — accuracy: {_nsl_info.get('rf_accuracy','?')}%")
        return True
    except Exception as e:
        print(f"[INFO] NSL-KDD model not loaded: {e}")
        return False


# ── Initialize on import ──────────────────────────────────
_load_models()
_load_nsl_models()


def is_loaded() -> bool:
    return _loaded


def get_model_info() -> dict:
    if _model_info:
        return _model_info
    return {'loaded': False, 'note': 'Run network_ids_model_training.ipynb to train models'}


def predict_flow(flow_features: dict) -> dict:
    """
    Classify a network flow.

    The trained model is required before a suspicious event is treated as a real attack.
    If the model is missing or the feature schema does not match, return UNKNOWN and do not
    mark the event as an authenticated attack.
    """
    if not _loaded or _rf_model is None:
        return _fallback_prediction(flow_features)

    try:
        missing_features = [
            feature for feature in (_features or [])
            if feature not in flow_features or flow_features[feature] is None
        ]
        if missing_features:
            return _unverified_prediction(
                f'Flow is missing required model features: {", ".join(missing_features)}',
                model='feature_mismatch',
            )

        # Do not silently substitute zeros: they can turn an invalid flow into a model result.
        x = np.array([[float(flow_features[f]) for f in _features]], dtype=np.float32)
        required_features = int(getattr(_rf_model, 'n_features_in_', len(_features)))
        if x.shape[1] != required_features:
            return _unverified_prediction(
                f'Model expects {required_features} features, received {x.shape[1]}',
                model='feature_mismatch',
            )

        if not np.isfinite(x).all():
            return _unverified_prediction(
                'Flow contains non-finite model features',
                model='invalid_features',
            )

        # Scale
        x_scaled = _scaler.transform(x)

        # RF prediction
        rf_probs = _rf_model.predict_proba(x)[0]
        rf_idx   = int(rf_probs.argmax())
        rf_conf  = float(rf_probs[rf_idx])

        # DNN prediction
        dl_conf  = 0.0
        dl_probs = None
        if _dl_model is not None:
            try:
                import torch
                with torch.no_grad():
                    logits   = _dl_model(torch.FloatTensor(x_scaled))
                    dl_p     = torch.softmax(logits, dim=1)[0].numpy()
                    dl_probs = dl_p
                    dl_conf  = float(dl_p[rf_idx])
            except Exception:
                pass

        # Ensemble: 65% RF + 35% DNN
        if dl_probs is not None:
            ens_probs = 0.65 * rf_probs + 0.35 * dl_probs
        else:
            ens_probs = rf_probs

        best_idx    = int(ens_probs.argmax())
        prediction  = _label_encoder.classes_[best_idx]
        confidence  = float(ens_probs[best_idx]) * 100

        # Anomaly score
        anomaly_score = 0.0
        is_anomaly    = False
        if _anomaly_model is not None and _anomaly_model_compatible:
            try:
                anomaly_score = float(_anomaly_model.score_samples(x_scaled)[0])
                is_anomaly = _anomaly_model.predict(x_scaled)[0] == -1
            except Exception as e:
                print(f"[WARN] Network anomaly scoring failed: {e}")

        # Risk score (ML contribution to overall risk)
        risk_score = _compute_risk_score(prediction, confidence, is_anomaly, anomaly_score)

        # All probabilities
        all_probs = {
            cls: round(float(p) * 100, 2)
            for cls, p in zip(_label_encoder.classes_, ens_probs)
        }

        is_attack = prediction.upper() != 'BENIGN' and confidence >= 70.0

        return {
            'prediction':    prediction,
            'confidence':    round(confidence, 2),
            'is_attack':     is_attack,
            'verified':      True,
            'anomaly_score': round(anomaly_score, 4),
            'is_anomaly':    is_anomaly,
            'risk_score':    risk_score,
            'all_probs':     all_probs,
            'timestamp':     datetime.utcnow().isoformat(),
            'model':         (
                'network_rf_dnn_ensemble'
                if dl_probs is not None
                else 'network_random_forest'
            ),
        }

    except (TypeError, ValueError, OverflowError) as e:
        print(f"[WARN] Invalid network flow features: {e}")
        return _unverified_prediction(
            f'Invalid model features: {e}',
            model='invalid_features',
        )
    except Exception as e:
        print(f"[WARN] network_scorer.predict_flow error: {e}")
        return _unverified_prediction(
            f'Trained network model inference failed: {e}',
            model='inference_error',
        )


def predict_attack_type(alert_type: str, features: dict = None) -> dict:
    """
    Quick prediction given a detected alert type (from rule-based detection).
    Combines rule-based certainty with ML confidence when available.
    """
    # Map rule-based alerts to expected ML class
    ALERT_TO_CLASS = {
        'PORT_SCAN':   'PORT_SCAN',
        'BRUTE_FORCE': 'BRUTE_FORCE',
        'SYN_FLOOD':   'DOS',
        'DATA_EXFIL':  'INFILTRATION',
        'C2_BEACON':   'INFILTRATION',
        'NULL_SCAN':   'PORT_SCAN',
        'XMAS_SCAN':   'PORT_SCAN',
        'FIN_SCAN':    'PORT_SCAN',
    }

    expected_class = ALERT_TO_CLASS.get(alert_type, 'PORT_SCAN')

    if not _loaded or features is None:
        result = _fallback_prediction(features)
        result['candidate_type'] = expected_class
        return result

    result = predict_flow(features)
    result['candidate_type'] = expected_class
    result['rule_agreement'] = result.get('prediction') == expected_class
    if not result['rule_agreement']:
        result['is_attack'] = False
        result['verified'] = False
        result['note'] = (
            f"Rule candidate {expected_class} was not confirmed by the trained model"
        )
    return result


def _compute_risk_score(prediction: str, confidence: float, is_anomaly: bool, anomaly_score: float) -> float:
    """Translate ML prediction into a 0-100 risk contribution score."""
    CLASS_BASE_RISK = {
        'BENIGN':       5.0,
        'PORT_SCAN':    40.0,
        'BRUTE_FORCE':  65.0,
        'DOS':          70.0,
        'DDOS':         75.0,
        'BOTNET':       80.0,
        'WEB_ATTACK':   55.0,
        'INFILTRATION': 85.0,
    }
    base = CLASS_BASE_RISK.get(prediction, 30.0)
    # Scale by confidence
    conf_factor = (confidence / 100.0) ** 0.5   # square root so low confidence still contributes
    score = base * conf_factor
    # Anomaly boost
    if is_anomaly:
        score = min(score * 1.15, 100.0)
    return round(min(score, 100.0), 1)


def _fallback_prediction(flow_features: dict) -> dict:
    """Return when models are not loaded."""
    return _unverified_prediction(
        'Run network_ids_model_training.ipynb to train models',
        model='not_loaded',
    )


def _unverified_prediction(note: str, model: str) -> dict:
    """Return a fail-closed prediction that cannot be counted as an attack."""
    return {
        'prediction':    'UNKNOWN',
        'confidence':   0.0,
        'anomaly_score': 0.0,
        'is_anomaly':   False,
        'is_attack':    False,
        'verified':     False,
        'risk_score':   0.0,
        'all_probs':    {},
        'timestamp':   datetime.utcnow().isoformat(),
        'model':        model,
        'note':         note,
    }


def get_status() -> dict:
    """Return current model status for the /api/health endpoint."""
    return {
        'network_ids_loaded':   _loaded,
        'nsl_kdd_loaded':       _nsl_loaded,
        'feature_count':        len(_features) if _features else 0,
        'features':             len(_features) if _features else 0,
        'classes':              _label_encoder.classes_.tolist() if _label_encoder else [],
        'rf_accuracy':          _model_info.get('rf_accuracy') if _model_info else None,
        'dl_accuracy':          _model_info.get('dl_accuracy') if _model_info else None,
        'anomaly_model':        _anomaly_model is not None and _anomaly_model_compatible,
        'dl_model':             _dl_model is not None,
        'note':                 'Run mini_train_test.py or full notebook for better accuracy' if not _loaded else '',
    }


def get_scorer_info() -> dict:
    """Used by /api/system/health — returns loaded flag and detail string."""
    if _loaded:
        classes = _label_encoder.classes_.tolist() if _label_encoder else []
        rf_acc  = _model_info.get('rf_accuracy', '?') if _model_info else '?'
        return {
            'loaded': True,
            'detail': f"RF {rf_acc}% — {len(classes)} classes: {', '.join(classes[:4])}{'…' if len(classes) > 4 else ''}",
        }
    return {
        'loaded': False,
        'detail': 'Models not trained — run notebooks/network_ids_v2.ipynb',
    }
