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
import json
import pickle
import numpy as np
from datetime import datetime
from typing import Optional

MODELS_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Model state ───────────────────────────────────────────
_rf_model      = None
_dl_model      = None
_scaler        = None
_label_encoder = None
_anomaly_model = None
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
    global _model_info, _features, _loaded

    info_path = os.path.join(MODELS_DIR, 'network_model_info.json')
    if not os.path.exists(info_path):
        print("ℹ️  Network IDS models not trained yet — run network_ids_model_training.ipynb first")
        return False

    try:
        with open(info_path) as f:
            _model_info = json.load(f)
        _features = _model_info.get('features', [])

        # RF
        with open(os.path.join(MODELS_DIR, 'network_rf_model.pkl'), 'rb') as f:
            _rf_model = pickle.load(f)

        # Scaler
        with open(os.path.join(MODELS_DIR, 'network_scaler.pkl'), 'rb') as f:
            _scaler = pickle.load(f)

        # Label encoder
        with open(os.path.join(MODELS_DIR, 'network_label_encoder.pkl'), 'rb') as f:
            _label_encoder = pickle.load(f)

        # Anomaly model
        anom_path = os.path.join(MODELS_DIR, 'network_anomaly_model.pkl')
        if os.path.exists(anom_path):
            with open(anom_path, 'rb') as f:
                _anomaly_model = pickle.load(f)

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
            print(f"ℹ️  DNN not loaded: {e}")

        _loaded = True
        classes = _label_encoder.classes_.tolist() if _label_encoder else []
        print(f"✅ Network IDS models loaded!")
        print(f"   RF accuracy : {_model_info.get('rf_accuracy', '?')}%")
        print(f"   Classes     : {classes}")
        print(f"   Features    : {len(_features)}")
        return True

    except Exception as e:
        print(f"⚠️  Network IDS model load error: {e}")
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
            _nsl_rf = pickle.load(f)
        with open(os.path.join(MODELS_DIR, 'network_nslkdd_scaler.pkl'), 'rb') as f:
            _nsl_scaler = pickle.load(f)
        with open(os.path.join(MODELS_DIR, 'network_nslkdd_encoder.pkl'), 'rb') as f:
            _nsl_le = pickle.load(f)
        _nsl_loaded = True
        print(f"✅ NSL-KDD model loaded — accuracy: {_nsl_info.get('rf_accuracy','?')}%")
        return True
    except Exception as e:
        print(f"ℹ️  NSL-KDD model not loaded: {e}")
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

    Parameters
    ----------
    flow_features : dict
        CICFlowMeter-compatible features extracted from a network flow.
        Missing features are filled with 0.

    Returns
    -------
    dict with keys:
        prediction       — class label (BENIGN, PORT_SCAN, BRUTE_FORCE, etc.)
        confidence       — 0–100 confidence %
        anomaly_score    — Isolation Forest score (lower = more anomalous)
        is_anomaly       — bool
        risk_score       — 0–100 ML risk contribution
        all_probs        — dict of {class: probability}
        timestamp        — ISO timestamp
        model            — which model was used
    """
    if not _loaded or _rf_model is None:
        return _fallback_prediction(flow_features)

    try:
        # Build feature vector
        x = np.array(
            [[float(flow_features.get(f, 0) or 0) for f in _features]],
            dtype=np.float32
        )
        # Replace inf/nan
        x = np.nan_to_num(x, nan=0.0, posinf=0.0, neginf=0.0)

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
        if _anomaly_model is not None:
            anomaly_score = float(_anomaly_model.score_samples(x_scaled)[0])
            is_anomaly    = _anomaly_model.predict(x_scaled)[0] == -1

        # Risk score (ML contribution to overall risk)
        risk_score = _compute_risk_score(prediction, confidence, is_anomaly, anomaly_score)

        # All probabilities
        all_probs = {
            cls: round(float(p) * 100, 2)
            for cls, p in zip(_label_encoder.classes_, ens_probs)
        }

        return {
            'prediction':    prediction,
            'confidence':    round(confidence, 2),
            'anomaly_score': round(anomaly_score, 4),
            'is_anomaly':    is_anomaly,
            'risk_score':    risk_score,
            'all_probs':     all_probs,
            'timestamp':     datetime.utcnow().isoformat(),
            'model':         'network_rf_dnn_ensemble',
        }

    except Exception as e:
        print(f"⚠️  network_scorer.predict_flow error: {e}")
        return _fallback_prediction(flow_features)


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
        # Return rule-based result
        return {
            'prediction':  expected_class,
            'confidence':  85.0,   # rule-based is high confidence
            'anomaly_score': -0.1,
            'is_anomaly':  True,
            'risk_score':  65.0,
            'model':       'rule_based',
            'timestamp':   datetime.utcnow().isoformat(),
        }

    result = predict_flow(features)
    # Boost confidence if ML agrees with rule-based detection
    if result.get('prediction') == expected_class:
        result['confidence'] = min(result['confidence'] * 1.1, 100.0)
        result['rule_agreement'] = True
    else:
        # Rule-based takes precedence but note disagreement
        result['rule_prediction'] = expected_class
        result['ml_prediction']   = result.get('prediction')
        result['prediction']      = expected_class
        result['rule_agreement']  = False
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
    return {
        'prediction':    'UNKNOWN',
        'confidence':    0.0,
        'anomaly_score': 0.0,
        'is_anomaly':    False,
        'risk_score':    0.0,
        'all_probs':     {},
        'timestamp':     datetime.utcnow().isoformat(),
        'model':         'not_loaded',
        'note':          'Run network_ids_model_training.ipynb to train models',
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
        'anomaly_model':        _anomaly_model is not None,
        'dl_model':             _dl_model is not None,
        'note':                 'Run mini_train_test.py or full notebook for better accuracy' if not _loaded else '',
    }
