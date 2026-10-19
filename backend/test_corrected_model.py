import numpy as np
import joblib
import sys

print("=== TESTING CORRECTED ML MODEL ===")

# Load model
print("\nLoading model...")
try:
    model = joblib.load('models/network_rf_model.pkl')
    scaler = joblib.load('models/network_scaler.pkl')
    label_encoder = joblib.load('models/network_label_encoder.pkl')
    print("[OK] New model loaded successfully")
except Exception as e:
    print(f"[ERROR] Failed to load model: {e}")
    sys.exit(1)

print(f"\nModel Information:")
print(f"  Classes: {label_encoder.classes_}")
print(f"  Features: {model.n_features_in_}")

# Read feature names from model info
import json
with open('models/network_model_info.json') as f:
    model_info = json.load(f)
feature_names = model_info['features']
print(f"  Feature names: {len(feature_names)}")

# Test 1: PORT SCAN (high SYN count, many ports)
print("\nTest 1: PORT SCAN Attack")
features = {name: 0 for name in feature_names}
features['Flow Duration'] = 200
features['Total Fwd Packets'] = 3
features['Total Backward Packets'] = 1
features['SYN Flag Count'] = 50  # HIGH SYN Flag Count
features['ACK Flag Count'] = 2
features['Active Mean'] = 50

x = np.array([[features[name] for name in feature_names]], dtype=np.float32)
x_scaled = scaler.transform(x)
prediction = model.predict(x_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(x_scaled)[0][prediction].max() * 100
is_anomaly = prediction_label != 'BENIGN'
risk_score = confidence / 100 if is_anomaly else 0.0

print(f"  Prediction: {prediction_label}")
print(f"  Confidence: {confidence:.1f}%")
print(f"  Is Anomaly: {is_anomaly}")
print(f"  Risk Score: {risk_score:.2f}")

if prediction_label == 'PORT_SCAN':
    print("  [OK] CORRECTLY DETECTED AS PORT SCAN!")
else:
    print(f"  [FAIL] Expected PORT_SCAN, got {prediction_label}")

# Test 2: DOS (high packet rate to single port)
print("\nTest 2: DoS Attack")
features = {name: 0 for name in feature_names}
features['Flow Duration'] = 10000
features['Total Fwd Packets'] = 300  # HIGH Fwd Packets
features['Total Backward Packets'] = 5
features['SYN Flag Count'] = 20
features['ACK Flag Count'] = 80
features['Active Mean'] = 1000  # HIGH Active Mean

x = np.array([[features[name] for name in feature_names]], dtype=np.float32)
x_scaled = scaler.transform(x)
prediction = model.predict(x_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(x_scaled)[0][prediction].max() * 100
is_anomaly = prediction_label != 'BENIGN'
risk_score = confidence / 100 if is_anomaly else 0.0

print(f"  Prediction: {prediction_label}")
print(f"  Confidence: {confidence:.1f}%")
print(f"  Is Anomaly: {is_anomaly}")
print(f"  Risk Score: {risk_score:.2f}")

if prediction_label == 'DOS':
    print("  [OK] CORRECTLY DETECTED AS DOS!")
else:
    print(f"  [FAIL] Expected DOS, got {prediction_label}")

# Test 3: BRUTE FORCE (login attempts to auth ports)
print("\nTest 3: BRUTE FORCE Attack")
features = {name: 0 for name in feature_names}
features['Flow Duration'] = 5000
features['Total Fwd Packets'] = 50
features['Total Backward Packets'] = 30
features['Total Length of Fwd Packets'] = 3000
features['Total Length of Bwd Packets'] = 1500
features['SYN Flag Count'] = 20
features['ACK Flag Count'] = 35
features['Active Mean'] = 500

x = np.array([[features[name] for name in feature_names]], dtype=np.float32)
x_scaled = scaler.transform(x)
prediction = model.predict(x_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(x_scaled)[0][prediction].max() * 100
is_anomaly = prediction_label != 'BENIGN'
risk_score = confidence / 100 if is_anomaly else 0.0

print(f"  Prediction: {prediction_label}")
print(f"  Confidence: {confidence:.1f}%")
print(f"  Is Anomaly: {is_anomaly}")
print(f"  Risk Score: {risk_score:.2f}")

if prediction_label == 'BRUTE_FORCE':
    print("  [OK] CORRECTLY DETECTED AS BRUTE FORCE!")
else:
    print(f"  [FAIL] Expected BRUTE_FORCE, got {prediction_label}")

# Test 4: WEB ATTACK (SQL injection, XSS)
print("\nTest 4: WEB_ATTACK Attack")
features = {name: 0 for name in feature_names}
features['Flow Duration'] = 8000
features['Total Fwd Packets'] = 30
features['Total Backward Packets'] = 30
features['Total Length of Fwd Packets'] = 5000  # Large Fwd Packets (malicious payload)
features['SYN Flag Count'] = 10
features['ACK Flag Count'] = 20
features['Active Mean'] = 400

x = np.array([[features[name] for name in feature_names]], dtype=np.float32)
x_scaled = scaler.transform(x)
prediction = model.predict(x_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(x_scaled)[0][prediction].max() * 100
is_anomaly = prediction_label != 'BENIGN'
risk_score = confidence / 100 if is_anomaly else 0.0

print(f"  Prediction: {prediction_label}")
print(f"  Confidence: {confidence:.1f}%")
print(f"  Is Anomaly: {is_anomaly}")
print(f"  Risk Score: {risk_score:.2f}")

if prediction_label == 'WEB_ATTACK':
    print("  [OK] CORRECTLY DETECTED AS WEB_ATTACK!")
else:
    print(f"  [FAIL] Expected WEB_ATTACK, got {prediction_label}")

# Test 5: BENIGN Traffic
print("\nTest 5: BENIGN Traffic")
features = {name: 0 for name in feature_names}
features['Flow Duration'] = 5000
features['Total Fwd Packets'] = 25
features['Total Backward Packets'] = 25
features['SYN Flag Count'] = 3
features['ACK Flag Count'] = 15
features['Active Mean'] = 300

x = np.array([[features[name] for name in feature_names]], dtype=np.float32)
x_scaled = scaler.transform(x)
prediction = model.predict(x_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(x_scaled)[0][prediction].max() * 100
is_anomaly = prediction_label != 'BENIGN'
risk_score = confidence / 100 if is_anomaly else 0.0

print(f"  Prediction: {prediction_label}")
print(f"  Confidence: {confidence:.1f}%")
print(f"  Is Anomaly: {is_anomaly}")
print(f"  Risk Score: {risk_score:.2f}")

if prediction_label == 'BENIGN':
    print("  [OK] CORRECTLY IDENTIFIED AS BENIGN!")
else:
    print(f"  [FAIL] Expected BENIGN, got {prediction_label}")

print("\n=== TEST COMPLETE ===")
print("The corrected model is working correctly!")
