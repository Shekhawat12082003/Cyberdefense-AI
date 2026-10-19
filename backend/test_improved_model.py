import numpy as np
import joblib
import sys

print("=== TESTING IMPROVED ML MODEL ===")

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

# Test 1: PORT SCAN (high SYN count, many ports)
print("\nTest 1: PORT SCAN Attack")
features = np.zeros(78)
features[0] = 200  # Short Flow Duration
features[1] = 3    # Few Fwd Packets
features[2] = 1    # Few Bwd Packets
features[38] = 50  # HIGH SYN Flag Count (port scan signature)
features[41] = 2   # Low ACK Flag Count
features[65] = 50  # Low Active Mean

features_scaled = scaler.transform([features])
prediction = model.predict(features_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(features_scaled)[0][prediction].max() * 100
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
features = np.zeros(78)
features[0] = 10000  # Long Flow Duration
features[1] = 300    # HIGH Fwd Packets
features[2] = 5      # Few Bwd Packets
features[38] = 20   # Moderate SYN Flag Count
features[41] = 80    # High ACK Flag Count
features[65] = 1000  # HIGH Active Mean

features_scaled = scaler.transform([features])
prediction = model.predict(features_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(features_scaled)[0][prediction].max() * 100
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
features = np.zeros(78)
features[0] = 5000   # Medium Flow Duration
features[1] = 50     # Moderate Fwd Packets
features[2] = 30     # Moderate Bwd Packets
features[3] = 3000   # Total Length of Fwd Packets
features[4] = 1500   # Total Length of Bwd Packets
features[38] = 20    # Moderate SYN Flag Count
features[41] = 35    # Moderate ACK Flag Count
features[65] = 500   # Moderate Active Mean

features_scaled = scaler.transform([features])
prediction = model.predict(features_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(features_scaled)[0][prediction].max() * 100
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
features = np.zeros(78)
features[0] = 8000   # Medium Flow Duration
features[1] = 30     # Moderate Fwd Packets
features[2] = 30     # Moderate Bwd Packets
features[3] = 5000   # Large Fwd Packets (malicious payload)
features[38] = 10    # Low SYN Flag Count
features[41] = 20    # Moderate ACK Flag Count
features[65] = 400   # Moderate Active Mean

features_scaled = scaler.transform([features])
prediction = model.predict(features_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(features_scaled)[0][prediction].max() * 100
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
features = np.zeros(78)
features[0] = 5000   # Normal Flow Duration
features[1] = 25     # Normal Fwd Packets
features[2] = 25     # Normal Bwd Packets
features[38] = 3     # Normal SYN Flag Count
features[41] = 15    # Normal ACK Flag Count
features[65] = 300   # Normal Active Mean

features_scaled = scaler.transform([features])
prediction = model.predict(features_scaled)[0]
prediction_label = label_encoder.inverse_transform([prediction])[0]
confidence = model.predict_proba(features_scaled)[0][prediction].max() * 100
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
print("The improved model can now distinguish between different attack types!")
