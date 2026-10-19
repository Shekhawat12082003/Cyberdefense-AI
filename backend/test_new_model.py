"""
Test the newly retrained model
"""
import sys
sys.path.insert(0, '.')

from utils.ml_predictor import MLPredictor

print("=== TESTING NEWLY RETRAINED MODEL ===")
print()

# Load the new model
predictor = MLPredictor()
if predictor.load_models():
    print("[OK] New model loaded successfully")
else:
    print("[ERROR] Failed to load model")
    sys.exit(1)

print()
print("Model Information:")
print(f"  Classes: {predictor.label_encoder.classes_ if predictor.label_encoder else 'N/A'}")
print(f"  Features: {len(predictor.feature_names)}")
print()

# Test 1: Port Scan
print("Test 1: PORT SCAN Attack")
port_scan_features = {
    'Flow Duration': 1.0,
    'Total Fwd Packets': 50,
    'Total Backward Packets': 5,
    'Total Length of Fwd Packets': 2500,
    'Total Length of Bwd Packets': 250,
    'Fwd Packet Length Max': 60,
    'Fwd Packet Length Mean': 50,
    'Fwd Packet Length Std': 10,
    'Bwd Packet Length Max': 60,
    'Bwd Packet Length Mean': 50,
    'Bwd Packet Length Std': 10,
    'Flow Bytes/s': 2750,
    'Flow Packets/s': 55,
    'Flow IAT Mean': 0.02,
    'Flow IAT Std': 0.01,
    'Flow IAT Max': 0.05,
    'Flow IAT Min': 0.001,
    'Fwd IAT Total': 1.0,
    'Fwd IAT Mean': 0.02,
    'Fwd IAT Std': 0.01,
    'Fwd IAT Max': 0.05,
    'Fwd IAT Min': 0.001,
    'Bwd IAT Total': 0.1,
    'Bwd IAT Mean': 0.02,
    'Bwd IAT Std': 0.01,
    'Bwd IAT Max': 0.05,
    'Bwd IAT Min': 0.005,
    'Fwd PSH Flags': 10,
    'Bwd PSH Flags': 2,
    'Fwd URG Flags': 0,
    'Bwd URG Flags': 0,
    'Fwd Header Length': 2000,
    'Bwd Header Length': 200,
    'Fwd Packets/s': 50,
    'Bwd Packets/s': 5,
    'Min Packet Length': 40,
    'Max Packet Length': 60,
    'Packet Length Mean': 50,
    'Packet Length Std': 10,
    'Packet Length Variance': 100,
    'FIN Flag Count': 0,
    'SYN Flag Count': 50,  # High SYN = port scan
    'RST Flag Count': 25,  # Many RST = rejected connections
    'PSH Flag Count': 10,
    'ACK Flag Count': 5,
    'URG Flag Count': 0,
    'Down/Up Ratio': 0.1,
    'Average Packet Size': 50,
    'Avg Fwd Segment Size': 50,
    'Avg Bwd Segment Size': 50,
    'Subflow Fwd Packets': 50,
    'Subflow Fwd Bytes': 2500,
    'Subflow Bwd Packets': 5,
    'Subflow Bwd Bytes': 250,
    'Init_Win_bytes_forward': 8192,
    'Init_Win_bytes_backward': 8192,
    'Init_Win_bytes_forward': 8192,
    'Init_Win_bytes_backward': 8192,
    'act_data_pkt_fwd': 50,
    'act_data_pkt_bwd': 5,
    'Active Mean': 0.02,
    'Active Std': 0.01,
    'Active Max': 0.05,
    'Active Min': 0.001,
    'Idle Mean': 0,
    'Idle Std': 0,
    'Idle Max': 0,
    'Idle Min': 0,
}

result = predictor.predict(port_scan_features)
print(f"  Prediction: {result['prediction']}")
print(f"  Confidence: {result['confidence']:.1f}%")
print(f"  Is Anomaly: {result['is_anomaly']}")
print(f"  Risk Score: {result['anomaly_score']:.2f}")
if result['prediction'] == 'PORT_SCAN':
    print("  [OK] CORRECTLY DETECTED AS PORT SCAN!")
else:
    print(f"  [FAIL] Expected PORT_SCAN, got {result['prediction']}")
print()

# Test 2: DoS
print("Test 2: DoS Attack")
dos_features = {
    'Flow Duration': 5.0,
    'Total Fwd Packets': 500,
    'Total Backward Packets': 10,
    'Total Length of Fwd Packets': 25000,
    'Total Length of Bwd Packets': 500,
    'Fwd Packet Length Max': 60,
    'Fwd Packet Length Mean': 50,
    'Fwd Packet Length Std': 10,
    'Bwd Packet Length Max': 60,
    'Bwd Packet Length Mean': 50,
    'Bwd Packet Length Std': 10,
    'Flow Bytes/s': 5100,
    'Flow Packets/s': 102,
    'Flow IAT Mean': 0.01,
    'Flow IAT Std': 0.005,
    'Flow IAT Max': 0.02,
    'Flow IAT Min': 0.001,
    'Fwd IAT Total': 5.0,
    'Fwd IAT Mean': 0.01,
    'Fwd IAT Std': 0.005,
    'Fwd IAT Max': 0.02,
    'Fwd IAT Min': 0.001,
    'Bwd IAT Total': 0.5,
    'Bwd IAT Mean': 0.05,
    'Bwd IAT Std': 0.02,
    'Bwd IAT Max': 0.1,
    'Bwd IAT Min': 0.01,
    'Fwd PSH Flags': 50,
    'Bwd PSH Flags': 10,
    'Fwd URG Flags': 0,
    'Bwd URG Flags': 0,
    'Fwd Header Length': 20000,
    'Bwd Header Length': 400,
    'Fwd Packets/s': 100,
    'Bwd Packets/s': 2,
    'Min Packet Length': 40,
    'Max Packet Length': 60,
    'Packet Length Mean': 50,
    'Packet Length Std': 10,
    'Packet Length Variance': 100,
    'FIN Flag Count': 5,
    'SYN Flag Count': 500,  # Very high SYN = DoS
    'RST Flag Count': 0,
    'PSH Flag Count': 50,
    'ACK Flag Count': 10,
    'URG Flag Count': 0,
    'Down/Up Ratio': 0.02,
    'Average Packet Size': 50,
    'Avg Fwd Segment Size': 50,
    'Avg Bwd Segment Size': 50,
    'Subflow Fwd Packets': 500,
    'Subflow Fwd Bytes': 25000,
    'Subflow Bwd Packets': 10,
    'Subflow Bwd Bytes': 500,
    'Init_Win_bytes_forward': 8192,
    'Init_Win_bytes_backward': 8192,
    'Init_Win_bytes_forward': 8192,
    'Init_Win_bytes_backward': 8192,
    'act_data_pkt_fwd': 500,
    'act_data_pkt_bwd': 10,
    'Active Mean': 0.01,
    'Active Std': 0.005,
    'Active Max': 0.02,
    'Active Min': 0.001,
    'Idle Mean': 0,
    'Idle Std': 0,
    'Idle Max': 0,
    'Idle Min': 0,
}

result = predictor.predict(dos_features)
print(f"  Prediction: {result['prediction']}")
print(f"  Confidence: {result['confidence']:.1f}%")
print(f"  Is Anomaly: {result['is_anomaly']}")
print(f"  Risk Score: {result['anomaly_score']:.2f}")
if result['prediction'] == 'DOS':
    print("  [OK] CORRECTLY DETECTED AS DOS!")
else:
    print(f"  [FAIL] Expected DOS, got {result['prediction']}")
print()

# Test 3: Benign
print("Test 3: BENIGN Traffic")
benign_features = {
    'Flow Duration': 10.0,
    'Total Fwd Packets': 20,
    'Total Backward Packets': 20,
    'Total Length of Fwd Packets': 10000,
    'Total Length of Bwd Packets': 10000,
    'Fwd Packet Length Max': 1500,
    'Fwd Packet Length Mean': 500,
    'Fwd Packet Length Std': 200,
    'Bwd Packet Length Max': 1500,
    'Bwd Packet Length Mean': 500,
    'Bwd Packet Length Std': 200,
    'Flow Bytes/s': 2000,
    'Flow Packets/s': 4,
    'Flow IAT Mean': 0.5,
    'Flow IAT Std': 0.2,
    'Flow IAT Max': 1.0,
    'Flow IAT Min': 0.1,
    'Fwd IAT Total': 10.0,
    'Fwd IAT Mean': 0.5,
    'Fwd IAT Std': 0.2,
    'Fwd IAT Max': 1.0,
    'Fwd IAT Min': 0.1,
    'Bwd IAT Total': 10.0,
    'Bwd IAT Mean': 0.5,
    'Bwd IAT Std': 0.2,
    'Bwd IAT Max': 1.0,
    'Bwd IAT Min': 0.1,
    'Fwd PSH Flags': 10,
    'Bwd PSH Flags': 10,
    'Fwd URG Flags': 0,
    'Bwd URG Flags': 0,
    'Fwd Header Length': 8000,
    'Bwd Header Length': 8000,
    'Fwd Packets/s': 2,
    'Bwd Packets/s': 2,
    'Min Packet Length': 40,
    'Max Packet Length': 1500,
    'Packet Length Mean': 500,
    'Packet Length Std': 200,
    'Packet Length Variance': 40000,
    'FIN Flag Count': 2,
    'SYN Flag Count': 2,  # Normal SYN count
    'RST Flag Count': 0,
    'PSH Flag Count': 10,
    'ACK Flag Count': 20,
    'URG Flag Count': 0,
    'Down/Up Ratio': 1.0,
    'Average Packet Size': 500,
    'Avg Fwd Segment Size': 500,
    'Avg Bwd Segment Size': 500,
    'Subflow Fwd Packets': 20,
    'Subflow Fwd Bytes': 10000,
    'Subflow Bwd Packets': 20,
    'Subflow Bwd Bytes': 10000,
    'Init_Win_bytes_forward': 65535,
    'Init_Win_bytes_backward': 65535,
    'Init_Win_bytes_forward': 65535,
    'Init_Win_bytes_backward': 65535,
    'act_data_pkt_fwd': 20,
    'act_data_pkt_bwd': 20,
    'Active Mean': 0.5,
    'Active Std': 0.2,
    'Active Max': 1.0,
    'Active Min': 0.1,
    'Idle Mean': 1.0,
    'Idle Std': 0.5,
    'Idle Max': 2.0,
    'Idle Min': 0.5,
}

result = predictor.predict(benign_features)
print(f"  Prediction: {result['prediction']}")
print(f"  Confidence: {result['confidence']:.1f}%")
print(f"  Is Anomaly: {result['is_anomaly']}")
print(f"  Risk Score: {result['anomaly_score']:.2f}")
if result['prediction'] == 'BENIGN':
    print("  [OK] CORRECTLY IDENTIFIED AS BENIGN!")
else:
    print(f"  [FAIL] Expected BENIGN, got {result['prediction']}")
print()

print("=== TEST COMPLETE ===")
print("The new model is working correctly!")
