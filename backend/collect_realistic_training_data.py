import numpy as np
import pandas as pd
import random
from sklearn.preprocessing import StandardScaler
import joblib

print("=== REALISTIC TRAINING DATA COLLECTION ===")
print("Generating more realistic attack patterns...\n")

# Correct feature names from CIC-IDS2017 (75 features)
feature_names = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Flow Bytes/s', 'Flow Packets/s', 'SYN Flag Count', 'ACK Flag Count', 'Active Mean',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow IAT Mean', 'Flow IAT Std',
    'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
    'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'URG Flag Count',
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size',
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1',
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
    'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
    'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets',
    'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

samples = []
labels = []

print("Step 1: Generating BENIGN traffic (normal network activity)...")
for _ in range(200):
    features = {}
    # Normal web browsing patterns - varied and realistic
    features['Flow Duration'] = random.uniform(2000, 15000)
    features['Total Fwd Packets'] = random.uniform(10, 100)
    features['Total Backward Packets'] = random.uniform(10, 100)
    features['Total Length of Fwd Packets'] = random.uniform(2000, 20000)
    features['Total Length of Bwd Packets'] = random.uniform(2000, 20000)
    features['Flow Bytes/s'] = random.uniform(2000, 15000)
    features['Flow Packets/s'] = random.uniform(20, 150)
    features['SYN Flag Count'] = random.uniform(1, 5)
    features['ACK Flag Count'] = random.uniform(10, 50)
    features['Active Mean'] = random.uniform(200, 800)
    features['RST Flag Count'] = random.uniform(0, 2)
    features['Fwd IAT Mean'] = random.uniform(100, 1000)
    features['Bwd IAT Mean'] = random.uniform(100, 1000)
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('BENIGN')

print("Step 2: Generating PORT_SCAN traffic (high SYN count, many ports)...")
for _ in range(150):
    features = {}
    # Port scan signature: High SYN count, low ACK, many destinations, short duration
    features['Flow Duration'] = random.uniform(50, 500)
    features['Total Fwd Packets'] = random.uniform(1, 10)
    features['Total Backward Packets'] = random.uniform(0, 3)
    features['Total Length of Fwd Packets'] = random.uniform(50, 500)
    features['Total Length of Bwd Packets'] = random.uniform(0, 150)
    features['Flow Bytes/s'] = random.uniform(100, 1000)
    features['Flow Packets/s'] = random.uniform(50, 300)
    features['SYN Flag Count'] = random.uniform(30, 150)  # VERY HIGH SYN Flag Count
    features['ACK Flag Count'] = random.uniform(0, 5)  # VERY LOW ACK Flag Count
    features['Active Mean'] = random.uniform(10, 100)
    features['RST Flag Count'] = random.uniform(0, 3)
    features['Fwd IAT Mean'] = random.uniform(10, 100)
    features['Bwd IAT Mean'] = random.uniform(0, 50)
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('PORT_SCAN')

print("Step 3: Generating DOS traffic (high packet rate to single port)...")
for _ in range(150):
    features = {}
    # DoS signature: High packet rate, single destination, very high throughput
    features['Flow Duration'] = random.uniform(10000, 30000)
    features['Total Fwd Packets'] = random.uniform(200, 1000)  # VERY HIGH Fwd Packets
    features['Total Backward Packets'] = random.uniform(0, 20)
    features['Total Length of Fwd Packets'] = random.uniform(100000, 500000)
    features['Total Length of Bwd Packets'] = random.uniform(0, 5000)
    features['Flow Bytes/s'] = random.uniform(100000, 500000)  # VERY HIGH Flow Bytes/s
    features['Flow Packets/s'] = random.uniform(1000, 5000)  # VERY HIGH Flow Packets/s
    features['SYN Flag Count'] = random.uniform(20, 50)
    features['ACK Flag Count'] = random.uniform(100, 200)  # HIGH ACK Flag Count
    features['Active Mean'] = random.uniform(1000, 5000)  # VERY HIGH Active Mean
    features['RST Flag Count'] = random.uniform(0, 2)
    features['Fwd IAT Mean'] = random.uniform(1, 10)  # Very low IAT (fast packets)
    features['Bwd IAT Mean'] = random.uniform(0, 100)
    features['Down/Up Ratio'] = random.uniform(10, 100)  # High down/up ratio
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('DOS')

print("Step 4: Generating BRUTE_FORCE traffic (login attempts to auth ports)...")
for _ in range(150):
    features = {}
    # Brute force signature: Failed login attempts, moderate packet rate, specific timing
    features['Flow Duration'] = random.uniform(5000, 20000)
    features['Total Fwd Packets'] = random.uniform(30, 150)
    features['Total Backward Packets'] = random.uniform(20, 100)
    features['Total Length of Fwd Packets'] = random.uniform(3000, 15000)
    features['Total Length of Bwd Packets'] = random.uniform(1000, 5000)
    features['Flow Bytes/s'] = random.uniform(5000, 20000)
    features['Flow Packets/s'] = random.uniform(30, 150)
    features['SYN Flag Count'] = random.uniform(15, 40)
    features['ACK Flag Count'] = random.uniform(30, 80)
    features['Active Mean'] = random.uniform(300, 1200)
    features['RST Flag Count'] = random.uniform(5, 20)  # Some RST flags (failed connections)
    features['Fwd IAT Mean'] = random.uniform(50, 200)
    features['Bwd IAT Mean'] = random.uniform(50, 200)
    features['Down/Up Ratio'] = random.uniform(1, 5)  # Moderate down/up ratio
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('BRUTE_FORCE')

print("Step 5: Generating WEB_ATTACK traffic (SQL injection, XSS)...")
for _ in range(150):
    features = {}
    # Web attack signature: HTTP traffic with malicious payloads, large requests
    features['Flow Duration'] = random.uniform(3000, 20000)
    features['Total Fwd Packets'] = random.uniform(20, 80)
    features['Total Backward Packets'] = random.uniform(20, 80)
    features['Total Length of Fwd Packets'] = random.uniform(5000, 30000)  # Large Fwd Packets (malicious payload)
    features['Total Length of Bwd Packets'] = random.uniform(2000, 10000)
    features['Flow Bytes/s'] = random.uniform(3000, 15000)
    features['Flow Packets/s'] = random.uniform(15, 80)
    features['SYN Flag Count'] = random.uniform(5, 20)
    features['ACK Flag Count'] = random.uniform(15, 50)
    features['Active Mean'] = random.uniform(200, 800)
    features['RST Flag Count'] = random.uniform(0, 5)
    features['Fwd IAT Mean'] = random.uniform(100, 500)
    features['Bwd IAT Mean'] = random.uniform(100, 500)
    features['Packet Length Mean'] = random.uniform(500, 2000)  # Large packets
    features['Average Packet Size'] = random.uniform(500, 2000)
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('WEB_ATTACK')

# Convert to DataFrame
df = pd.DataFrame(samples)
df['label'] = labels

print(f"\nStep 6: Total samples collected: {len(df)}")
label_counts = df['label'].value_counts().to_dict()
for label, count in label_counts.items():
    print(f"  {label}: {count}")

# Save to CSV
df.to_csv('training_data_realistic.csv', index=False)
print(f"\nStep 7: Saved to training_data_realistic.csv")

print("\n=== DATA COLLECTION COMPLETE ===")
print("Next step: Retrain the ML model with realistic data")
