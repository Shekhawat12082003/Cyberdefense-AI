import numpy as np
import pandas as pd
import random
from sklearn.preprocessing import StandardScaler
import joblib

print("=== CORRECTED TRAINING DATA COLLECTION ===")
print("Using correct CIC-IDS2017 feature names...\n")

# Correct feature names from CIC-IDS2017 (66 features)
feature_names = [
    'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
    'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min',
    'Bwd Packet Length Mean', 'Bwd Packet Length Std', 'Flow Bytes/s',
    'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max',
    'Flow IAT Min', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
    'Fwd IAT Min', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max',
    'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags',
    'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance',
    'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count',
    'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size',
    'Avg Bwd Segment Size', 'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk',
    'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk',
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
    'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
    'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max',
    'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

samples = []
labels = []

print("Step 1: Generating BENIGN traffic (normal network activity)...")
for _ in range(150):
    features = {}
    # Normal web browsing patterns
    features['Flow Duration'] = random.uniform(1000, 10000)
    features['Total Fwd Packets'] = random.uniform(5, 50)
    features['Total Backward Packets'] = random.uniform(5, 50)
    features['Total Length of Fwd Packets'] = random.uniform(1000, 10000)
    features['Total Length of Bwd Packets'] = random.uniform(1000, 10000)
    features['Flow Bytes/s'] = random.uniform(1000, 10000)
    features['Flow Packets/s'] = random.uniform(10, 100)
    features['SYN Flag Count'] = random.uniform(1, 5)
    features['ACK Flag Count'] = random.uniform(5, 20)
    features['Active Mean'] = random.uniform(100, 500)
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('BENIGN')

print("Step 2: Generating PORT_SCAN traffic (high SYN count, many ports)...")
for _ in range(100):
    features = {}
    # Port scan signature: High SYN count, low ACK, many destinations
    features['Flow Duration'] = random.uniform(100, 500)
    features['Total Fwd Packets'] = random.uniform(1, 5)
    features['Total Backward Packets'] = random.uniform(0, 2)
    features['Total Length of Fwd Packets'] = random.uniform(100, 500)
    features['Total Length of Bwd Packets'] = random.uniform(0, 100)
    features['Flow Bytes/s'] = random.uniform(100, 500)
    features['Flow Packets/s'] = random.uniform(50, 200)
    features['SYN Flag Count'] = random.uniform(20, 100)  # HIGH SYN Flag Count
    features['ACK Flag Count'] = random.uniform(0, 5)  # Low ACK Flag Count
    features['Active Mean'] = random.uniform(10, 100)
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('PORT_SCAN')

print("Step 3: Generating DOS traffic (high packet rate to single port)...")
for _ in range(100):
    features = {}
    # DoS signature: High packet rate, single destination, low port diversity
    features['Flow Duration'] = random.uniform(5000, 20000)
    features['Total Fwd Packets'] = random.uniform(100, 500)  # HIGH Fwd Packets
    features['Total Backward Packets'] = random.uniform(0, 10)
    features['Total Length of Fwd Packets'] = random.uniform(50000, 200000)
    features['Total Length of Bwd Packets'] = random.uniform(0, 1000)
    features['Flow Bytes/s'] = random.uniform(50000, 200000)  # HIGH Flow Bytes/s
    features['Flow Packets/s'] = random.uniform(500, 2000)  # HIGH Flow Packets/s
    features['SYN Flag Count'] = random.uniform(10, 30)
    features['ACK Flag Count'] = random.uniform(50, 100)  # High ACK Flag Count
    features['Active Mean'] = random.uniform(500, 2000)  # HIGH Active Mean
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('DOS')

print("Step 4: Generating BRUTE_FORCE traffic (login attempts to auth ports)...")
for _ in range(100):
    features = {}
    # Brute force signature: Failed login attempts, specific ports (22, 3389)
    features['Flow Duration'] = random.uniform(2000, 10000)
    features['Total Fwd Packets'] = random.uniform(20, 100)
    features['Total Backward Packets'] = random.uniform(10, 50)
    features['Total Length of Fwd Packets'] = random.uniform(1000, 5000)
    features['Total Length of Bwd Packets'] = random.uniform(500, 2000)
    features['Flow Bytes/s'] = random.uniform(5000, 20000)
    features['Flow Packets/s'] = random.uniform(20, 100)
    features['SYN Flag Count'] = random.uniform(10, 30)
    features['ACK Flag Count'] = random.uniform(20, 50)
    features['Active Mean'] = random.uniform(200, 800)
    # Fill remaining features with 0
    for name in feature_names:
        if name not in features:
            features[name] = 0
    samples.append(features)
    labels.append('BRUTE_FORCE')

print("Step 5: Generating WEB_ATTACK traffic (SQL injection, XSS)...")
for _ in range(100):
    features = {}
    # Web attack signature: HTTP traffic with malicious payloads
    features['Flow Duration'] = random.uniform(2000, 15000)
    features['Total Fwd Packets'] = random.uniform(10, 50)
    features['Total Backward Packets'] = random.uniform(10, 50)
    features['Total Length of Fwd Packets'] = random.uniform(2000, 10000)  # Large Fwd Packets (malicious payload)
    features['Total Length of Bwd Packets'] = random.uniform(1000, 5000)
    features['Flow Bytes/s'] = random.uniform(2000, 10000)
    features['Flow Packets/s'] = random.uniform(10, 50)
    features['SYN Flag Count'] = random.uniform(5, 15)
    features['ACK Flag Count'] = random.uniform(10, 30)
    features['Active Mean'] = random.uniform(150, 600)
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
df.to_csv('training_data_corrected.csv', index=False)
print(f"\nStep 7: Saved to training_data_corrected.csv")

print("\n=== DATA COLLECTION COMPLETE ===")
print("Next step: Retrain the ML model with corrected data")
