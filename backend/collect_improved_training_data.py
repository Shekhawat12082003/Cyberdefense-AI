import numpy as np
import pandas as pd
import random
from sklearn.preprocessing import StandardScaler
import joblib

print("=== IMPROVED TRAINING DATA COLLECTION ===")
print("Creating distinctive features for each attack type...\n")

# Feature names based on CIC-IDS2017 dataset (78 features)
feature_names = [f'feature_{i}' for i in range(78)]

samples = []
labels = []

print("Step 1: Generating BENIGN traffic (normal network activity)...")
for _ in range(150):
    features = np.zeros(78)
    # Normal web browsing patterns
    features[0] = random.uniform(1000, 10000)  # Flow Duration
    features[1] = random.uniform(5, 50)  # Total Fwd Packets
    features[2] = random.uniform(5, 50)  # Total Backward Packets
    features[13] = random.uniform(1000, 10000)  # Flow Bytes/s
    features[14] = random.uniform(10, 100)  # Flow Packets/s
    features[38] = random.uniform(1, 5)  # SYN Flag Count (normal)
    features[41] = random.uniform(5, 20)  # ACK Flag Count
    features[65] = random.uniform(100, 500)  # Active Mean
    samples.append(features)
    labels.append('BENIGN')

print("Step 2: Generating PORT_SCAN traffic (high SYN count, many ports)...")
for _ in range(100):
    features = np.zeros(78)
    # Port scan signature: High SYN count, low ACK, many destinations
    features[0] = random.uniform(100, 500)  # Short Flow Duration
    features[1] = random.uniform(1, 5)  # Few Fwd Packets
    features[2] = random.uniform(0, 2)  # Few or no Bwd Packets
    features[13] = random.uniform(100, 500)  # Low Flow Bytes/s
    features[14] = random.uniform(50, 200)  # Moderate Flow Packets/s
    features[38] = random.uniform(20, 100)  # HIGH SYN Flag Count (port scan signature)
    features[41] = random.uniform(0, 5)  # Low ACK Flag Count
    features[65] = random.uniform(10, 100)  # Low Active Mean
    samples.append(features)
    labels.append('PORT_SCAN')

print("Step 3: Generating DOS traffic (high packet rate to single port)...")
for _ in range(100):
    features = np.zeros(78)
    # DoS signature: High packet rate, single destination, low port diversity
    features[0] = random.uniform(5000, 20000)  # Long Flow Duration
    features[1] = random.uniform(100, 500)  # HIGH Fwd Packets
    features[2] = random.uniform(0, 10)  # Few Bwd Packets
    features[13] = random.uniform(50000, 200000)  # HIGH Flow Bytes/s
    features[14] = random.uniform(500, 2000)  # HIGH Flow Packets/s
    features[38] = random.uniform(10, 30)  # Moderate SYN Flag Count
    features[41] = random.uniform(50, 100)  # High ACK Flag Count
    features[65] = random.uniform(500, 2000)  # HIGH Active Mean
    samples.append(features)
    labels.append('DOS')

print("Step 4: Generating BRUTE_FORCE traffic (login attempts to auth ports)...")
for _ in range(100):
    features = np.zeros(78)
    # Brute force signature: Failed login attempts, specific ports (22, 3389)
    features[0] = random.uniform(2000, 10000)  # Medium Flow Duration
    features[1] = random.uniform(20, 100)  # Moderate Fwd Packets
    features[2] = random.uniform(10, 50)  # Moderate Bwd Packets
    features[13] = random.uniform(5000, 20000)  # Moderate Flow Bytes/s
    features[14] = random.uniform(20, 100)  # Moderate Flow Packets/s
    features[38] = random.uniform(10, 30)  # Moderate SYN Flag Count
    features[41] = random.uniform(20, 50)  # Moderate ACK Flag Count
    features[65] = random.uniform(200, 800)  # Moderate Active Mean
    # Add specific patterns for authentication failures
    features[3] = random.uniform(1000, 5000)  # Total Length of Fwd Packets
    features[4] = random.uniform(500, 2000)  # Total Length of Bwd Packets
    samples.append(features)
    labels.append('BRUTE_FORCE')

print("Step 5: Generating WEB_ATTACK traffic (SQL injection, XSS)...")
for _ in range(100):
    features = np.zeros(78)
    # Web attack signature: HTTP traffic with malicious payloads
    features[0] = random.uniform(2000, 15000)  # Medium Flow Duration
    features[1] = random.uniform(10, 50)  # Moderate Fwd Packets
    features[2] = random.uniform(10, 50)  # Moderate Bwd Packets
    features[13] = random.uniform(2000, 10000)  # Moderate Flow Bytes/s
    features[14] = random.uniform(10, 50)  # Low Flow Packets/s
    features[38] = random.uniform(5, 15)  # Low SYN Flag Count
    features[41] = random.uniform(10, 30)  # Moderate ACK Flag Count
    features[65] = random.uniform(150, 600)  # Moderate Active Mean
    # Web attacks have specific payload patterns
    features[3] = random.uniform(2000, 10000)  # Large Fwd Packets (malicious payload)
    samples.append(features)
    labels.append('WEB_ATTACK')

# Convert to numpy arrays
X = np.array(samples)
y = np.array(labels)

print(f"\nStep 6: Total samples collected: {len(X)}")
label_counts = {label: sum(1 for l in y if l == label) for label in set(y)}
for label, count in label_counts.items():
    print(f"  {label}: {count}")

# Create DataFrame
df = pd.DataFrame(X, columns=feature_names)
df['label'] = y

# Save to CSV
df.to_csv('training_data_improved.csv', index=False)
print(f"\nStep 7: Saved to training_data_improved.csv")

print("\n=== DATA COLLECTION COMPLETE ===")
print("Next step: Retrain the ML model with improved data")
