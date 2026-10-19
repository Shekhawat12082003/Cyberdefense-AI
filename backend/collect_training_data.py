"""
Collect training data for ML model retraining
Captures real network traffic features and labels them
"""
import csv
import time
import json
import threading
from datetime import datetime
from pathlib import Path
import sys
sys.path.insert(0, '.')

from utils.ml_predictor import MLPredictor
from utils.flow_extractor import FlowExtractor, Flow

class TrainingDataCollector:
    def __init__(self, output_file='training_data.csv'):
        self.output_file = Path(output_file)
        self.flows_data = []
        self.flow_extractor = FlowExtractor()
        self._lock = threading.Lock()
        self.running = False

    def start_collection(self, duration_seconds=60):
        """Start collecting traffic data"""
        self.running = True
        self.flow_extractor.start(self._on_flow_complete)
        print(f"Collecting training data for {duration_seconds} seconds...")
        print("Generate traffic now (browsing, apps, or use attack scripts)")
        print()

        time.sleep(duration_seconds)

        self.flow_extractor.stop()
        self.running = False
        print(f"\nCollection complete. Collected {len(self.flows_data)} flow samples.")

    def _on_flow_complete(self, features, flow):
        """Callback when flow is complete"""
        if not self.running:
            return

        with self._lock:
            # Add label (default to BENIGN)
            flow_data = {
                'label': 'BENIGN',
                'timestamp': datetime.utcnow().isoformat(),
                **features
            }
            self.flows_data.append(flow_data)

    def save_to_csv(self):
        """Save collected data to CSV"""
        if not self.flows_data:
            print("No data to save!")
            return

        # Get feature names from first flow
        feature_names = list(self.flows_data[0].keys())

        with open(self.output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=feature_names)
            writer.writeheader()
            writer.writerows(self.flows_data)

        print(f"Saved {len(self.flows_data)} samples to {self.output_file}")

    def add_attack_samples(self, attack_type, features_list):
        """Add attack samples with labels"""
        for features in features_list:
            flow_data = {
                'label': attack_type,
                'timestamp': datetime.utcnow().isoformat(),
                **features
            }
            self.flows_data.append(flow_data)
        print(f"Added {len(features_list)} {attack_type} samples")


def generate_port_scan_samples():
    """Generate synthetic port scan features"""
    samples = []
    for i in range(50):
        sample = {
            'Flow Duration': 1.0 + i * 0.1,
            'Total Fwd Packets': 50 + i * 2,
            'Total Backward Packets': 5,
            'Total Length of Fwd Packets': 2500 + i * 100,
            'Total Length of Bwd Packets': 250,
            'Fwd Packet Length Max': 60,
            'Fwd Packet Length Mean': 50,
            'Fwd Packet Length Std': 10,
            'Bwd Packet Length Max': 60,
            'Bwd Packet Length Mean': 50,
            'Bwd Packet Length Std': 10,
            'Flow Bytes/s': 2750 + i * 100,
            'Flow Packets/s': 55 + i * 2,
            'Flow IAT Mean': 0.02,
            'Flow IAT Std': 0.01,
            'Flow IAT Max': 0.05,
            'Flow IAT Min': 0.001,
            'Fwd IAT Total': 1.0 + i * 0.1,
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
            'Fwd Header Length': 2000 + i * 100,
            'Bwd Header Length': 200,
            'Fwd Packets/s': 50 + i * 2,
            'Bwd Packets/s': 5,
            'Min Packet Length': 40,
            'Max Packet Length': 60,
            'Packet Length Mean': 50,
            'Packet Length Std': 10,
            'Packet Length Variance': 100,
            'FIN Flag Count': 0,
            'SYN Flag Count': 50 + i * 2,  # High SYN = port scan
            'RST Flag Count': 25 + i,  # Many RST = rejected connections
            'PSH Flag Count': 10,
            'ACK Flag Count': 5,
            'URG Flag Count': 0,
            'Down/Up Ratio': 0.1,
            'Average Packet Size': 50,
            'Avg Fwd Segment Size': 50,
            'Avg Bwd Segment Size': 50,
            'Subflow Fwd Packets': 50 + i * 2,
            'Subflow Fwd Bytes': 2500 + i * 100,
            'Subflow Bwd Packets': 5,
            'Subflow Bwd Bytes': 250,
            'Init_Win_bytes_forward': 8192,
            'Init_Win_bytes_backward': 8192,
            'Init_Win_bytes_forward': 8192,
            'Init_Win_bytes_backward': 8192,
            'act_data_pkt_fwd': 50 + i * 2,
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
        samples.append(sample)
    return samples


def generate_dos_samples():
    """Generate synthetic DoS features"""
    samples = []
    for i in range(50):
        sample = {
            'Flow Duration': 5.0 + i * 0.5,
            'Total Fwd Packets': 500 + i * 20,
            'Total Backward Packets': 10,
            'Total Length of Fwd Packets': 25000 + i * 1000,
            'Total Length of Bwd Packets': 500,
            'Fwd Packet Length Max': 60,
            'Fwd Packet Length Mean': 50,
            'Fwd Packet Length Std': 10,
            'Bwd Packet Length Max': 60,
            'Bwd Packet Length Mean': 50,
            'Bwd Packet Length Std': 10,
            'Flow Bytes/s': 5100 + i * 200,
            'Flow Packets/s': 102 + i * 4,
            'Flow IAT Mean': 0.01,
            'Flow IAT Std': 0.005,
            'Flow IAT Max': 0.02,
            'Flow IAT Min': 0.001,
            'Fwd IAT Total': 5.0 + i * 0.5,
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
            'Fwd Header Length': 20000 + i * 1000,
            'Bwd Header Length': 400,
            'Fwd Packets/s': 100 + i * 4,
            'Bwd Packets/s': 2,
            'Min Packet Length': 40,
            'Max Packet Length': 60,
            'Packet Length Mean': 50,
            'Packet Length Std': 10,
            'Packet Length Variance': 100,
            'FIN Flag Count': 5,
            'SYN Flag Count': 500 + i * 20,  # Very high SYN = DoS
            'RST Flag Count': 0,
            'PSH Flag Count': 50,
            'ACK Flag Count': 10,
            'URG Flag Count': 0,
            'Down/Up Ratio': 0.02,
            'Average Packet Size': 50,
            'Avg Fwd Segment Size': 50,
            'Avg Bwd Segment Size': 50,
            'Subflow Fwd Packets': 500 + i * 20,
            'Subflow Fwd Bytes': 25000 + i * 1000,
            'Subflow Bwd Packets': 10,
            'Subflow Bwd Bytes': 500,
            'Init_Win_bytes_forward': 8192,
            'Init_Win_bytes_backward': 8192,
            'Init_Win_bytes_forward': 8192,
            'Init_Win_bytes_backward': 8192,
            'act_data_pkt_fwd': 500 + i * 20,
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
        samples.append(sample)
    return samples


def generate_benign_samples():
    """Generate synthetic benign traffic features"""
    samples = []
    for i in range(100):
        sample = {
            'Flow Duration': 10.0 + i * 0.5,
            'Total Fwd Packets': 20 + i,
            'Total Backward Packets': 20 + i,
            'Total Length of Fwd Packets': 10000 + i * 500,
            'Total Length of Bwd Packets': 10000 + i * 500,
            'Fwd Packet Length Max': 1500,
            'Fwd Packet Length Mean': 500,
            'Fwd Packet Length Std': 200,
            'Bwd Packet Length Max': 1500,
            'Bwd Packet Length Mean': 500,
            'Bwd Packet Length Std': 200,
            'Flow Bytes/s': 2000 + i * 100,
            'Flow Packets/s': 4 + i * 0.2,
            'Flow IAT Mean': 0.5,
            'Flow IAT Std': 0.2,
            'Flow IAT Max': 1.0,
            'Flow IAT Min': 0.1,
            'Fwd IAT Total': 10.0 + i * 0.5,
            'Fwd IAT Mean': 0.5,
            'Fwd IAT Std': 0.2,
            'Fwd IAT Max': 1.0,
            'Fwd IAT Min': 0.1,
            'Bwd IAT Total': 10.0 + i * 0.5,
            'Bwd IAT Mean': 0.5,
            'Bwd IAT Std': 0.2,
            'Bwd IAT Max': 1.0,
            'Bwd IAT Min': 0.1,
            'Fwd PSH Flags': 10,
            'Bwd PSH Flags': 10,
            'Fwd URG Flags': 0,
            'Bwd URG Flags': 0,
            'Fwd Header Length': 8000 + i * 400,
            'Bwd Header Length': 8000 + i * 400,
            'Fwd Packets/s': 2 + i * 0.1,
            'Bwd Packets/s': 2 + i * 0.1,
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
            'Subflow Fwd Packets': 20 + i,
            'Subflow Fwd Bytes': 10000 + i * 500,
            'Subflow Bwd Packets': 20 + i,
            'Subflow Bwd Bytes': 10000 + i * 500,
            'Init_Win_bytes_forward': 65535,
            'Init_Win_bytes_backward': 65535,
            'Init_Win_bytes_forward': 65535,
            'Init_Win_bytes_backward': 65535,
            'act_data_pkt_fwd': 20 + i,
            'act_data_pkt_bwd': 20 + i,
            'Active Mean': 0.5,
            'Active Std': 0.2,
            'Active Max': 1.0,
            'Active Min': 0.1,
            'Idle Mean': 1.0,
            'Idle Std': 0.5,
            'Idle Max': 2.0,
            'Idle Min': 0.5,
        }
        samples.append(sample)
    return samples


if __name__ == '__main__':
    print("=== TRAINING DATA COLLECTION ===")
    print()

    collector = TrainingDataCollector('training_data.csv')

    # Step 1: Generate synthetic training data
    print("Step 1: Generating synthetic training data...")
    print()

    # Add benign samples
    benign_samples = generate_benign_samples()
    collector.add_attack_samples('BENIGN', benign_samples)

    # Add port scan samples
    port_scan_samples = generate_port_scan_samples()
    collector.add_attack_samples('PORT_SCAN', port_scan_samples)

    # Add DoS samples
    dos_samples = generate_dos_samples()
    collector.add_attack_samples('DOS', dos_samples)

    print()
    print(f"Total samples: {len(collector.flows_data)}")
    print(f"  BENIGN: {len(benign_samples)}")
    print(f"  PORT_SCAN: {len(port_scan_samples)}")
    print(f"  DOS: {len(dos_samples)}")
    print()

    # Step 2: Save to CSV
    print("Step 2: Saving to CSV...")
    collector.save_to_csv()

    print()
    print("=== DATA COLLECTION COMPLETE ===")
    print("Next step: Retrain the ML model with this data")
