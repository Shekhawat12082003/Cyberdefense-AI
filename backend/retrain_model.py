"""
Retrain ML model with new training data
"""
import pandas as pd
import numpy as np
import pickle
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import sys
sys.path.insert(0, '.')

print("=== RETRAINING ML MODEL ===")
print()

# Load training data
print("Step 1: Loading training data...")
df = pd.read_csv('training_data.csv')
print(f"Loaded {len(df)} samples")
print(f"Classes: {df['label'].value_counts().to_dict()}")
print()

# Separate features and labels
print("Step 2: Preparing features and labels...")
feature_columns = [col for col in df.columns if col not in ['label', 'timestamp']]
X = df[feature_columns].values
y = df['label'].values

print(f"Features: {X.shape}")
print(f"Labels: {y.shape}")
print()

# Encode labels
print("Step 3: Encoding labels...")
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
print(f"Label classes: {label_encoder.classes_}")
print()

# Split train/test
print("Step 4: Splitting train/test data...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"Train samples: {len(X_train)}")
print(f"Test samples: {len(X_test)}")
print()

# Scale features
print("Step 5: Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("Features scaled")
print()

# Train Random Forest
print("Step 6: Training Random Forest model...")
rf_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42,
    n_jobs=-1
)
rf_model.fit(X_train_scaled, y_train)
print("Model trained")
print()

# Evaluate
print("Step 7: Evaluating model...")
y_pred = rf_model.predict(X_test_scaled)
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
print()

# Save model
print("Step 8: Saving model...")
models_dir = Path('models')
models_dir.mkdir(exist_ok=True)

# Save Random Forest
with open(models_dir / 'network_rf_model.pkl', 'wb') as f:
    pickle.dump(rf_model, f)
print(f"Saved Random Forest model to {models_dir / 'network_rf_model.pkl'}")

# Save scaler
with open(models_dir / 'network_scaler.pkl', 'wb') as f:
    pickle.dump(scaler, f)
print(f"Saved scaler to {models_dir / 'network_scaler.pkl'}")

# Save label encoder
with open(models_dir / 'network_label_encoder.pkl', 'wb') as f:
    pickle.dump(label_encoder, f)
print(f"Saved label encoder to {models_dir / 'network_label_encoder.pkl'}")

# Save model info
model_info = {
    'features': feature_columns,
    'classes': label_encoder.classes_.tolist(),
    'n_features': len(feature_columns),
    'n_classes': len(label_encoder.classes_),
    'accuracy': rf_model.score(X_test_scaled, y_test)
}

import json
with open(models_dir / 'network_model_info.json', 'w') as f:
    json.dump(model_info, f, indent=2)
print(f"Saved model info to {models_dir / 'network_model_info.json'}")
print()

print("=== MODEL RETRAINING COMPLETE ===")
print(f"Model accuracy: {model_info['accuracy']:.2%}")
print("Model saved and ready for deployment")
