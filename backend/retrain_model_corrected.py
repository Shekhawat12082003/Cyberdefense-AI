import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import json

print("=== RETRAINING ML MODEL WITH CORRECTED DATA ===")

# Step 1: Load training data
print("\nStep 1: Loading training data...")
df = pd.read_csv('training_data_corrected.csv')
print(f"Loaded {len(df)} samples")

# Separate features and labels
X = df.drop('label', axis=1)
y = df['label']

print(f"Features: {list(X.columns)}")
print(f"Classes: {dict(zip(*np.unique(y, return_counts=True)))}")

# Step 2: Encode labels
print("\nStep 2: Encoding labels...")
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)
print(f"Label classes: {label_encoder.classes_}")

# Step 3: Split train/test data
print("\nStep 3: Splitting train/test data...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
)
print(f"Train samples: {len(X_train)}")
print(f"Test samples: {len(X_test)}")

# Step 4: Scale features
print("\nStep 4: Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("Features scaled")

# Step 5: Train Random Forest model
print("\nStep 5: Training Random Forest model...")
model = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1
)
model.fit(X_train_scaled, y_train)
print("Model trained")

# Step 6: Evaluate model
print("\nStep 6: Evaluating model...")
y_pred = model.predict(X_test_scaled)
print("\nClassification Report:")
print(classification_report(
    y_test, y_pred,
    target_names=label_encoder.classes_,
    zero_division=0
))

# Step 7: Save model
print("\nStep 7: Saving model...")
joblib.dump(model, 'models/network_rf_model.pkl')
joblib.dump(scaler, 'models/network_scaler.pkl')
joblib.dump(label_encoder, 'models/network_label_encoder.pkl')

# Save model info with correct feature names
model_info = {
    'accuracy': float(model.score(X_test_scaled, y_test)),
    'rf_accuracy': float(model.score(X_test_scaled, y_test) * 100),
    'n_estimators': model.n_estimators,
    'max_depth': model.max_depth,
    'feature_count': X.shape[1],
    'features': list(X.columns),
    'classes': label_encoder.classes_.tolist(),
    'sample_count': len(df)
}

with open('models/network_model_info.json', 'w') as f:
    json.dump(model_info, f, indent=2)

print(f"Saved Random Forest model to models/network_rf_model.pkl")
print(f"Saved scaler to models/network_scaler.pkl")
print(f"Saved label encoder to models/network_label_encoder.pkl")
print(f"Saved model info to models/network_model_info.json")

print("\n=== MODEL RETRAINING COMPLETE ===")
print(f"Model accuracy: {model_info['accuracy']:.2%}")
print("Model saved and ready for deployment")
