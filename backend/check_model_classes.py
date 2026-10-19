# Check what attack types the ML model can detect
import sys
sys.path.insert(0, '.')

from utils.ml_predictor import MLPredictor

print("=== CHECKING ML MODEL CAPABILITIES ===")
print()

predictor = MLPredictor()
predictor.load_models()

print("Model Information:")
print(f"RF Model Loaded: {predictor.rf_model is not None}")
print(f"Scaler Loaded: {predictor.scaler is not None}")
print(f"Label Encoder Loaded: {predictor.label_encoder is not None}")
print()

if predictor.rf_model:
    print("Random Forest Classes (Attack Types it can detect):")
    classes = predictor.rf_model.classes_
    for i, cls in enumerate(classes):
        print(f"  {i}: {cls}")
    print()

if predictor.label_encoder:
    print("Label Encoder Classes:")
    try:
        classes = predictor.label_encoder.classes_
        for i, cls in enumerate(classes):
            print(f"  {i}: {cls}")
    except:
        print("  (Cannot access classes)")
    print()

print("Feature Names:")
print(f"  Total features: {len(predictor.feature_names)}")
print(f"  Sample features: {predictor.feature_names[:10]}")
print()

print("=== CONCLUSION ===")
print("The model is trained to detect these attack types.")
print("If predictions are always BENIGN, it may be because:")
print("1. Features don't match training data exactly")
print("2. Model needs retraining with more diverse data")
print("3. Feature scaling is different")
