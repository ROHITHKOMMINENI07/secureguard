import joblib

data = joblib.load("ml_model/ids_model_advanced.joblib")

print("Saved object type:", type(data).__name__)

if isinstance(data, dict):
    print("Available keys:", list(data.keys()))
    features = next((data[k] for k in ("features", "feature_columns", "feature_names") if k in data and data[k] is not None), None)
    model = data.get("model")
else:
    model = data
    features = getattr(model, "feature_names_in_", None)

if features is None and model is not None:
    features = getattr(model, "feature_names_in_", None)

if features is not None:
    print("\nTotal features:", len(features))
    for i, feature in enumerate(features, 1):
        print(f"{i:02d}. {feature}")
else:
    print("Feature names not found.")

if model is not None:
    print("Model type:", type(model).__name__)
    print("Expected features:", getattr(model, "n_features_in_", "Unknown"))
