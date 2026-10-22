import joblib
import numpy as np
import pandas as pd

from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = BASE_DIR / "ml_model" / "ids_model_advanced.joblib"
DATA_PATH = BASE_DIR / "data" / "processed" / "train_processed.csv"

# Load trained model
saved = joblib.load(MODEL_PATH)
model = saved["model"]
features = saved["features"]

# Load training data
df = pd.read_csv(DATA_PATH)

X = df[features]
y = df["Label"]

# Recreate the original validation split
_, X_val, _, y_val = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

# Calculate attack probabilities
probabilities = model.predict_proba(X_val)[:, 1]
best_threshold = None
best_f1 = -1

for threshold in np.arange(0.50, 0.951, 0.01):
    predictions = (probabilities >= threshold).astype(int)

    recall = recall_score(y_val, predictions, zero_division=0)
    f1 = f1_score(y_val, predictions, zero_division=0)

    if recall >= 0.90 and f1 > best_f1:
        best_f1 = f1
        best_threshold = round(float(threshold), 2)

print("\n===== AUTOMATIC THRESHOLD SELECTION =====")

if best_threshold is None:
    print("No threshold met the minimum 90% recall requirement.")
else:
    print("Selected threshold:", best_threshold)
    print("Validation F1:", round(best_f1, 4))

print("\n===== THRESHOLD COMPARISON =====")

for threshold in np.arange(0.50, 0.96, 0.05):

    predictions = (probabilities >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_val,
        predictions,
        labels=[0, 1]
    ).ravel()

    print(f"\nThreshold: {threshold:.2f}")
    print(f"Accuracy: {accuracy_score(y_val, predictions):.4f}")
    print(f"Precision: {precision_score(y_val, predictions, zero_division=0):.4f}")
    print(f"Recall: {recall_score(y_val, predictions, zero_division=0):.4f}")
    print(f"F1 Score: {f1_score(y_val, predictions, zero_division=0):.4f}")
    print(f"False Positives: {fp}")
    print(f"Missed Attacks: {fn}")
    print(f"False Positive Rate: {fp / (fp + tn):.4f}")
    print("\n===== TEST DATA THRESHOLD EVALUATION =====")

test_df = pd.read_csv(
    BASE_DIR / "data" / "processed" / "test_processed.csv"
)

X_test = test_df[features]
y_test = test_df["Label"]

test_probabilities = model.predict_proba(X_test)[:, 1]

for threshold in [0.50, 0.70, 0.80, 0.90]:
    predictions = (test_probabilities >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    print(f"\nThreshold: {threshold:.2f}")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"Precision: {precision_score(y_test, predictions, zero_division=0):.4f}")
    print(f"Recall: {recall_score(y_test, predictions, zero_division=0):.4f}")
    print(f"F1 Score: {f1_score(y_test, predictions, zero_division=0):.4f}")
    print(f"False Positives: {fp}")
    print(f"Missed Attacks: {fn}")

    selected_threshold = 0.57

final_predictions = (
    test_probabilities >= selected_threshold
).astype(int)

tn, fp, fn, tp = confusion_matrix(
    y_test,
    final_predictions,
    labels=[0, 1]
).ravel()

print("\n===== SELECTED THRESHOLD FINAL TEST =====")
print("Threshold:", selected_threshold)
print("Accuracy:", round(accuracy_score(y_test, final_predictions), 4))
print("Precision:", round(precision_score(y_test, final_predictions), 4))
print("Recall:", round(recall_score(y_test, final_predictions), 4))
print("F1 Score:", round(f1_score(y_test, final_predictions), 4))
print("False Positives:", fp)
print("Missed Attacks:", fn)
print("False Positive Rate:", round(fp / (fp + tn), 4))
print("Confusion Matrix:")
print(confusion_matrix(y_test, final_predictions, labels=[0, 1]))