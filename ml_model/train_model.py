import pandas as pd
import joblib
from pathlib import Path

from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    train_test_split
)
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data" / "processed"
MODEL_DIR = BASE_DIR / "ml_model"

print("Loading datasets...")

train_df = pd.read_csv(DATA_DIR / "train_processed.csv")
test_df = pd.read_csv(DATA_DIR / "test_processed.csv")

X = train_df.drop(columns=["Label"])
y = train_df["Label"]

X_test = test_df[X.columns]
y_test = test_df["Label"]

X_train, X_val, y_train, y_val = train_test_split(
    X,
    y,
    test_size=0.2,
    stratify=y,
    random_state=42
)

models = {
    "Random Forest": RandomForestClassifier(
        random_state=42,
        n_jobs=2
    ),
    "Extra Trees": ExtraTreesClassifier(
        random_state=42,
        n_jobs=2
    )
}

parameters = {
    "n_estimators": [200, 300, 400],
    "max_depth": [15, 25, 35, None],
    "min_samples_split": [2, 5, 10],
    "min_samples_leaf": [1, 2, 4],
    "max_features": ["sqrt", 0.7],
    "class_weight": [None, "balanced", {0: 2, 1: 1}]
}

best_model = None
best_score = -1
best_name = None

for name, estimator in models.items():

    print(f"\nTraining {name}...")

    search = RandomizedSearchCV(
        estimator=estimator,
        param_distributions=parameters,
        n_iter=12,
        cv=3,
        scoring="f1",
        n_jobs=1,
        random_state=42,
        verbose=1
    )

    search.fit(X_train, y_train)

    model = search.best_estimator_
    predictions = model.predict(X_val)

    score = f1_score(y_val, predictions)

    print(f"\n{name} Validation Results:")
    print("Accuracy:", round(accuracy_score(y_val, predictions), 4))
    print("Precision:", round(precision_score(y_val, predictions), 4))
    print("Recall:", round(recall_score(y_val, predictions), 4))
    print("F1 Score:", round(score, 4))

    if score > best_score:
        best_score = score
        best_model = model
        best_name = name

print("\nBest algorithm:", best_name)

# Evaluate selected model on the separate test dataset
test_predictions = best_model.predict(X_test)

print("\n===== FINAL TEST RESULTS =====")
print("Accuracy:", round(accuracy_score(y_test, test_predictions), 4))
print("Precision:", round(precision_score(y_test, test_predictions, zero_division=0), 4))
print("Recall:", round(recall_score(y_test, test_predictions, zero_division=0), 4))
print("F1 Score:", round(f1_score(y_test, test_predictions, zero_division=0), 4))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, test_predictions, labels=[0, 1]))

joblib.dump(
    {
        "model": best_model,
        "features": X.columns.tolist(),
        "algorithm": best_name
    },
    MODEL_DIR / "ids_model_advanced.joblib"
)

print("\nAdvanced model saved successfully!")