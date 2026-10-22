import joblib
import pandas as pd
from pathlib import Path


class IntrusionDetectionSystem:

    def __init__(self, threshold=0.57):

        base_dir = Path(__file__).resolve().parent

        model_path = base_dir / "ids_model_advanced.joblib"

        saved = joblib.load(model_path)

        self.model = saved["model"]
        self.features = saved["features"]
        self.algorithm = saved["algorithm"]
        self.threshold = threshold

        print(f"IDS Model Loaded: {self.algorithm}")

    def predict(self, traffic_features):

        # Accept a dictionary containing network features
        data = pd.DataFrame([traffic_features])

        # Ensure all 45 features are present
        missing = [
            feature for feature in self.features
            if feature not in data.columns
        ]

        if missing:
            raise ValueError(
                f"Missing {len(missing)} network features: {missing}"
            )

        data = data[self.features]

        # Calculate attack score
        attack_score = float(
            self.model.predict_proba(data)[0][1]
        )

        prediction = (
            "ATTACK"
            if attack_score >= self.threshold
            else "NORMAL"
        )

        return {
            "prediction": prediction,
            "attack_score": round(attack_score, 4),
            "threshold": self.threshold,
            "algorithm": self.algorithm
        }