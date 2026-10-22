import unittest
import pandas as pd
from pathlib import Path

from ml_model.predict import IntrusionDetectionSystem


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "processed" / "test_processed.csv"


class TestIntrusionDetectionSystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ids = IntrusionDetectionSystem()
        cls.df = pd.read_csv(DATA_PATH)

    def test_model_loaded(self):
        self.assertEqual(len(self.ids.features), 45)
        self.assertEqual(self.ids.algorithm, "Random Forest")

    def test_normal_traffic(self):
        record = self.df[self.df["Label"] == 0].iloc[0]
        result = self.ids.predict(record[self.ids.features].to_dict())

        self.assertEqual(result["prediction"], "NORMAL")

    def test_attack_traffic(self):
        record = self.df[self.df["Label"] == 1].iloc[0]
        result = self.ids.predict(record[self.ids.features].to_dict())

        self.assertEqual(result["prediction"], "ATTACK")

    def test_missing_features(self):
        with self.assertRaises(ValueError):
            self.ids.predict({"Rate": 100})


if __name__ == "__main__":
    unittest.main()