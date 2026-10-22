import unittest
import pandas as pd
from pathlib import Path

from backend.ids_monitor import IDSMonitor


BASE_DIR = Path(__file__).resolve().parent.parent
DATA_PATH = BASE_DIR / "data" / "processed" / "test_processed.csv"


class TestIDSMonitor(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.df = pd.read_csv(DATA_PATH)

    def setUp(self):
        self.monitor = IDSMonitor()

    def test_normal_traffic_no_alert(self):
        record = self.df[self.df["Label"] == 0].iloc[0]
        features = record[self.monitor.ids.features].to_dict()

        result = self.monitor.analyze_traffic(features, "HR001")

        self.assertEqual(result["prediction"]["prediction"], "NORMAL")
        self.assertIsNone(result["alert"])
        self.assertEqual(len(self.monitor.get_alerts()), 0)

    def test_attack_generates_alert(self):
        record = self.df[self.df["Label"] == 1].iloc[0]
        features = record[self.monitor.ids.features].to_dict()

        result = self.monitor.analyze_traffic(features, "HR001")

        self.assertEqual(result["prediction"]["prediction"], "ATTACK")
        self.assertIsNotNone(result["alert"])
        self.assertEqual(
            result["alert"]["threat_type"],
            "POSSIBLE_ARP_SPOOFING"
        )
        self.assertEqual(len(self.monitor.get_alerts()), 1)

    def test_multiple_alerts_stored(self):
        record = self.df[self.df["Label"] == 1].iloc[0]
        features = record[self.monitor.ids.features].to_dict()

        self.monitor.analyze_traffic(features, "HR001")
        self.monitor.analyze_traffic(features, "TEMP001")

        alerts = self.monitor.get_alerts()

        self.assertEqual(len(alerts), 2)
        self.assertEqual(alerts[0]["device_id"], "HR001")
        self.assertEqual(alerts[1]["device_id"], "TEMP001")


if __name__ == "__main__":
    unittest.main()