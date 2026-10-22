from datetime import datetime, timezone

from ml_model.predict import IntrusionDetectionSystem


class IDSMonitor:

    def __init__(self):
        self.ids = IntrusionDetectionSystem()
        self.alerts = []

    def analyze_traffic(self, traffic_features, device_id="UNKNOWN"):

        result = self.ids.predict(traffic_features)

        if result["prediction"] == "ATTACK":

            alert = {
                "device_id": device_id,
                "threat_type": "POSSIBLE_ARP_SPOOFING",
                "attack_score": result["attack_score"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "status": "ALERT"
            }

            self.alerts.append(alert)

            return {
                "prediction": result,
                "alert": alert
            }

        return {
            "prediction": result,
            "alert": None
        }

    def get_alerts(self):
        return self.alerts.copy()