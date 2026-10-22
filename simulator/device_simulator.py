import random
from datetime import datetime


class HealthcareDevice:
    def __init__(self, device_id, device_type):
        self.device_id = device_id
        self.device_type = device_type

    def generate_reading(self):
        if self.device_type == "heart_rate":
            value = random.randint(60, 100)
            unit = "BPM"

        elif self.device_type == "temperature":
            value = round(random.uniform(36.1, 37.2), 2)
            unit = "C"

        elif self.device_type == "spo2":
            value = random.randint(95, 100)
            unit = "%"

        else:
            raise ValueError("Unsupported device type")

        return {
            "device_id": self.device_id,
            "device_type": self.device_type,
            "value": value,
            "unit": unit,
            "timestamp": datetime.now().isoformat()
        }


if __name__ == "__main__":
    devices = [
        HealthcareDevice("HR001", "heart_rate"),
        HealthcareDevice("TEMP001", "temperature"),
        HealthcareDevice("SPO2001", "spo2")
    ]

    for device in devices:
        print(device.generate_reading())