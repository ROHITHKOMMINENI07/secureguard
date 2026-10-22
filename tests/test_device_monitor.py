
import unittest

from simulator.device_monitor import DeviceMonitor
from backend.app_state import state


class TestDeviceMonitor(unittest.TestCase):

    def setUp(self):
        state.readings.clear()
        self.monitor = DeviceMonitor(interval=5)

    def test_all_devices_generate_readings(self):
        results = self.monitor.monitor_once()

        self.assertEqual(len(results), 3)

        device_ids = {
            reading["device_id"]
            for reading in results
        }

        self.assertEqual(
            device_ids,
            {"HR001", "TEMP001", "SPO2001"}
        )

    def test_readings_saved_in_shared_state(self):
        results = self.monitor.monitor_once()

        self.assertEqual(len(state.readings), 3)
        self.assertEqual(state.readings, results)

    def test_readings_have_required_fields(self):
        results = self.monitor.monitor_once()

        for reading in results:
            self.assertIn("device_id", reading)
            self.assertIn("device_type", reading)
            self.assertIn("value", reading)
            self.assertIn("unit", reading)
            self.assertIn("timestamp", reading)


if __name__ == "__main__":
    unittest.main()

