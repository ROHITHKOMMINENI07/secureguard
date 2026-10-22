
import unittest
import json

from fastapi.testclient import TestClient

from backend.api import app
from backend.app_state import state

from simulator.device_simulator import HealthcareDevice
from simulator.device_sender import DeviceSender


class TestAPIIntegration(unittest.TestCase):

    def test_genuine_device_http_request(self):
        client = TestClient(app)

        # Create a registered healthcare device
        device = HealthcareDevice("HR001", "heart_rate")

        # Register device and generate HMAC key
        secret_key = state.communication.register_device(
            device.device_id
        )

        # Check whether sender and receiver share the same key
        receiver_key = state.communication.security.device_keys.get(
            device.device_id
        )

        print(
            "\nSender and receiver keys match:",
            secret_key == receiver_key
        )

        print(
            "API uses shared receiver:",
            state.receiver.communication is state.communication
        )

        # Create secure device sender
        sender = DeviceSender(
            device,
            state.encryption,
            state.communication,
            secret_key
        )

        # Generate encrypted and signed message
        payload, signature = sender.prepare_secure_message()

        # Check HMAC before HTTP transmission
        hmac_before = state.communication.security.verify_signature(
            device.device_id,
            json.dumps(payload, sort_keys=True),
            signature
        )

        print("HMAC valid before HTTP:", hmac_before)

        # Simulate HTTP JSON serialization and deserialization
        http_payload = json.loads(json.dumps(payload))

        hmac_after = state.communication.security.verify_signature(
            device.device_id,
            json.dumps(http_payload, sort_keys=True),
            signature
        )

        print("HMAC valid after JSON round-trip:", hmac_after)

        # Send message to FastAPI TestClient
        response = client.post(
            "/device-data",
            json={
                "payload": payload,
                "signature": signature
            }
        )

        print("API Status Code:", response.status_code)
        print("API Response:", response.json())

        # Verify API accepted the genuine device
        self.assertEqual(
            response.status_code,
            200,
            msg=f"API rejected device: {response.text}"
        )

        result = response.json()

        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["device_id"], "HR001")

        # Verify accepted reading is stored
        readings_response = client.get("/readings")

        self.assertEqual(readings_response.status_code, 200)

        readings = readings_response.json()["readings"]

        self.assertTrue(
            any(
                reading["device_id"] == "HR001"
                for reading in readings
            )
        )


if __name__ == "__main__":
    unittest.main()
