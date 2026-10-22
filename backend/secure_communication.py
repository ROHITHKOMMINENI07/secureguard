import json

from backend.device_security import DeviceSecurity
from backend.replay_protection import ReplayProtection


class SecureCommunication:

    def __init__(self):
        self.security = DeviceSecurity()
        self.replay = ReplayProtection()

    def register_device(self, device_id):
        return self.security.register_device(device_id)

    def create_message(self, device_id, reading, secret_key):
        nonce = self.replay.generate_nonce()

        payload = {
            "device_id": device_id,
            "reading": reading,
            "nonce": nonce
        }

        message = json.dumps(payload, sort_keys=True)

        signature = self.security.generate_signature(
            secret_key, message
        )

        return payload, signature

    def verify_message(self, payload, signature):
        message = json.dumps(payload, sort_keys=True)

        device_id = payload["device_id"]
        nonce = payload["nonce"]

        # Step 1: Verify cryptographic signature
        if not self.security.verify_signature(
            device_id, message, signature
        ):
            return False, "Invalid HMAC signature"

        # Step 2: Check replay attack
        if not self.replay.verify_nonce(device_id, nonce):
            return False, "Replay attack detected"

        return True, "Message accepted"


if __name__ == "__main__":

    communication = SecureCommunication()

    # Register genuine device
    key = communication.register_device("HR001")

    reading = {
        "heart_rate": 75,
        "unit": "BPM"
    }

    # Create authenticated message
    payload, signature = communication.create_message(
        "HR001", reading, key
    )

    # Test 1: Genuine message
    print("\nTEST 1: Genuine Message")
    print(communication.verify_message(payload, signature))

    # Test 2: Replay attack
    print("\nTEST 2: Replay Attack")
    print(communication.verify_message(payload, signature))

    # Test 3: Message tampering
    print("\nTEST 3: Message Tampering")

    tampered_payload = {
        **payload,
        "reading": {
            "heart_rate": 150,
            "unit": "BPM"
        }
    }

    print(communication.verify_message(
        tampered_payload, signature
    ))