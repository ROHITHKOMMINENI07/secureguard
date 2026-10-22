from simulator.device_simulator import HealthcareDevice
from simulator.device_sender import DeviceSender

from backend.authentication import DeviceAuthenticator
from backend.secure_communication import SecureCommunication
from backend.encryption import DataEncryption
from backend.server_receiver import ServerReceiver


def test_sender_receiver():

    # Step 1: Initialize security modules
    authenticator = DeviceAuthenticator()
    communication = SecureCommunication()
    encryption = DataEncryption()

    # Step 2: Create healthcare device
    device = HealthcareDevice("HR001", "heart_rate")

    # Step 3: Register device and generate HMAC key
    secret_key = communication.register_device("HR001")

    # Step 4: Create sender and receiver
    sender = DeviceSender(
        device,
        encryption,
        communication,
        secret_key
    )

    receiver = ServerReceiver(
        authenticator,
        communication,
        encryption
    )

    # TEST 1: Genuine message
    payload, signature = sender.prepare_secure_message()

    accepted, result = receiver.receive_message(
        payload, signature
    )

    assert accepted, f"Genuine message rejected: {result}"
    assert result["device_id"] == "HR001"

    print("[PASS] Genuine healthcare message accepted")
    print("[DATA]", result)

    # TEST 2: Replay attack
    accepted, reason = receiver.receive_message(
        payload, signature
    )

    assert not accepted
    assert reason == "Replay attack detected"

    print("[PASS] Replay attack blocked")

    # TEST 3: Message tampering
    tampered_payload = {
        **payload,
        "reading": {
            **payload["reading"],
            "ciphertext": "00" + payload["reading"]["ciphertext"][2:]
        }
    }

    accepted, reason = receiver.receive_message(
        tampered_payload, signature
    )

    assert not accepted
    assert reason == "Invalid HMAC signature"

    print("[PASS] Tampered message blocked")


if __name__ == "__main__":
    test_sender_receiver()