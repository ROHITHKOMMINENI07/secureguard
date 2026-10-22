import json
from cryptography.exceptions import InvalidTag


class ServerReceiver:

    def __init__(self, authenticator, communication, encryption):
        self.authenticator = authenticator
        self.communication = communication
        self.encryption = encryption

    def receive_message(self, payload, signature):

        # Step 1: Check device registration
        device_id = payload.get("device_id")

        if device_id not in self.authenticator.registered_devices:
            return False, "Unregistered device"

        # Step 2: Verify HMAC signature and replay nonce
        try:
            is_valid, reason = self.communication.verify_message(
                payload, signature
            )
        except (KeyError, TypeError, ValueError):
            return False, "Invalid message format"

        if not is_valid:
            return False, reason

        # Step 3: Decrypt encrypted healthcare reading
        try:
            encrypted_reading = payload["reading"]

            nonce = bytes.fromhex(encrypted_reading["aes_nonce"])
            ciphertext = bytes.fromhex(encrypted_reading["ciphertext"])

            decrypted_json = self.encryption.decrypt_data(
                nonce, ciphertext
            )

            reading = json.loads(decrypted_json)

        except (InvalidTag, KeyError, TypeError, ValueError):
            return False, "Decryption failed or invalid data"

        # Step 4: Confirm reading belongs to sending device
        if not isinstance(reading, dict):
            return False, "Invalid reading format"

        if reading.get("device_id") != device_id:
            return False, "Device ID mismatch"

        return True, reading