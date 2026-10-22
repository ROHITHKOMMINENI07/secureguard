import json


class DeviceSender:

    def __init__(self, device, encryption, communication, secret_key):
        self.device = device
        self.encryption = encryption
        self.communication = communication
        self.secret_key = secret_key

    def prepare_secure_message(self):

        # Step 1: Generate healthcare sensor reading
        reading = self.device.generate_reading()

        # Step 2: Convert reading to JSON
        reading_json = json.dumps(reading)

        # Step 3: Encrypt reading using AES-256-GCM
        aes_nonce, ciphertext = self.encryption.encrypt_data(
            reading_json
        )

        encrypted_reading = {
            "aes_nonce": aes_nonce.hex(),
            "ciphertext": ciphertext.hex()
        }

        # Step 4: Generate signed message with replay nonce
        payload, signature = self.communication.create_message(
            self.device.device_id,
            encrypted_reading,
            self.secret_key
        )

        return payload, signature