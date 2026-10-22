import hmac
import hashlib
import secrets

#secrets.token_bytes(32)	Generates a random 256-bit secret key
#hmac.new()	Creates an HMAC signature
#hashlib.sha256	SHA-256 hash algorithm
#compare_digest()	Compares signatures safely
#device_keys	Stores device secrets temporarily in memory
class DeviceSecurity:

    def __init__(self):
        self.device_keys = {}

    def register_device(self, device_id):
        secret_key = secrets.token_bytes(32)
        self.device_keys[device_id] = secret_key
        return secret_key

    def generate_signature(self, secret_key, message):
        return hmac.new(
            secret_key,
            message.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def verify_signature(self, device_id, message, signature):
        secret_key = self.device_keys.get(device_id)

        if secret_key is None:
            return False

        expected_signature = self.generate_signature(
            secret_key, message
        )

        return hmac.compare_digest(
            expected_signature, signature
        )


if __name__ == "__main__":

    security = DeviceSecurity()

    key = security.register_device("HR001")

    message = "Heart Rate: 75 BPM"

    valid_signature = security.generate_signature(
        key, message
    )

    print("Genuine device:",
          security.verify_signature(
              "HR001", message, valid_signature
          ))

    print("Fake signature:",
          security.verify_signature(
              "HR001", message, "fake_signature"
          ))