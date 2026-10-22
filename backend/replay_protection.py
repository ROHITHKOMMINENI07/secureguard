import secrets


class ReplayProtection:

    def __init__(self):
        self.used_nonces = set()

    def generate_nonce(self):
        return secrets.token_hex(16)

    def verify_nonce(self, device_id, nonce):

        if (device_id, nonce) in self.used_nonces:
            return False

        self.used_nonces.add((device_id, nonce))
        return True


if __name__ == "__main__":

    replay = ReplayProtection()

    nonce = replay.generate_nonce()

    print("Generated Nonce:", nonce)

    print("First Request:",
          replay.verify_nonce("HR001", nonce))

    print("Replay Attack:",
          replay.verify_nonce("HR001", nonce))

    new_nonce = replay.generate_nonce()

    print("New Request:",
          replay.verify_nonce("HR001", new_nonce))