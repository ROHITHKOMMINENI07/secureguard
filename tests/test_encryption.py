from backend.encryption import DataEncryption
from cryptography.exceptions import InvalidTag


def test_encryption():
    encryption = DataEncryption()
    message = "Heart Rate: 85 BPM"

    # Test 1: Genuine encryption and decryption
    nonce, ciphertext = encryption.encrypt_data(message)
    decrypted = encryption.decrypt_data(nonce, ciphertext)

    assert decrypted == message
    print("[PASS] Genuine encrypted data decrypted successfully")

    # Test 2: Attacker modifies encrypted data
    tampered = bytearray(ciphertext)
    tampered[0] ^= 1

    try:
        encryption.decrypt_data(nonce, bytes(tampered))
        print("[FAIL] Tampered ciphertext accepted")
    except InvalidTag:
        print("[PASS] Tampered ciphertext rejected")

    # Test 3: Attacker uses wrong encryption key
    attacker = DataEncryption()

    try:
        attacker.decrypt_data(nonce, ciphertext)
        print("[FAIL] Wrong encryption key accepted")
    except InvalidTag:
        print("[PASS] Wrong encryption key rejected")


if __name__ == "__main__":
    test_encryption()