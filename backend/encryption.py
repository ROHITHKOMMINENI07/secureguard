import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class DataEncryption:

    def __init__(self):
        # Generate a 256-bit secret key
        self.key = AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt_data(self, message):
        # Generate a fresh 12-byte nonce
        nonce = os.urandom(12)

        # Convert plaintext into bytes
        plaintext = message.encode("utf-8")

        # Encrypt and authenticate the data
        ciphertext = self.aesgcm.encrypt(
            nonce, plaintext, None
        )

        return nonce, ciphertext

    def decrypt_data(self, nonce, ciphertext):
        # Decrypt and verify the encrypted data
        plaintext = self.aesgcm.decrypt(
            nonce, ciphertext, None
        )

        return plaintext.decode("utf-8")


if __name__ == "__main__":

    encryption = DataEncryption()

    patient_data = "Heart Rate: 85 BPM"

    print("\nOriginal Patient Data:")
    print(patient_data)

    nonce, encrypted_data = encryption.encrypt_data(patient_data)

    print("\nEncrypted Patient Data:")
    print(encrypted_data.hex())

    decrypted_data = encryption.decrypt_data(
        nonce, encrypted_data
    )

    print("\nDecrypted Patient Data:")
    print(decrypted_data)
    