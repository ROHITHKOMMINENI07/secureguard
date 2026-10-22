from backend.device_security import DeviceSecurity


def test_device_security():
    security = DeviceSecurity()

    # Register genuine healthcare device
    secret_key = security.register_device("HR001")

    message = "Heart Rate: 75 BPM"

    # TEST 1: Genuine device
    valid_signature = security.generate_signature(
        secret_key, message
    )

    print("\nTEST 1: Genuine Device")

    if security.verify_signature(
        "HR001", message, valid_signature
    ):
        print("[PASSED] Genuine device accepted")
    else:
        print("[FAILED] Genuine device rejected")

    # TEST 2: Attacker impersonates HR001
    print("\nTEST 2: Device Spoofing Attack")

    fake_signature = "attacker_fake_signature"

    if not security.verify_signature(
        "HR001", message, fake_signature
    ):
        print("[PASSED] Spoofed device rejected")
    else:
        print("[FAILED] Spoofed device accepted")

    # TEST 3: Attacker modifies message
    print("\nTEST 3: Message Tampering Attack")

    modified_message = "Heart Rate: 150 BPM"

    if not security.verify_signature(
        "HR001", modified_message, valid_signature
    ):
        print("[PASSED] Modified message rejected")
    else:
        print("[FAILED] Modified message accepted")


if __name__ == "__main__":
    test_device_security()