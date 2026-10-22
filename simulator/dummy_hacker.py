
import requests
import json
from datetime import datetime

API_URL = "http://127.0.0.1:8000/device-data"


def send_attack(attack_name, payload, signature):
    print("\n" + "=" * 55)
    print("SECUREGUARD - DUMMY HACKER")
    print("=" * 55)

    print("Attack Type:", attack_name)
    print("Time:", datetime.now().strftime("%H:%M:%S"))
    print("Target:", API_URL)
    print("Attacker Device:", payload["device_id"])

    try:
        response = requests.post(
            API_URL,
            json={
                "payload": payload,
                "signature": signature
            },
            timeout=10
        )

        print("\nHTTP Status:", response.status_code)

        try:
            print("Server Response:")
            print(json.dumps(response.json(), indent=2))
        except ValueError:
            print(response.text)

        if response.status_code == 403:
            print("\n[BLOCKED] SecureGuard rejected the attack.")

        elif response.status_code == 200:
            print("\n[WARNING] SecureGuard accepted the message!")

        else:
            print("\n[INFO] Request was not accepted.")
            print("Check the response to identify the reason.")

    except requests.RequestException as error:
        print("\n[ERROR] Cannot connect to SecureGuard.")
        print("Details:", error)
        print("Start the system using: python main.py")


def unauthorized_device_attack():
    fake_payload = {
        "device_id": "HACKER001",
        "device_type": "heart_rate",
        "value": 250,
        "timestamp": datetime.now().isoformat()
    }

    fake_signature = "invalid_hacker_signature"

    send_attack(
        "Unauthorized Device Spoofing",
        fake_payload,
        fake_signature
    )


def main():
    print("\n======================================")
    print("    SECUREGUARD ATTACK SIMULATOR")
    print("======================================")
    print("Mode: Local demonstration")
    print("Attack: Unauthorized healthcare device")

    unauthorized_device_attack()


if __name__ == "__main__":
    main()
