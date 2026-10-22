
import json
import sqlite3
from pathlib import Path

try:
    from backend.database import get_connection, initialize_database
except ModuleNotFoundError:
    from database import get_connection, initialize_database


BASE_DIR = Path(__file__).resolve().parent.parent
OLD_REGISTRY_FILE = BASE_DIR / "data" / "registered_devices.json"

DEFAULT_DEVICES = {
    "HR001": "heart_rate",
    "TEMP001": "temperature",
    "SPO2001": "spo2",
}

VALID_DEVICE_TYPES = {
    "heart_rate",
    "temperature",
    "spo2",
}


class DeviceAuthenticator:

    def __init__(self):
        initialize_database()
        self._migrate_existing_devices()

    def _migrate_existing_devices(self):
        devices = DEFAULT_DEVICES.copy()

        if OLD_REGISTRY_FILE.exists():
            with OLD_REGISTRY_FILE.open(
                "r", encoding="utf-8"
            ) as file:
                old_devices = json.load(file)

            if isinstance(old_devices, dict):
                devices = old_devices

        with get_connection() as connection:
            for device_id, device_type in devices.items():
                connection.execute(
                    """
                    INSERT OR IGNORE INTO devices
                    (device_id, device_type, status)
                    VALUES (?, ?, 'active')
                    """,
                    (device_id, device_type)
                )

    @property
    def registered_devices(self):
        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT device_id, device_type
                FROM devices
                WHERE status = 'active'
                """
            ).fetchall()

        return {
            row["device_id"]: row["device_type"]
            for row in rows
        }

    def authenticate_device(self, device_id, device_type):
        with get_connection() as connection:
            row = connection.execute(
                """
                SELECT device_id
                FROM devices
                WHERE device_id = ?
                  AND device_type = ?
                  AND status = 'active'
                """,
                (device_id, device_type)
            ).fetchone()

        return row is not None

    def register_device(self, device_id, device_type):
        device_id = device_id.strip()

        if not device_id:
            raise ValueError("Device ID cannot be empty")

        if device_type not in VALID_DEVICE_TYPES:
            raise ValueError("Unsupported device type")

        with get_connection() as connection:
            existing = connection.execute(
                """
                SELECT status
                FROM devices
                WHERE device_id = ?
                """,
                (device_id,)
            ).fetchone()

            if existing:
                raise ValueError(
                    "Device ID already exists. "
                    "Use reactivation for revoked devices."
                )

            connection.execute(
                """
                INSERT INTO devices
                (device_id, device_type, status)
                VALUES (?, ?, 'active')
                """,
                (device_id, device_type)
            )

        return True

    def revoke_device(self, device_id):
        with get_connection() as connection:
            cursor = connection.execute(
                """
                UPDATE devices
                SET status = 'revoked',
                    revoked_at = CURRENT_TIMESTAMP
                WHERE device_id = ?
                  AND status = 'active'
                """,
                (device_id,)
            )

            if cursor.rowcount == 0:
                raise ValueError(
                    "Device not found or already revoked"
                )

        return True

    def list_devices(self):
        with get_connection() as connection:
            rows = connection.execute(
                """
                SELECT device_id, device_type,
                       status, registered_at, revoked_at
                FROM devices
                ORDER BY registered_at DESC
                """
            ).fetchall()

        return [dict(row) for row in rows]


if __name__ == "__main__":
    auth = DeviceAuthenticator()

    print("Registered Devices:", auth.registered_devices)

    print(
        "HR001:",
        auth.authenticate_device("HR001", "heart_rate")
    )

    print(
        "HACKER001:",
        auth.authenticate_device("HACKER001", "heart_rate")
    )

    print("All Devices:", auth.list_devices())
