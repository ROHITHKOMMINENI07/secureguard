
import time
from datetime import datetime

from simulator.device_simulator import HealthcareDevice
from simulator.device_sender import DeviceSender
from backend.app_state import state


class DeviceMonitor:

    def __init__(self, interval=5):
        self.interval = interval
        self.running = False

        self.devices = [
            HealthcareDevice("HR001", "heart_rate"),
            HealthcareDevice("TEMP001", "temperature"),
            HealthcareDevice("SPO2001", "spo2")
        ]

        self.senders = []

        for device in self.devices:
            secret_key = state.communication.register_device(
                device.device_id
            )

            sender = DeviceSender(
                device,
                state.encryption,
                state.communication,
                secret_key
            )

            self.senders.append(sender)

    def monitor_once(self):
        results = []

        for sender in self.senders:
            payload, signature = sender.prepare_secure_message()

            accepted, result = state.receiver.receive_message(
                payload,
                signature
            )

            if accepted:
                state.readings.append(result)

                print(
                    f"[{datetime.now().strftime('%H:%M:%S')}] "
                    f"{result['device_id']} | "
                    f"{result['value']} {result['unit']} | "
                    f"SECURE"
                )

                results.append(result)

            else:
                print(
                    f"SECURITY ALERT: {result}"
                )

        return results

    def start(self):
        self.running = True

        print("\nSecureGuard Automatic Device Monitoring Started")
        print(f"Reading interval: {self.interval} seconds\n")

        try:
            while self.running:
                self.monitor_once()
                time.sleep(self.interval)

        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self.running = False
        print("\nDevice Monitoring Stopped")


if __name__ == "__main__":
    monitor = DeviceMonitor(interval=5)
    monitor.start()
