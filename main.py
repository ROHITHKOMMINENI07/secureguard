import sys
import time
import threading
import subprocess
from pathlib import Path

import uvicorn

from backend.app_state import state
from simulator.device_monitor import DeviceMonitor


BASE_DIR = Path(__file__).resolve().parent


def start_device_monitor():
    monitor = DeviceMonitor(interval=5)
    monitor.start()


def main():
    print("\n====================================")
    print("       SECUREGUARD SYSTEM")
    print("====================================")

    print("\nSecurity Components:")
    print("AES-256-GCM Encryption: READY")
    print("HMAC Authentication: READY")
    print("Replay Protection: READY")
    print(f"AI IDS Model: {state.ids_monitor.ids.algorithm}")

    dashboard_process = None
    live_monitor_process = None

    try:
        # Configure FastAPI
        config = uvicorn.Config(
            "backend.api:app",
            host="127.0.0.1",
            port=8000,
            reload=False,
            log_level="info"
        )
        server = uvicorn.Server(config)

        # Start healthcare IoT device simulator
        device_thread = threading.Thread(
            target=start_device_monitor,
            daemon=True
        )
        device_thread.start()

        # Start live Wi-Fi network monitoring
        live_monitor_process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(BASE_DIR / "backend" / "live_monitor.py")
            ],
            cwd=str(BASE_DIR)
        )

        # Start Streamlit dashboard
        dashboard_process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "streamlit",
                "run",
                str(BASE_DIR / "dashboard" / "app.py"),
                "--server.address",
                "127.0.0.1",
                "--server.port",
                "8501",
                "--server.headless",
                "true"
            ],
            cwd=str(BASE_DIR)
        )

        print("\nSecureGuard Services Starting...")
        print("Healthcare IoT Simulator: STARTED")
        print("Live Wi-Fi Monitoring: STARTED")
        print("FastAPI: http://127.0.0.1:8000")
        print("API Docs: http://127.0.0.1:8000/docs")
        print("Streamlit Dashboard: http://127.0.0.1:8501")
        print("\nPress Ctrl+C to stop SecureGuard.\n")

        # Run FastAPI in the main process
        server.run()

    except KeyboardInterrupt:
        print("\nStopping SecureGuard...")

    finally:
        for process in [live_monitor_process, dashboard_process]:
            if process is not None and process.poll() is None:
                process.terminate()

                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

        print("SecureGuard shutdown complete.")


if __name__ == "__main__":
    main()

