
import json
from pathlib import Path
from datetime import datetime, timezone

from scapy.all import sniff

from live_feature_extractor import (
    INTERFACE,
    WINDOW_SECONDS,
    extract_live_statistics,
)
from live_ids_engine import LiveIDSEngine


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "data" / "live"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "latest_traffic.json"
ALERTS_FILE = OUTPUT_DIR / "ids_alerts.json"

# Persistent IDS engine keeps track of previously observed ARP mappings.
ids_engine = LiveIDSEngine(syn_threshold=100)


def save_json_atomic(path, data):
    """Write JSON safely without leaving a partially written file."""
    temporary_file = path.with_suffix(".tmp")

    with temporary_file.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)

    temporary_file.replace(path)


def save_observation(stats, alerts):
    """Save current network statistics and rule-based IDS results."""
    record = {
        "source": "live_wifi_capture",
        "interface": INTERFACE,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "statistics": stats,
        "ids_status": "rule_based_active_ml_pending",
        "prediction": None,
        "attack_probability": None,
        "rule_based_alert_count": len(alerts),
        "rule_based_alerts": alerts,
    }

    save_json_atomic(OUTPUT_FILE, record)


def save_alerts(alerts):
    """Keep a history of the latest 500 IDS alerts."""
    if not alerts:
        return

    existing = []

    if ALERTS_FILE.exists():
        try:
            with ALERTS_FILE.open("r", encoding="utf-8") as file:
                existing = json.load(file)

            if not isinstance(existing, list):
                existing = []

        except (json.JSONDecodeError, OSError):
            existing = []

    existing.extend(alerts)

    save_json_atomic(ALERTS_FILE, existing[-500:])


def main():
    print("\nSECUREGUARD LIVE NETWORK MONITOR + IDS")
    print("Interface:", INTERFACE)
    print("Output:", OUTPUT_FILE)
    print("IDS alerts:", ALERTS_FILE)
    print("Detection: Rule-based active")
    print("Random Forest: Pending feature compatibility")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            # Capture real Wi-Fi traffic.
            packets = sniff(
                iface=INTERFACE,
                timeout=WINDOW_SECONDS,
                store=True,
            )

            # Preserve existing live traffic statistics.
            stats = extract_live_statistics(packets)

            # Analyze captured packets for suspicious behavior.
            alerts = ids_engine.analyze(packets)

            # Save latest traffic and detection results.
            save_observation(stats, alerts)

            # Save detected alerts separately.
            save_alerts(alerts)

            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] "
                f"Packets={stats['packet_count']} | "
                f"Rate={stats['packet_rate']:.1f}/s | "
                f"TCP={stats['protocols'].get('TCP', 0)} | "
                f"ARP={stats['protocols'].get('ARP', 0)} | "
                f"IDS Alerts={len(alerts)}"
            )

            for alert in alerts:
                print(
                    f"  [IDS ALERT] {alert['attack_type']} | "
                    f"Source={alert['source_ip']} | "
                    f"{alert['evidence']}"
                )

    except KeyboardInterrupt:
        print("\nLive monitoring stopped.")


if __name__ == "__main__":
    main()

