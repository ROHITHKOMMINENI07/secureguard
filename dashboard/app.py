
import json
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import requests
import streamlit as st


API_URL = "http://127.0.0.1:8000"

BASE_DIR = Path(__file__).resolve().parent.parent
IDS_ALERTS_FILE = BASE_DIR / "data" / "live" / "ids_alerts.json"


st.set_page_config(
    page_title="SecureGuard Hospital Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SecureGuard")
st.caption("AI-Based Healthcare IoT Cybersecurity Monitoring System")


def fetch_api(endpoint):
    response = requests.get(
        f"{API_URL}{endpoint}",
        timeout=3
    )
    response.raise_for_status()
    return response.json()


def load_ids_alerts():
    if not IDS_ALERTS_FILE.exists():
        return []

    try:
        with IDS_ALERTS_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)

        return data if isinstance(data, list) else []

    except (OSError, json.JSONDecodeError):
        return []


@st.fragment(run_every="5s")
def healthcare_dashboard():
    try:
        readings_data = fetch_api("/readings")
        alerts_data = fetch_api("/alerts")

        readings = readings_data.get("readings", [])
        alerts = alerts_data.get("alerts", [])

        st.success("Backend Connected | Live Monitoring Active")

        latest = {}

        for reading in readings:
            latest[reading["device_type"]] = reading

        col1, col2, col3, col4 = st.columns(4)

        with col1:
            heart = latest.get("heart_rate")
            st.metric(
                "❤️ Heart Rate",
                f"{heart['value']} BPM" if heart else "--"
            )

        with col2:
            temp = latest.get("temperature")
            st.metric(
                "🌡️ Temperature",
                f"{temp['value']} °C" if temp else "--"
            )

        with col3:
            spo2 = latest.get("spo2")
            st.metric(
                "🫁 Oxygen Saturation",
                f"{spo2['value']} %" if spo2 else "--"
            )

        with col4:
            st.metric(
                "📡 Secure Readings",
                readings_data.get("total", 0)
            )

        st.divider()

        left, right = st.columns(2)

        with left:
            st.subheader("📈 Healthcare Device Trends")

            if readings:
                df = pd.DataFrame(readings)

                df["timestamp"] = pd.to_datetime(
                    df["timestamp"],
                    errors="coerce"
                )

                df["value"] = pd.to_numeric(
                    df["value"],
                    errors="coerce"
                )

                selected_device = st.selectbox(
                    "Select Healthcare Device",
                    ["heart_rate", "temperature", "spo2"],
                    key="selected_device"
                )

                device_df = df[
                    df["device_type"] == selected_device
                ].copy()

                device_df = device_df.dropna(
                    subset=["timestamp", "value"]
                )

                if not device_df.empty:
                    device_df = device_df.sort_values("timestamp")

                    st.line_chart(
                        device_df.set_index("timestamp")["value"]
                    )
                else:
                    st.info("No readings available.")
            else:
                st.info("Waiting for healthcare device readings...")

        with right:
            st.subheader("🔐 Cybersecurity Status")

            st.write("AES-256-GCM Encryption: Enabled")
            st.write("HMAC-SHA256 Authentication: Enabled")
            st.write("Replay Attack Protection: Enabled")

            st.metric("Backend IDS Alerts", len(alerts))

            if alerts:
                st.error("Backend security alerts detected!")

                st.dataframe(
                    pd.DataFrame(alerts).tail(10),
                    use_container_width=True,
                    hide_index=True
                )
            else:
                st.info("No backend IDS alerts recorded.")

        st.divider()

        st.subheader("📋 Recent Healthcare Device Readings")

        if readings:
            st.dataframe(
                pd.DataFrame(readings[-15:]).iloc[::-1],
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No device readings received yet.")

        st.caption(
            "Last dashboard update: "
            f"{datetime.now().strftime('%H:%M:%S')}"
        )

    except requests.RequestException as error:
        st.error(
            "Cannot connect to SecureGuard FastAPI backend. "
            "Please start the backend using python main.py."
        )
        st.caption(f"Connection details: {error}")


@st.fragment(run_every="5s")
def live_network_monitoring():
    st.divider()
    st.subheader("🌐 Live Network Monitoring")

    st.caption(
        "Real-time Wi-Fi traffic captured using Scapy and Npcap."
    )

    try:
        data = fetch_api("/live-traffic")

        stats = data.get("statistics", {})
        protocols = stats.get("protocols", {})

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "Packets Captured",
            stats.get("packet_count", 0)
        )

        col2.metric(
            "Packet Rate",
            f"{stats.get('packet_rate', 0):.1f}/sec"
        )

        col3.metric(
            "TCP Packets",
            protocols.get("TCP", 0)
        )

        col4.metric(
            "ARP Packets",
            protocols.get("ARP", 0)
        )

        col5, col6, col7 = st.columns(3)

        col5.metric(
            "UDP Packets",
            protocols.get("UDP", 0)
        )

        col6.metric(
            "Traffic Volume",
            f"{stats.get('total_bytes', 0) / 1024:.2f} KB"
        )

        col7.metric(
            "Average Packet Size",
            f"{stats.get('avg_packet_size', 0):.1f} bytes"
        )

        captured_at = data.get("captured_at")

        if captured_at:
            capture_time = datetime.fromisoformat(
                captured_at.replace("Z", "+00:00")
            )

            age = (
                datetime.now(timezone.utc) - capture_time
            ).total_seconds()

            if age <= 30:
                st.success(
                    f"Live capture active - latest observation "
                    f"{max(0, age):.0f} seconds ago."
                )
            else:
                st.warning(
                    f"Capture data is stale: "
                    f"{max(0, age):.0f} seconds old."
                )

        # STEP 68E: Display the actual live IDS status.
        ids_status = data.get("ids_status", "unknown")
        current_alerts = data.get("rule_based_alert_count", 0)

        if ids_status == "rule_based_active_ml_pending":
            if captured_at and age <= 30:
                st.success(
                    "Live Rule-Based IDS: ACTIVE | "
                    "Monitoring ARP spoofing and suspicious "
                    "TCP SYN activity."
                )
            else:
                st.warning(
                    "Rule-Based IDS configured, but live capture "
                    "is not confirmed active."
                )

            st.metric(
                "IDS Alerts in Latest Capture",
                current_alerts
            )

            st.caption(
                "Random Forest ML IDS is trained and evaluated "
                "separately. Live ML inference is not enabled."
            )
        else:
            st.warning(
                "Live IDS status not confirmed. "
                "Check that the updated live monitor is running."
            )

        with st.expander("Detailed Network Statistics"):
            st.json(stats)

    except Exception as error:
        st.warning(
            "Live network monitoring is unavailable. "
            "Ensure FastAPI and the live monitor are running."
        )
        st.caption(str(error))


@st.fragment(run_every="5s")
def live_ids_monitor():
    st.divider()

    st.subheader("🚨 Live Network Intrusion Detection")

    st.caption(
        "Rule-based detection of suspicious ARP spoofing "
        "and TCP SYN activity."
    )

    alerts = load_ids_alerts()

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Live IDS Alerts",
        len(alerts)
    )

    high_count = sum(
        1 for alert in alerts
        if alert.get("severity") == "HIGH"
    )

    col2.metric(
        "High-Severity Alerts",
        high_count
    )

    unique_sources = {
        alert.get("source_ip")
        for alert in alerts
        if alert.get("source_ip")
    }

    col3.metric(
        "Suspicious Source IPs",
        len(unique_sources)
    )

    if alerts:
        st.warning(
            f"{len(alerts)} suspicious network event(s) recorded."
        )

        df = pd.DataFrame(alerts)

        preferred_columns = [
            "timestamp",
            "attack_type",
            "severity",
            "source_ip",
            "detection_method",
            "evidence",
        ]

        available_columns = [
            column for column in preferred_columns
            if column in df.columns
        ]

        st.dataframe(
            df[available_columns].iloc[::-1].head(50),
            use_container_width=True,
            hide_index=True
        )

    else:
        st.success("No rule-based network alerts recorded.")

    st.caption(
        "These alerts indicate suspicious behavior, "
        "not necessarily confirmed attacks. "
        "This detection is separate from Random Forest ML."
    )


@st.fragment(run_every="5s")
def blocked_attack_monitor():
    st.divider()

    st.subheader("🛑 Blocked Device Attacks")

    st.caption(
        "Security rejections recorded by the SecureGuard backend."
    )

    try:
        data = fetch_api("/blocked-attacks")

        total = data.get("total", 0)
        events = data.get("attacks", [])

        st.metric(
            "Blocked Device Requests",
            total
        )

        if total > 0:
            st.error(
                f"SecureGuard rejected {total} "
                "unauthorized or invalid device request(s)."
            )

            st.dataframe(
                list(reversed(events)),
                use_container_width=True,
                hide_index=True
            )

        else:
            st.success("No rejected device requests recorded.")

        st.caption(
            "These events are backend security rejections, "
            "not Random Forest IDS predictions."
        )

    except Exception as error:
        st.warning("Unable to load blocked device attacks.")
        st.caption(str(error))


healthcare_dashboard()
live_network_monitoring()
live_ids_monitor()
blocked_attack_monitor()
