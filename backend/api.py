
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from backend.app_state import state


app = FastAPI(
    title="SecureGuard API",
    description="AI-Based Healthcare IoT Cybersecurity System",
    version="1.0.0"
)


class DeviceMessage(BaseModel):
    payload: dict[str, Any]
    signature: str


@app.get("/")
def home():
    return {
        "project": "SecureGuard",
        "message": "Healthcare IoT Security Server Running",
        "status": "active"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "SecureGuard Backend",
        "ids_model": state.ids_monitor.ids.algorithm
    }


@app.post("/device-data")
def receive_device_data(message: DeviceMessage):

    # Verify device authentication, message integrity,
    # replay protection, and encrypted payload.
    accepted, result = state.receiver.receive_message(
        message.payload,
        message.signature
    )

    if not accepted:
        state.blocked_attacks.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "device_id": message.payload.get(
                "device_id", "unknown"
            ),
            "reason": str(result),
            "status": "blocked"
        })

        raise HTTPException(
            status_code=403,
            detail=result
        )

    # Save verified reading in application state.
    state.readings.append(result)

    return {
        "status": "accepted",
        "device_id": result["device_id"],
        "reading": result
    }


@app.get("/readings")
def get_readings():
    return {
        "total": len(state.readings),
        "readings": state.readings
    }


@app.get("/alerts")
def get_alerts():
    alerts = state.ids_monitor.get_alerts()

    return {
        "total": len(alerts),
        "alerts": alerts
    }


@app.get("/live-traffic")
def get_live_traffic():

    traffic_file = (
        Path(__file__).resolve().parent.parent
        / "data"
        / "live"
        / "latest_traffic.json"
    )

    if not traffic_file.exists():
        raise HTTPException(
            status_code=503,
            detail="Live traffic data is not available yet"
        )

    try:
        with traffic_file.open(
            "r", encoding="utf-8"
        ) as file:
            return json.load(file)

    except (OSError, ValueError) as error:
        raise HTTPException(
            status_code=503,
            detail=f"Unable to read live traffic data: {error}"
        )


@app.get("/blocked-attacks")
def get_blocked_attacks():
    return {
        "total": len(state.blocked_attacks),
        "attacks": state.blocked_attacks
    }
