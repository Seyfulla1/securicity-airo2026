#!/usr/bin/env python3
"""
VillageShield - Core Utilities (the protected backend)
======================================================

This represents the REAL control plane of the village: the service that actually
acts on device commands (records telemetry, turns the pump on/off, etc.). It is
the "crown jewels" we are protecting.

Notice what is NOT here: there is no security logic at all. That is intentional.
In a zero-trust design the backend assumes that *something in front of it* has
already vetted every request. Core Utilities is also NOT published to the host in
docker-compose - the ONLY way to reach it is through the security router on the
internal bridge. If an attacker can't even route to it, they can't attack it.
"""

import os
from datetime import datetime, timezone

from flask import Flask, request, jsonify

CORE_PORT = int(os.environ.get("CORE_PORT", "6000"))

app = Flask(__name__)

# A tiny in-memory record of the last command executed per device, just so the
# service does something observable in its logs.
LAST_COMMAND = {}


@app.get("/health")
def health():
    return jsonify({"service": "villageshield-core", "status": "up"}), 200


@app.post("/command")
def command():
    data = request.get_json(silent=True) or {}
    device_id = data.get("device_id", "unknown")
    action = data.get("action", "unknown")
    payload = data.get("payload", "")

    LAST_COMMAND[device_id] = {
        "action": action,
        "payload": payload,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }
    print(f"[CORE] executed {action} for {device_id} (payload={payload!r})", flush=True)
    return jsonify({"executed": True, "device_id": device_id, "action": action}), 200


if __name__ == "__main__":
    print(f"[BOOT] VillageShield core listening on :{CORE_PORT}", flush=True)
    app.run(host="0.0.0.0", port=CORE_PORT, threaded=True)
