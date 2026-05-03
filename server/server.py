"""Flask server implementing challenge-response device authentication."""

from __future__ import annotations

import logging
from pathlib import Path
from threading import Lock
from typing import Dict

from flask import Flask, jsonify, request

from auth_utils import (
    current_unix_time,
    generate_nonce,
    load_registry,
    parse_public_key,
    save_registry,
    validate_device_id,
    verify_signature,
)

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
REGISTRY_PATH = BASE_DIR / "trusted_devices.json"
CHALLENGE_TTL_SECONDS = 60
MAX_CLOCK_SKEW_SECONDS = 30

registry_lock = Lock()
challenge_lock = Lock()

# In-memory challenge store to prevent replay attacks.
# Format: {device_id: {"nonce": str, "issued_at": int, "used": bool}}
pending_challenges: Dict[str, Dict[str, object]] = {}

logging.basicConfig(
    filename=str(BASE_DIR / "auth.log"),
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def _json_error(message: str, status_code: int = 400):
    """Return a consistent JSON error response."""
    return jsonify({"status": "error", "message": message}), status_code


@app.post("/register")
def register_device():
    """Register a device public key in the trusted registry."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _json_error("Invalid JSON body")

    device_id = payload.get("device_id")
    public_key = payload.get("public_key")

    if not validate_device_id(device_id):
        return _json_error("Invalid device_id format")

    try:
        parse_public_key(public_key)
    except Exception:
        return _json_error("Invalid public key format")

    with registry_lock:
        registry = load_registry(REGISTRY_PATH)
        registry[device_id] = {
            "public_key": public_key,
            "registered_at": current_unix_time(),
        }
        save_registry(REGISTRY_PATH, registry)

    logging.info("Device registered: %s", device_id)
    return jsonify({"status": "ok", "message": "Device registered"})


@app.post("/challenge")
def issue_challenge():
    """Generate and return a fresh challenge nonce for a known device."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _json_error("Invalid JSON body")

    device_id = payload.get("device_id")
    if not validate_device_id(device_id):
        return _json_error("Invalid device_id format")

    with registry_lock:
        registry = load_registry(REGISTRY_PATH)
        if device_id not in registry:
            logging.warning("Challenge requested by unregistered device: %s", device_id)
            return _json_error("Unknown device", 404)

    nonce = generate_nonce(32)
    issued_at = current_unix_time()

    with challenge_lock:
        pending_challenges[device_id] = {
            "nonce": nonce,
            "issued_at": issued_at,
            "used": False,
        }

    logging.info("Challenge issued for device: %s", device_id)
    return jsonify(
        {
            "status": "ok",
            "device_id": device_id,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_in": CHALLENGE_TTL_SECONDS,
        }
    )


@app.post("/authenticate")
def authenticate_device():
    """Validate a signature over an outstanding server challenge."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _json_error("Invalid JSON body")

    device_id = payload.get("device_id")
    nonce = payload.get("nonce")
    signature = payload.get("signature")
    client_timestamp = payload.get("timestamp")

    if not validate_device_id(device_id):
        return _json_error("Invalid device_id format")

    if not isinstance(signature, str) or len(signature) > 4096:
        return _json_error("Invalid signature format")

    with registry_lock:
        registry = load_registry(REGISTRY_PATH)
        device_record = registry.get(device_id)

    if device_record is None:
        logging.warning("Authentication attempt from unknown device: %s", device_id)
        return _json_error("Unknown device", 404)

    with challenge_lock:
        challenge = pending_challenges.get(device_id)
        if challenge is None:
            logging.warning("No active challenge for device: %s", device_id)
            return _json_error("No active challenge", 409)

        expected_nonce = challenge.get("nonce")
        issued_at = int(challenge.get("issued_at", 0))
        used = bool(challenge.get("used", False))

        if used:
            logging.warning("Replay detected for device %s", device_id)
            return _json_error("Challenge already used", 409)

        if nonce != expected_nonce:
            logging.warning("Nonce mismatch for device: %s", device_id)
            return _json_error("Nonce mismatch", 401)

        now = current_unix_time()
        if now - issued_at > CHALLENGE_TTL_SECONDS:
            pending_challenges.pop(device_id, None)
            logging.warning("Expired challenge for device: %s", device_id)
            return _json_error("Challenge expired", 401)

        if client_timestamp is not None:
            if not isinstance(client_timestamp, int):
                return _json_error("timestamp must be an integer")
            if abs(now - client_timestamp) > MAX_CLOCK_SKEW_SECONDS:
                logging.warning("Timestamp skew too large for device: %s", device_id)
                return _json_error("Invalid timestamp", 401)

    ok, message = verify_signature(device_record["public_key"], nonce, signature)

    if not ok:
        logging.warning("Authentication failed for device %s: %s", device_id, message)
        return _json_error("Authentication failed", 401)

    with challenge_lock:
        # Mark used and remove to make replay impossible.
        pending_challenges[device_id]["used"] = True
        pending_challenges.pop(device_id, None)

    logging.info("Authentication successful for device: %s", device_id)
    return jsonify({"status": "ok", "message": "Authentication successful"})


@app.get("/health")
def healthcheck():
    """Return server health status."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
