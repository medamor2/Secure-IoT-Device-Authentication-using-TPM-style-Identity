"""IoT device client for registration and challenge-response authentication."""

from __future__ import annotations

import argparse
import logging
import sys
import time

import requests

from crypto_utils import sign_nonce
from tpm_utils import (
    export_public_key_pem,
    generate_keypair,
    is_tpm_available,
    load_private_key_securely,
    store_private_key_securely,
)

DEFAULT_SERVER_URL = "http://127.0.0.1:5000"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


def ensure_identity(algorithm: str = "ecc"):
    """Load existing secure private key or create a new one."""
    try:
        private_key = load_private_key_securely()
        logging.info("Loaded existing device private key from secure storage")
        return private_key
    except FileNotFoundError:
        logging.info("No existing key found. Generating new %s keypair", algorithm.upper())

    private_key, _ = generate_keypair(algorithm=algorithm)
    store_private_key_securely(private_key)
    logging.info("Private key created and stored securely")
    return private_key


def register_device(server_url: str, device_id: str, algorithm: str = "ecc") -> bool:
    """Register the device public key with the authentication server."""
    private_key = ensure_identity(algorithm=algorithm)
    public_key = export_public_key_pem(private_key)

    payload = {
        "device_id": device_id,
        "public_key": public_key,
    }

    response = requests.post(
        f"{server_url.rstrip('/')}/register",
        json=payload,
        timeout=10,
    )

    if response.status_code != 200:
        logging.error("Registration failed [%s]: %s", response.status_code, response.text)
        return False

    logging.info("Registration successful for device '%s'", device_id)
    return True


def authenticate_device(server_url: str, device_id: str) -> bool:
    """Authenticate the device by signing a server-provided challenge."""
    private_key = load_private_key_securely()

    challenge_response = requests.post(
        f"{server_url.rstrip('/')}/challenge",
        json={"device_id": device_id},
        timeout=10,
    )

    if challenge_response.status_code != 200:
        logging.error(
            "Challenge request failed [%s]: %s",
            challenge_response.status_code,
            challenge_response.text,
        )
        return False

    challenge_data = challenge_response.json()
    nonce = challenge_data.get("nonce")

    if not isinstance(nonce, str):
        logging.error("Invalid nonce from server")
        return False

    signature = sign_nonce(private_key, nonce)

    auth_payload = {
        "device_id": device_id,
        "nonce": nonce,
        "signature": signature,
        "timestamp": int(time.time()),
    }

    auth_response = requests.post(
        f"{server_url.rstrip('/')}/authenticate",
        json=auth_payload,
        timeout=10,
    )

    if auth_response.status_code != 200:
        logging.error(
            "Authentication failed [%s]: %s",
            auth_response.status_code,
            auth_response.text,
        )
        return False

    logging.info("Authentication successful for device '%s'", device_id)
    return True


def main() -> int:
    """CLI entry point for register/authenticate operations."""
    parser = argparse.ArgumentParser(
        description="Secure IoT Device Authentication Client"
    )
    parser.add_argument("command", choices=["register", "authenticate"])
    parser.add_argument("--device-id", required=True, help="Unique device identifier")
    parser.add_argument(
        "--server-url",
        default=DEFAULT_SERVER_URL,
        help="Server base URL, e.g. http://127.0.0.1:5000",
    )
    parser.add_argument(
        "--algorithm",
        default="ecc",
        choices=["ecc", "rsa"],
        help="Key algorithm used when creating a new identity",
    )

    args = parser.parse_args()

    if is_tpm_available():
        logging.info("TPM tools detected on host")
    else:
        logging.info("TPM unavailable. Using simulated secure storage")

    try:
        if args.command == "register":
            success = register_device(args.server_url, args.device_id, args.algorithm)
        else:
            success = authenticate_device(args.server_url, args.device_id)
    except Exception as exc:
        logging.error("Device operation failed: %s", exc)
        return 1

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
