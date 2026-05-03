"""Authentication utility functions for the IoT authentication server."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from pathlib import Path
from typing import Dict, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

DEVICE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


def validate_device_id(device_id: str) -> bool:
    """Validate that a device ID follows a safe, predictable format."""
    if not isinstance(device_id, str):
        return False
    return bool(DEVICE_ID_PATTERN.fullmatch(device_id))


def generate_nonce(size_bytes: int = 32) -> str:
    """Generate a cryptographically secure random nonce as a hex string."""
    return secrets.token_hex(size_bytes)


def current_unix_time() -> int:
    """Return the current UNIX time in seconds."""
    return int(time.time())


def load_registry(registry_path: Path) -> Dict[str, Dict[str, str]]:
    """Load the trusted device registry from disk."""
    if not registry_path.exists():
        return {}

    with registry_path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError("Registry content is not a dictionary")

    return data


def save_registry(registry_path: Path, registry: Dict[str, Dict[str, str]]) -> None:
    """Persist the trusted device registry to disk."""
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    with registry_path.open("w", encoding="utf-8") as file:
        json.dump(registry, file, indent=2)


def parse_public_key(public_key_pem: str):
    """Parse and validate a PEM-encoded public key."""
    if not isinstance(public_key_pem, str) or len(public_key_pem) > 10000:
        raise ValueError("Invalid public key input")

    key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(key, (ec.EllipticCurvePublicKey, rsa.RSAPublicKey)):
        raise ValueError("Unsupported key type")

    return key


def verify_signature(public_key_pem: str, nonce: str, signature_b64: str) -> Tuple[bool, str]:
    """Verify a device signature over a nonce using SHA-256."""
    try:
        public_key = parse_public_key(public_key_pem)
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        return False, f"Invalid key or signature format: {exc}"

    if not isinstance(nonce, str) or len(nonce) < 16 or len(nonce) > 256:
        return False, "Invalid nonce format"

    try:
        payload = nonce.encode("utf-8")
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        else:
            public_key.verify(
                signature,
                payload,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
    except InvalidSignature:
        return False, "Signature verification failed"
    except Exception as exc:
        return False, f"Signature verification error: {exc}"

    return True, "Signature verified"
