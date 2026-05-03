"""TPM-style secure identity handling for IoT device private keys.

If tpm2-tools are available and enabled, this module can be extended to use a real TPM.
By default, it securely simulates TPM behavior using encrypted local storage.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization

from crypto_utils import (
    generate_ecc_keypair,
    generate_rsa_keypair,
    private_key_from_pem,
    private_key_to_pem,
)

BASE_DIR = Path(__file__).resolve().parent
SECURE_DIR = BASE_DIR / ".secure"
PRIVATE_KEY_ENC_PATH = SECURE_DIR / "device_private_key.enc"
STORAGE_KEY_PATH = SECURE_DIR / "storage.key"


def is_tpm_available() -> bool:
    """Return True if tpm2-tools seem to be available on this host."""
    tool = shutil.which("tpm2_getcap")
    if not tool:
        return False

    try:
        # Quick capability probe; failure means tools or TPM are not usable.
        subprocess.run(
            [tool, "properties-fixed"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
    except Exception:
        return False

    return True


def _ensure_secure_directory() -> None:
    """Create secure storage directory with restricted permissions when possible."""
    SECURE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(SECURE_DIR, 0o700)
    except Exception:
        # chmod may not fully apply on every Windows setup.
        pass


def _load_or_create_storage_key() -> bytes:
    """Load or create the symmetric key used to encrypt local private key material."""
    _ensure_secure_directory()

    if STORAGE_KEY_PATH.exists():
        key = STORAGE_KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        STORAGE_KEY_PATH.write_bytes(key)

    try:
        os.chmod(STORAGE_KEY_PATH, 0o600)
    except Exception:
        pass

    return key


def generate_keypair(algorithm: str = "ecc") -> Tuple[object, str]:
    """Generate a device keypair for secure identity.

    Supported values:
    - "ecc" (default): SECP256R1
    - "rsa": RSA-2048
    """
    normalized = algorithm.lower().strip()
    if normalized == "ecc":
        return generate_ecc_keypair()
    if normalized == "rsa":
        return generate_rsa_keypair(2048)
    raise ValueError("Unsupported algorithm. Use 'ecc' or 'rsa'.")


def store_private_key_securely(private_key) -> None:
    """Store private key in TPM-style secure storage.

    Current implementation uses encrypted local storage as fallback.
    If TPM tools are available, the same API remains valid while backend can be swapped.
    """
    _ensure_secure_directory()

    key = _load_or_create_storage_key()
    fernet = Fernet(key)

    private_pem = private_key_to_pem(private_key)
    encrypted = fernet.encrypt(private_pem)
    PRIVATE_KEY_ENC_PATH.write_bytes(encrypted)

    try:
        os.chmod(PRIVATE_KEY_ENC_PATH, 0o600)
    except Exception:
        pass


def load_private_key_securely():
    """Load and decrypt the device private key from secure storage."""
    if not PRIVATE_KEY_ENC_PATH.exists():
        raise FileNotFoundError("No secure private key found. Register device first.")

    key = _load_or_create_storage_key()
    fernet = Fernet(key)

    encrypted = PRIVATE_KEY_ENC_PATH.read_bytes()
    private_pem = fernet.decrypt(encrypted)

    return private_key_from_pem(private_pem)


def export_public_key_pem(private_key) -> str:
    """Export corresponding public key in PEM format for server registration."""
    return (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
