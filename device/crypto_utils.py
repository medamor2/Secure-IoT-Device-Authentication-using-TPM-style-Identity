"""Cryptographic helpers for IoT device identity and signatures."""

from __future__ import annotations

import base64
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


def generate_ecc_keypair() -> Tuple[ec.EllipticCurvePrivateKey, str]:
    """Generate an ECC SECP256R1 keypair and return private key plus PEM public key."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_key, public_pem


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, str]:
    """Generate an RSA keypair and return private key plus PEM public key."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return private_key, public_pem


def sign_nonce(private_key, nonce: str) -> str:
    """Sign a server nonce with SHA-256 and return base64 signature."""
    payload = nonce.encode("utf-8")

    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    elif isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    else:
        raise TypeError("Unsupported private key type")

    return base64.b64encode(signature).decode("utf-8")


def private_key_to_pem(private_key) -> bytes:
    """Serialize a private key to PKCS8 PEM (unencrypted)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def private_key_from_pem(private_key_pem: bytes):
    """Deserialize a PEM private key into a cryptography key object."""
    return serialization.load_pem_private_key(private_key_pem, password=None)
