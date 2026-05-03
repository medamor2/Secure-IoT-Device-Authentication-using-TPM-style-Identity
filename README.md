# Secure IoT Device Authentication using TPM-style Identity

Author: Mohamed Moncef Amor  
License: All rights reserved

## Project Overview
This project implements secure IoT device authentication using a cryptographic device identity and challenge-response verification.

Each device has a unique private key used only for signing server-issued nonces. The server stores trusted public keys and verifies signatures to approve or reject authentication attempts.

Private keys are handled in TPM-style secure storage:
- Preferred: real TPM path when `tpm2-tools` are available.
- Implemented fallback: encrypted local secure storage with restricted file permissions.

## Architecture Diagram

```text
+-------------------+                              +------------------------------+
|   IoT Device      |                              | Authentication Server        |
|-------------------|   POST /register             |------------------------------|
| generate keypair  | ---------------------------> | store device public key      |
| secure priv key   |                              | trusted registry (JSON)      |
| sign challenges   |                              +------------------------------+
|                   |
|                   |   POST /challenge (device_id)
|                   | <---------------------------  issue random nonce + TTL
|                   |
|                   |   POST /authenticate
|                   |   (device_id, nonce,
|                   |    signature, timestamp)
|                   | --------------------------->  verify signature + nonce use
|                   |                               + replay protection + logging
+-------------------+                              +------------------------------+
```

## Project Structure

```text
Secure IoT Authentication System/
  device/
    device.py
    crypto_utils.py
    tpm_utils.py
  server/
    server.py
    auth_utils.py
  requirements.txt
  README.md
```

## How Device Authentication Works
1. Device creates an ECC (default SECP256R1) or RSA-2048 keypair.
2. Device stores private key securely (simulated TPM fallback).
3. Device sends its public key to `/register`.
4. For authentication, device requests a challenge from `/challenge`.
5. Server returns a unique random nonce and issue time.
6. Device signs the nonce with its private key and sends signature to `/authenticate`.
7. Server verifies:
- Device exists in trusted registry.
- Nonce matches active challenge.
- Nonce is not expired and not reused.
- Signature is valid for that device public key.
- Optional timestamp skew is acceptable.
8. Server accepts or rejects authentication and logs the result.

## TPM vs Simulated Secure Storage
### TPM path (preferred)
- `tpm2-tools` detection is included via `tpm2_getcap` probing.
- The project interface (`generate_keypair`, `store_private_key_securely`, `load_private_key_securely`) is designed so TPM-backed implementation can be plugged in without changing business logic.

### Simulated secure storage (implemented fallback)
- Private key is serialized in PKCS8 PEM format.
- Key is encrypted at rest using `cryptography.Fernet` symmetric encryption.
- Encryption key and encrypted private key are stored under `device/.secure/`.
- Best-effort restrictive permissions are applied (`700` dir and `600` files).

## Setup Instructions

### 1. Create virtual environment and install dependencies

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### 2. Start server

```bash
cd server
python server.py
```

Server runs by default at `http://127.0.0.1:5000`.

### 3. Register a device
In a new terminal:

```bash
cd device
python device.py register --device-id sensor-node-001 --server-url http://127.0.0.1:5000 --algorithm ecc
```

### 4. Authenticate device

```bash
cd device
python device.py authenticate --device-id sensor-node-001 --server-url http://127.0.0.1:5000
```

## Example Workflow
1. Start the server.
2. Run `register` once for a new device.
3. Run `authenticate` whenever the device needs access.
4. Check server logs in `server/auth.log` for audit trail.

## API Endpoints
- `POST /register`
- Request: `{"device_id": "...", "public_key": "PEM"}`
- Response: registration status

- `POST /challenge`
- Request: `{"device_id": "..."}`
- Response: nonce, issue time, expiration

- `POST /authenticate`
- Request: `{"device_id": "...", "nonce": "...", "signature": "base64", "timestamp": 1710000000}`
- Response: authentication success/failure

## Security Considerations
- Nonce-based challenge-response prevents static credential replay.
- Server enforces one active nonce per device and marks nonce as used.
- Challenge TTL limits validity window.
- Timestamp skew checks reduce delayed replay opportunities.
- Strong cryptography:
- ECC SECP256R1 (default) or RSA-2048
- SHA-256 signatures
- cryptographically secure random nonces
- Input validation on device IDs, keys, nonce, and signatures.
- Authentication attempts logged server-side.

## Limitations
- TPM integration is currently capability-detected, with secure encrypted fallback used by default.
- Trusted registry uses local JSON file, not a hardened database/HSM.
- No mutual TLS between device and server in this baseline implementation.
- In-memory challenge store is reset on server restart.

## Future Improvements
- Full TPM key generation/signing flow using `tpm2-tools` contexts.
- mTLS between devices and server.
- Persistent challenge/session cache (Redis).
- Docker Compose deployment.
- Simple admin dashboard for auth logs.

All rights reserved.
