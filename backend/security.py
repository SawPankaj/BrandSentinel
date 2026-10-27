"""Cryptographic and identity primitives used by the local service."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ROUNDS = 600_000
PASSWORD_MIN_LENGTH = 12


def load_master_key(data_dir: Path, production: bool = False) -> bytes:
    encoded = os.environ.get("BRANDSENTINEL_MASTER_KEY", "")
    if encoded:
        try:
            key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        except Exception as exc:
            raise RuntimeError("BRANDSENTINEL_MASTER_KEY must be URL-safe base64") from exc
        if len(key) != 32:
            raise RuntimeError("BRANDSENTINEL_MASTER_KEY must decode to 32 bytes")
        return key
    if production:
        raise RuntimeError("Set BRANDSENTINEL_MASTER_KEY before starting in production")
    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / "development.key"
    try:
        with key_path.open("xb") as stream:
            stream.write(secrets.token_bytes(32))
    except FileExistsError:
        pass
    key = key_path.read_bytes()
    if len(key) != 32:
        raise RuntimeError("Development key file is invalid")
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key


def derive_workspace_key(master_key: bytes, workspace_id: str) -> bytes:
    return hmac.new(master_key, b"brandsentinel-workspace-v1\0" + workspace_id.encode("utf-8"), hashlib.sha256).digest()


def encrypt_text(master_key: bytes, workspace_id: str, purpose: str, plaintext: str) -> str:
    nonce = secrets.token_bytes(12)
    aad = f"brandsentinel:v1:{workspace_id}:{purpose}".encode("utf-8")
    ciphertext = AESGCM(derive_workspace_key(master_key, workspace_id)).encrypt(nonce, plaintext.encode("utf-8"), aad)
    return "v1." + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii").rstrip("=")


def decrypt_text(master_key: bytes, workspace_id: str, purpose: str, encoded: str) -> str:
    if not encoded.startswith("v1."):
        raise ValueError("Encrypted record has an unsupported format")
    raw = base64.urlsafe_b64decode(encoded[3:] + "=" * (-len(encoded[3:]) % 4))
    if len(raw) < 29:
        raise ValueError("Encrypted record is truncated")
    aad = f"brandsentinel:v1:{workspace_id}:{purpose}".encode("utf-8")
    plaintext = AESGCM(derive_workspace_key(master_key, workspace_id)).decrypt(raw[:12], raw[12:], aad)
    return plaintext.decode("utf-8")


def hash_password(password: str, salt: bytes | None = None) -> str:
    if len(password) < PASSWORD_MIN_LENGTH or len(password) > 1024:
        raise ValueError(f"Password must be between {PASSWORD_MIN_LENGTH} and 1024 characters")
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS, dklen=32)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        scheme, rounds, salt_b64, digest_b64 = encoded.split("$", 3)
        if scheme != "pbkdf2_sha256" or int(rounds) < 300_000 or int(rounds) > 2_000_000:
            return False
        salt = base64.b64decode(salt_b64, validate=True)
        expected = base64.b64decode(digest_b64, validate=True)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(rounds), dklen=len(expected))
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeEncodeError):
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)
