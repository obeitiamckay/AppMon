"""Security utilities: Fernet encryption, Argon2 hashing, JWT sessions, Vault, and rate limiting."""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

logger = logging.getLogger(__name__)
_password_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hash a password using Argon2id."""
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against an Argon2 hash."""
    try:
        return _password_hasher.verify(hashed_password, plain_password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


class SecretCipher:
    """Encrypt and decrypt sensitive credentials using Fernet."""

    def __init__(self, fernet_key: Optional[str] = None) -> None:
        key = fernet_key or get_settings().fernet_key
        if not key:
            # Generate an ephemeral key only for dev/test when FERNET_KEY is unset
            key = Fernet.generate_key().decode("utf-8")
            logger.warning("FERNET_KEY not configured; using ephemeral key (not suitable for production).")
        self._fernet = Fernet(key.encode("utf-8") if isinstance(key, str) else key)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext string into a URL-safe token."""
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a Fernet token back to plaintext."""
        if not ciphertext:
            return ""
        try:
            return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise ValueError("Failed to decrypt secret: invalid Fernet token or key") from exc


def get_vault_secret(path: str, key: str = "secret") -> Optional[str]:
    """Optionally retrieve a secret from HashiCorp Vault KV v2."""
    settings = get_settings()
    if not settings.vault_enabled:
        return None
    try:
        import hvac

        client = hvac.Client(url=settings.vault_addr, token=settings.vault_token)
        if not client.is_authenticated():
            logger.error("HashiCorp Vault authentication failed")
            return None
        resp = client.secrets.kv.v2.read_secret_version(
            path=path,
            mount_point=settings.vault_mount_point,
        )
        return resp["data"]["data"].get(key)
    except Exception as exc:
        logger.error("Error reading secret from Vault at %s: %s", path, exc)
        return None


def create_access_token(
    subject: str,
    role: str,
    expires_minutes: Optional[int] = None,
) -> str:
    """Create a signed JWT token for web console sessions."""
    settings = get_settings()
    ttl = expires_minutes if expires_minutes is not None else settings.session_expire_minutes
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=ttl),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    """Decode and validate a JWT session token."""
    settings = get_settings()
    try:
        return jwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


class LoginRateLimiter:
    """In-memory sliding-window rate limiter for login endpoints by client IP."""

    def __init__(self, max_attempts: int = 10, window_seconds: int = 300) -> None:
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, client_ip: str) -> bool:
        """Return True if client IP has not exceeded rate limit."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = [ts for ts in self._attempts.get(client_ip, []) if ts > cutoff]
            self._attempts[client_ip] = timestamps
            return len(timestamps) < self.max_attempts

    def record_attempt(self, client_ip: str) -> None:
        """Record a login attempt for client IP."""
        now = time.monotonic()
        with self._lock:
            self._attempts.setdefault(client_ip, []).append(now)

    def reset(self, client_ip: str) -> None:
        """Clear rate limit history for client IP after successful login."""
        with self._lock:
            self._attempts.pop(client_ip, None)


login_rate_limiter = LoginRateLimiter()
