"""Enterprise Cryptographic Token Vault for HNX26EPS01 Security Gateway.

Implements HMAC-SHA256 authenticated session tokens with:
- Non-tamperable bounded claims (subject, role, issued_at, expiry, token_id, scope)
- Constant-time signature verification (timing-attack defense)
- Monotonic replay cache (prevents token replay within validity window)
- Secret key loading from protected filesystem locations (enforces 0600 permissions)
- Key rotation support with active and retired verification keys
- Protection against algorithm confusion and unsigned tokens
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from memory_protection import SecureBuffer


class TokenSecurityError(Exception):
    """Base exception for all token security failures."""


class TokenExpiredError(TokenSecurityError):
    """Raised when token has exceeded expiration timestamp."""


class TokenTamperedError(TokenSecurityError):
    """Raised when signature mismatch or invalid payload structure is detected."""


class TokenReplayError(TokenSecurityError):
    """Raised when a one-time or replayed token ID is reused."""


class TokenBindingMismatchError(TokenSecurityError):
    """Raised when token is presented with a certificate different from its bound certificate."""


class InsecureKeyPermissionsError(TokenSecurityError):
    """Raised when secret key file has overly permissive access bits."""


@dataclass(frozen=True)
class TokenClaims:
    """Immutable representation of verified token claims."""

    token_id: str
    subject: str
    role: str
    scopes: List[str]
    issued_at: int
    expiry: int
    bound_cert_fingerprint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class TokenVault:
    """Manages generation, signing, and verification of bounded session tokens."""

    def __init__(
        self,
        key_path: Optional[str] = None,
        secret_bytes: Optional[bytes] = None,
        replay_cache_ttl_seconds: int = 3600,
    ):
        self._key_buffer: Optional[SecureBuffer] = None
        self._retired_key_buffers: List[SecureBuffer] = []
        self._seen_token_ids: Dict[str, int] = {}  # token_id -> expiry timestamp
        self.replay_cache_ttl = replay_cache_ttl_seconds

        if secret_bytes:
            self._load_from_bytes(secret_bytes)
        elif key_path:
            self.load_key_from_file(key_path)
        else:
            # Generate temporary random key for memory-only testing
            random_key = os.urandom(32)
            self._load_from_bytes(random_key)

    def _load_from_bytes(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise TokenSecurityError("HMAC secret key must be at least 256 bits (32 bytes)")
        self._key_buffer = SecureBuffer(len(secret))
        self._key_buffer.write(secret)

    def load_key_from_file(self, file_path: str) -> None:
        """Loads HMAC key from file with strict permission validation (0600 or 0400)."""
        path = Path(file_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Token secret key file not found at: {path}")

        file_stat = path.stat()
        mode = file_stat.st_mode

        # Reject world-readable or group-readable files
        if bool(mode & (stat.S_IRWXG | stat.S_IRWXO)):
            raise InsecureKeyPermissionsError(
                f"Secret key file {path} has unsafe permissions ({oct(mode)}). "
                f"Must be 0600 (owner read/write only)."
            )

        with open(path, "rb") as f:
            secret = f.read().strip()

        # If base64 encoded, decode it
        try:
            if len(secret) == 44 and secret.endswith(b"="):
                secret = base64.b64decode(secret)
        except Exception:
            pass

        self._load_from_bytes(secret)

    def add_retired_key(self, retired_secret: bytes) -> None:
        """Adds a retired key for seamless rotation verification during grace period."""
        if len(retired_secret) < 32:
            raise TokenSecurityError("Retired HMAC secret key must be at least 32 bytes")
        buf = SecureBuffer(len(retired_secret))
        buf.write(retired_secret)
        self._retired_key_buffers.append(buf)

    def _b64url_encode(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    def _b64url_decode(self, data: str) -> bytes:
        padded = data + "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    def create_token(
        self,
        subject: str,
        role: str,
        scopes: Optional[List[str]] = None,
        ttl_seconds: int = 900,
        bound_cert_fingerprint: Optional[str] = None,
    ) -> str:
        """Create and sign a new bounded session token using HMAC-SHA256."""
        if not self._key_buffer:
            raise TokenSecurityError("Token vault key is not initialized")

        now = int(time.time())
        token_id = str(uuid.uuid4())
        if scopes is None:
            if role == "ROLE_LEGAL_QUERY":
                scopes = ["legal.query", "legal.search", "document.read"]
            elif role == "ROLE_LEGAL_REVIEW":
                scopes = ["legal.query", "legal.search", "document.read", "case.review"]
            elif role == "ROLE_ADMIN":
                scopes = ["security.status", "security.audit"]
            else:
                scopes = []

        claims: Dict[str, Any] = {
            "jti": token_id,
            "sub": subject,
            "role": role,
            "scopes": scopes,
            "iat": now,
            "exp": now + ttl_seconds,
        }

        # RFC 8705 Certificate confirmation binding
        if bound_cert_fingerprint:
            claims["cnf"] = {"sha256": bound_cert_fingerprint.strip().upper()}

        header = {"alg": "HS256", "typ": "HNX-TOKEN"}
        header_bytes = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
        payload_bytes = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")

        encoded_header = self._b64url_encode(header_bytes)
        encoded_payload = self._b64url_encode(payload_bytes)
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")

        secret = self._key_buffer.read()
        sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        encoded_sig = self._b64url_encode(sig)

        return f"{encoded_header}.{encoded_payload}.{encoded_sig}"

    def verify_token(
        self,
        token_str: str,
        enforce_replay_check: bool = False,
        expected_cert_fingerprint: Optional[str] = None,
    ) -> TokenClaims:
        """Verifies token authenticity, expiration, role integrity, binding, and replay status.

        Fails closed on any structural or cryptographic discrepancy.
        """
        if not token_str or not isinstance(token_str, str):
            raise TokenTamperedError("Token is missing or not a string")

        parts = token_str.strip().split(".")
        if len(parts) != 3:
            raise TokenTamperedError("Malformed token structure (must be header.payload.sig)")

        enc_header, enc_payload, enc_sig = parts

        try:
            header_bytes = self._b64url_decode(enc_header)
            header = json.loads(header_bytes.decode("utf-8"))
        except Exception as e:
            raise TokenTamperedError(f"Invalid token header: {e}")

        # Enforce exact algorithm and type to prevent algorithm confusion
        if header.get("alg") != "HS256" or header.get("typ") != "HNX-TOKEN":
            raise TokenTamperedError("Unsupported or rejected token algorithm/type")

        signing_input = f"{enc_header}.{enc_payload}".encode("ascii")

        try:
            expected_sig = self._b64url_decode(enc_sig)
        except Exception:
            raise TokenTamperedError("Invalid signature encoding")

        # Verify signature against primary key and retired keys in constant time
        verified = False
        all_keys = [self._key_buffer.read()] if self._key_buffer else []
        for retired in self._retired_key_buffers:
            all_keys.append(retired.read())

        for key_bytes in all_keys:
            computed = hmac.new(key_bytes, signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(computed, expected_sig):
                verified = True
                break

        if not verified:
            raise TokenTamperedError("Cryptographic signature verification failed")

        # Parse payload
        try:
            payload_bytes = self._b64url_decode(enc_payload)
            payload = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            raise TokenTamperedError(f"Invalid token payload structure: {e}")

        # Check required fields
        required_fields = ["jti", "sub", "role", "iat", "exp"]
        for field in required_fields:
            if field not in payload:
                raise TokenTamperedError(f"Missing required claim: {field}")

        now = int(time.time())
        exp = payload["exp"]
        iat = payload["iat"]

        # Validate timestamps
        if exp < now:
            raise TokenExpiredError(f"Token expired at timestamp {exp} (current time: {now})")
        if iat > now + 300:  # Allow 5 minutes clock skew into future
            raise TokenTamperedError("Token issued in the future")

        token_id = str(payload["jti"])

        # Token-to-Certificate Binding verification
        bound_fp = payload.get("cnf", {}).get("sha256")
        if expected_cert_fingerprint and bound_fp:
            if bound_fp.upper() != expected_cert_fingerprint.strip().upper():
                raise TokenBindingMismatchError(
                    f"Token is bound to certificate {bound_fp} but presented with {expected_cert_fingerprint}"
                )

        # Enforce replay cache check if enabled
        if enforce_replay_check:
            self._purge_expired_tokens(now)
            if token_id in self._seen_token_ids:
                raise TokenReplayError(f"Token replay detected for token ID {token_id}")
            self._seen_token_ids[token_id] = exp

        return TokenClaims(
            token_id=token_id,
            subject=str(payload["sub"]),
            role=str(payload["role"]),
            scopes=list(payload.get("scopes", [])),
            issued_at=int(iat),
            expiry=int(exp),
            bound_cert_fingerprint=bound_fp,
        )

    def _purge_expired_tokens(self, current_time: int) -> None:
        """Evicts expired token IDs from the replay cache."""
        expired = [tid for tid, exp in self._seen_token_ids.items() if exp < current_time]
        for tid in expired:
            del self._seen_token_ids[tid]

    def close(self) -> None:
        """Securely wipes keys from memory."""
        if self._key_buffer:
            self._key_buffer.close()
            self._key_buffer = None
        for buf in self._retired_key_buffers:
            buf.close()
        self._retired_key_buffers.clear()

    def __del__(self) -> None:
        self.close()
