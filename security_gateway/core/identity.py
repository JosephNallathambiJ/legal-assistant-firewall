"""Identity-Centric Cryptographic Principal Representation for HNX26EPS01.

Provides immutable representations of cryptographically verified identities.
Prevents client-asserted identity or privilege elevation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class AuthenticationStrength(str, Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    MTLS_ONLY = "MTLS_ONLY"
    TOKEN_ONLY = "TOKEN_ONLY"
    MTLS_PLUS_TOKEN = "MTLS_PLUS_TOKEN"
    ELEVATED_ADMIN = "ELEVATED_ADMIN"


@dataclass(frozen=True)
class AuthenticatedPrincipal:
    """Cryptographically verified principal identity context.

    All fields are derived exclusively from verified TLS certificates and HMAC tokens.
    Client-controlled headers or unverified parameters are strictly forbidden.
    """

    principal_id: str
    role: str
    client_certificate_id: str
    certificate_fingerprint: str
    token_id: str
    token_issued_at: int
    token_expiry: int
    scopes: List[str] = field(default_factory=list)
    auth_strength: AuthenticationStrength = AuthenticationStrength.MTLS_PLUS_TOKEN
    step_up_verified: bool = False
    security_context: Dict[str, Any] = field(default_factory=dict)

    def binds_to_certificate(self, presented_fingerprint: str) -> bool:
        """Verifies if the principal's token is cryptographically bound to the presented certificate."""
        if not self.certificate_fingerprint or not presented_fingerprint:
            return False
        return self.certificate_fingerprint.upper() == presented_fingerprint.upper()

    def has_scope(self, scope: str) -> bool:
        """Checks if principal has been granted a specific bounded scope."""
        return scope in self.scopes

    def to_dict(self) -> Dict[str, Any]:
        """Serializes principal representation without sensitive credential leakage."""
        data = asdict(self)
        data["auth_strength"] = self.auth_strength.value
        return data


@dataclass(frozen=True)
class AnonymousPrincipal(AuthenticatedPrincipal):
    """Fallback representation for unauthenticated requests."""

    def __init__(self, source_ip: str = "unknown"):
        super().__init__(
            principal_id=f"anonymous-{source_ip}",
            role="ROLE_ANONYMOUS",
            client_certificate_id="none",
            certificate_fingerprint="",
            token_id="",
            token_issued_at=0,
            token_expiry=0,
            scopes=[],
            auth_strength=AuthenticationStrength.UNAUTHENTICATED,
            step_up_verified=False,
            security_context={"source_ip": source_ip},
        )
