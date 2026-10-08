"""Zero Trust Session Security & Continuous Revalidation Manager for HNX26EPS01.

Maintains active session states and enforces continuous revalidation:
- Absolute and idle session timeouts
- Token and certificate binding verification
- Dynamic session revocation upon risk escalation, device disablement, or host lockdown
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.identity import AuthenticatedPrincipal
from core.security_context import PostureState


@dataclass
class SessionRecord:
    session_id: str
    principal_id: str
    certificate_fingerprint: str
    token_id: str
    role: str
    scopes: List[str]
    created_at: float
    last_seen: float
    absolute_expiration: float
    idle_expiration_seconds: float = 300.0  # 5 minutes idle
    risk_score: int = 0
    security_state: str = "ACTIVE"
    is_active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self, current_time: Optional[float] = None) -> Tuple[bool, str]:
        now = current_time or time.time()
        if not self.is_active:
            return True, "SESSION_REVOKED"
        if now > self.absolute_expiration:
            return True, "SESSION_ABSOLUTE_TIMEOUT"
        if (now - self.last_seen) > self.idle_expiration_seconds:
            return True, "SESSION_IDLE_TIMEOUT"
        return False, "SESSION_ACTIVE"

    def touch(self, current_time: Optional[float] = None) -> None:
        self.last_seen = current_time or time.time()


class SessionManager:
    """Thread-safe session state registry enforcing continuous trust revalidation."""

    def __init__(self, default_ttl_seconds: int = 900, idle_timeout_seconds: float = 300.0):
        self.default_ttl = default_ttl_seconds
        self.idle_timeout = idle_timeout_seconds
        self._sessions: Dict[str, SessionRecord] = {}

    def create_session(
        self,
        principal: AuthenticatedPrincipal,
        ttl_seconds: Optional[int] = None,
    ) -> SessionRecord:
        """Initializes a new tracked Zero Trust session for an authenticated principal."""
        now = time.time()
        session_id = str(uuid.uuid4())
        session_ttl = ttl_seconds or min(self.default_ttl, max(60, principal.token_expiry - int(now)))

        rec = SessionRecord(
            session_id=session_id,
            principal_id=principal.principal_id,
            certificate_fingerprint=principal.certificate_fingerprint,
            token_id=principal.token_id,
            role=principal.role,
            scopes=principal.scopes,
            created_at=now,
            last_seen=now,
            absolute_expiration=now + session_ttl,
            idle_expiration_seconds=self.idle_timeout,
            risk_score=0,
            security_state="ACTIVE",
            is_active=True,
        )
        self._sessions[session_id] = rec
        return rec

    def get_session(self, session_id: str) -> Optional[SessionRecord]:
        return self._sessions.get(session_id)

    def validate_and_touch_session(
        self,
        session_id: str,
        presented_certificate_fp: str,
        current_posture: PostureState,
        max_allowed_risk: int = 75,
    ) -> Tuple[bool, str, Optional[SessionRecord]]:
        """Continuously re-evaluates an active session on each request.

        Fails closed if certificates mismatch, risk escalated, or host compromised.
        """
        session = self._sessions.get(session_id)
        if not session:
            return False, "SESSION_NOT_FOUND", None

        # 1. Posture check (emergency termination)
        if current_posture in (PostureState.LOCKDOWN, PostureState.COMPROMISED):
            self.revoke_session(session_id, reason=f"Host entered {current_posture.value}")
            return False, "SESSION_REVOKED_HOST_COMPROMISED", session

        # 2. Expiration check
        expired, reason = session.is_expired()
        if expired:
            self.revoke_session(session_id, reason=reason)
            return False, reason, session

        # 3. Cryptographic Binding check
        if presented_certificate_fp and session.certificate_fingerprint:
            if presented_certificate_fp.upper() != session.certificate_fingerprint.upper():
                self.revoke_session(session_id, reason="Certificate binding mismatch during active session")
                return False, "SESSION_CERTIFICATE_MISMATCH", session

        # 4. Risk threshold check
        if session.risk_score > max_allowed_risk:
            self.revoke_session(session_id, reason=f"Risk score {session.risk_score} exceeded threshold")
            return False, "SESSION_RISK_TOO_HIGH", session

        session.touch()
        return True, "SESSION_VALID", session

    def update_session_risk(self, session_id: str, delta: int) -> int:
        session = self._sessions.get(session_id)
        if session:
            session.risk_score = max(0, min(100, session.risk_score + delta))
            return session.risk_score
        return 0

    def revoke_session(self, session_id: str, reason: str = "Operator revoked") -> bool:
        session = self._sessions.get(session_id)
        if session:
            session.is_active = False
            session.security_state = f"REVOKED: {reason}"
            return True
        return False

    def revoke_all_sessions(self, reason: str = "Emergency system revocation") -> int:
        count = 0
        for s in self._sessions.values():
            if s.is_active:
                s.is_active = False
                s.security_state = f"REVOKED: {reason}"
                count += 1
        return count

    def active_session_count(self) -> int:
        now = time.time()
        return sum(1 for s in self._sessions.values() if s.is_active and not s.is_expired(now)[0])
