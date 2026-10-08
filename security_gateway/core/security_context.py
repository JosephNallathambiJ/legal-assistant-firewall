"""Security Posture and Request Context Engine for HNX26EPS01 Gateway.

Tracks continuous host and network trust signals:
- Gateway operational state (READY, LOCKDOWN, etc.)
- Firewall status
- Watchdog detections
- Cryptographic file integrity status
- Upstream process status
- Resource pressure

Constructs structured RequestContext for each evaluated request.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from core.identity import AuthenticatedPrincipal


class PostureState(str, Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    SUSPICIOUS = "SUSPICIOUS"
    COMPROMISED = "COMPROMISED"
    LOCKDOWN = "LOCKDOWN"


@dataclass
class SecurityPosture:
    """Consolidated real-time trust state of all host defensive subsystems."""

    gateway_state: str = "READY"
    firewall_state: str = "ACTIVE"
    watchdog_state: str = "HEALTHY"
    integrity_state: str = "HEALTHY"
    certificate_state: str = "HEALTHY"
    token_state: str = "HEALTHY"
    upstream_state: str = "HEALTHY"
    resource_state: str = "NORMAL"
    last_updated: float = field(default_factory=time.time)

    def compute_overall_posture(self) -> PostureState:
        """Evaluates subsystem states to determine overall host security posture."""
        # 1. Critical Compromise / Lockdown conditions
        if self.gateway_state in ("LOCKDOWN", "COMPROMISED"):
            return PostureState.LOCKDOWN
        if self.watchdog_state == "CRITICAL":
            return PostureState.LOCKDOWN
        if self.integrity_state == "COMPROMISED":
            return PostureState.COMPROMISED
        if self.upstream_state == "TAMPERED":
            return PostureState.COMPROMISED

        # 2. Suspicious / Elevated Risk conditions
        if self.watchdog_state in ("SUSPICIOUS", "HIGH"):
            return PostureState.SUSPICIOUS
        if self.integrity_state in ("SUSPICIOUS", "HASH_MISMATCH"):
            return PostureState.SUSPICIOUS
        if self.upstream_state in ("DOWN", "UNRESPONSIVE"):
            return PostureState.SUSPICIOUS

        # 3. Degraded conditions (safe for read queries, blocked for admin/sensitive)
        if self.gateway_state == "DEGRADED" or self.resource_state == "PRESSURE":
            return PostureState.DEGRADED

        return PostureState.HEALTHY

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["overall_posture"] = self.compute_overall_posture().value
        return data


@dataclass(frozen=True)
class RequestContext:
    """Immutable context constructed for every inbound request prior to authorization."""

    request_id: str
    timestamp: str
    principal: Optional[AuthenticatedPrincipal]
    resource: str
    action: str  # "READ", "WRITE", "QUERY", "REVIEW", "ADMIN"
    http_method: str
    source_ip: str
    body_length: int
    content_type: Optional[str]
    risk_score: int
    posture: PostureState
    policy_version: str
    details: Dict[str, Any] = field(default_factory=dict)

    def to_decision_record(self, decision: str, reason_codes: List[str]) -> Dict[str, Any]:
        """Creates structured decision record for audit logging."""
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "principal_id": self.principal.principal_id if self.principal else "anonymous",
            "client_id": self.principal.client_certificate_id if self.principal else "unknown",
            "certificate_fingerprint": self.principal.certificate_fingerprint if self.principal else "",
            "role": self.principal.role if self.principal else "ROLE_ANONYMOUS",
            "resource": self.resource,
            "action": self.action,
            "source_ip": self.source_ip,
            "risk_score": self.risk_score,
            "security_posture": self.posture.value,
            "policy_version": self.policy_version,
            "decision": decision,
            "reason_codes": reason_codes,
            "details": self.details,
        }
