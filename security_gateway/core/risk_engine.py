"""Deterministic Local Request Risk Engine for HNX26EPS01 Gateway.

Computes explainable, real-time risk scores (0–100) based on local signals:
- Authentication and certificate anomalies
- Payload and parameter framing indicators
- Deep Packet Inspection (DPI) findings
- Host security posture and watchdog alerts
- Historical anomaly frequency per client
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.security_context import PostureState


class RiskLevel(str, Enum):
    LOW = "LOW"            # 0–20: Normal processing
    MEDIUM = "MEDIUM"      # 21–50: Tighter rate limits, strict logging
    HIGH = "HIGH"          # 51–75: Deny sensitive/admin endpoints
    CRITICAL = "CRITICAL"  # 76–100: Immediate block, session revocation


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: RiskLevel
    factors: List[str]
    details: Dict[str, Any] = field(default_factory=dict)


class RiskEngine:
    """Evaluates request risk deterministically without opaque cloud dependencies."""

    def __init__(self):
        # Local per-client anomaly counters for rate/behavior tracking
        self._client_violations: Dict[str, int] = {}

    def assess_request(
        self,
        source_ip: str,
        is_authenticated: bool,
        is_known_client: bool,
        cert_binding_match: bool,
        dpi_action: str,  # "ALLOW", "BLOCK", "REVIEW"
        posture: PostureState,
        body_length: int,
        is_burst: bool = False,
        auth_error: Optional[str] = None,
    ) -> RiskAssessment:
        """Calculates deterministic composite risk score and factors."""
        score = 0
        factors: List[str] = []

        # 1. Identity & Certificate Factors
        if not is_authenticated:
            score += 25
            factors.append("UNAUTHENTICATED_REQUEST (+25)")
        elif not cert_binding_match:
            score += 40
            factors.append("TOKEN_CERTIFICATE_BINDING_MISMATCH (+40)")

        if not is_known_client:
            score += 30
            factors.append("UNKNOWN_CLIENT_DEVICE (+30)")

        if auth_error:
            score += 25
            factors.append(f"AUTH_FAILURE_SIGNAL ({auth_error}) (+25)")

        # 2. DPI & Payload Factors
        if dpi_action == "BLOCK":
            score += 45
            factors.append("DPI_INJECTION_INDICATOR_DETECTED (+45)")
        elif dpi_action == "REVIEW":
            score += 15
            factors.append("DPI_SUSPICIOUS_CONTENT_REVIEW (+15)")

        if body_length > 1024 * 1024:  # > 1MB
            score += 10
            factors.append("OVERSIZED_PAYLOAD (+10)")

        if is_burst:
            score += 15
            factors.append("TRAFFIC_BURST_DETECTED (+15)")

        # 3. Security Posture Factors
        if posture == PostureState.SUSPICIOUS:
            score += 25
            factors.append("HOST_POSTURE_SUSPICIOUS (+25)")
        elif posture in (PostureState.COMPROMISED, PostureState.LOCKDOWN):
            score += 80
            factors.append("HOST_POSTURE_COMPROMISED (+80)")
        elif posture == PostureState.DEGRADED:
            score += 10
            factors.append("HOST_POSTURE_DEGRADED (+10)")

        # Clamp score to [0, 100]
        final_score = max(0, min(100, score))

        if final_score <= 20:
            level = RiskLevel.LOW
        elif final_score <= 50:
            level = RiskLevel.MEDIUM
        elif final_score <= 75:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        # Record tracking
        if final_score >= 50:
            self._client_violations[source_ip] = self._client_violations.get(source_ip, 0) + 1

        return RiskAssessment(
            score=final_score,
            level=level,
            factors=factors,
            details={"source_ip": source_ip, "violations_count": self._client_violations.get(source_ip, 0)},
        )
