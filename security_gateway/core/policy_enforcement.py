"""Zero Trust Policy Enforcement Point (PEP) for HNX26EPS01 Security Gateway.

Orchestrates the authoritative policy decision pipeline:
1. TLS Validation
2. Client Identity
3. Token Validation & Binding
4. Session Lookup & Revalidation
5. Continuous Security Posture Assessment
6. Resource & Action Identification
7. RBAC + ABAC Policy Evaluation (PDP)
8. Request Risk Evaluation
9. Upstream Workload Identity Audit
10. Deep Packet Inspection (DPI)
11. Final Enforcement (ALLOW / DENY / STEP_UP)
12. Audit Decision Record Logging
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from core.client_registry import ClientRegistration, ClientRegistry
from core.identity import AuthenticatedPrincipal, AuthenticationStrength
from core.risk_engine import RiskAssessment, RiskEngine
from core.security_context import PostureState, RequestContext, SecurityPosture
from core.session_manager import SessionManager, SessionRecord
from core.workload_identity import WorkloadIdentityValidator
from core.zero_trust_policy import PolicyDecision, ZeroTrustPolicyEngine
from dpi_engine import DPIDecision, DPIEngine
from security_logger import get_security_logger
from token_vault import TokenClaims, TokenSecurityError, TokenVault


@dataclass(frozen=True)
class EnforcementResult:
    """Outcome of PEP evaluation."""

    decision: str  # "ALLOW", "DENY", "STEP_UP"
    status_code: int
    reason_code: str
    principal: Optional[AuthenticatedPrincipal]
    session: Optional[SessionRecord]
    risk_assessment: RiskAssessment
    policy_decision: PolicyDecision
    dpi_decision: Optional[DPIDecision]
    error_message: Optional[str] = None

    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"


class PolicyEnforcementPoint:
    """Central PEP coordinating identity, session, risk, and policy enforcement."""

    def __init__(
        self,
        pdp: ZeroTrustPolicyEngine,
        client_registry: ClientRegistry,
        token_vault: TokenVault,
        session_manager: SessionManager,
        risk_engine: RiskEngine,
        workload_validator: WorkloadIdentityValidator,
        dpi_engine: DPIEngine,
        posture: SecurityPosture,
    ):
        self.pdp = pdp
        self.client_registry = client_registry
        self.token_vault = token_vault
        self.session_manager = session_manager
        self.risk_engine = risk_engine
        self.workload_validator = workload_validator
        self.dpi_engine = dpi_engine
        self.posture = posture
        self.logger = get_security_logger()

    def determine_action_from_method(self, method: str, resource: str) -> str:
        """Maps HTTP method and URI context to abstract action."""
        m = method.upper()
        if resource.startswith("/security/") or resource.startswith("/admin/"):
            return "ADMIN"
        if "review" in resource:
            return "REVIEW"
        if "query" in resource or "search" in resource:
            return "QUERY"
        if m in ("GET", "HEAD"):
            return "READ"
        if m in ("POST", "PUT", "PATCH"):
            return "WRITE"
        return "ANY"

    def enforce_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        query_params: Dict[str, List[str]],
        body_bytes: bytes,
        client_cert_info: Dict[str, Any],
        client_ip: str = "127.0.0.1",
        upstream_host: str = "127.0.0.1",
        upstream_port: int = 3000,
    ) -> EnforcementResult:
        """Executes the complete 11-step Zero Trust Policy Decision Pipeline."""
        request_id = str(uuid.uuid4())
        action = self.determine_action_from_method(method, path)
        cert_fp = client_cert_info.get("fingerprint", "")
        current_posture = self.posture.compute_overall_posture()

        # Step 1 & 2: Client & Device Identity Verification
        client_reg = self.client_registry.lookup(cert_fp) if cert_fp else None
        is_known_client = client_reg is not None

        # Step 3: Token Validation & Cryptographic Binding
        auth_header = headers.get("authorization", "")
        token_claims: Optional[TokenClaims] = None
        auth_error: Optional[str] = None

        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()
            try:
                token_claims = self.token_vault.verify_token(raw_token, enforce_replay_check=True)
            except TokenSecurityError as e:
                auth_error = str(e)
        else:
            auth_error = "MISSING_BEARER_TOKEN"

        principal: Optional[AuthenticatedPrincipal] = None
        cert_binding_match = False

        if token_claims and client_reg:
            # Check token-certificate binding
            token_bound_fp = getattr(token_claims, "bound_cert_fingerprint", None)
            if token_bound_fp:
                cert_binding_match = token_bound_fp.upper() == cert_fp.upper()
            else:
                # If token was generated without explicit bound fingerprint, match via registry
                cert_binding_match = True

            strength = (
                AuthenticationStrength.ELEVATED_ADMIN
                if token_claims.role == "ROLE_ADMIN"
                else AuthenticationStrength.MTLS_PLUS_TOKEN
            )
            effective_scopes = list(token_claims.scopes) if token_claims.scopes else []
            if not effective_scopes:
                if token_claims.role == "ROLE_LEGAL_QUERY":
                    effective_scopes = ["legal.query", "legal.search", "document.read"]
                elif token_claims.role == "ROLE_LEGAL_REVIEW":
                    effective_scopes = ["legal.query", "legal.search", "document.read", "case.review"]
                elif token_claims.role == "ROLE_ADMIN":
                    effective_scopes = ["security.status", "security.audit"]
            if client_reg and client_reg.allowed_scopes:
                effective_scopes = [s for s in effective_scopes if s in client_reg.allowed_scopes]

            principal = AuthenticatedPrincipal(
                principal_id=token_claims.subject,
                role=token_claims.role,
                client_certificate_id=client_reg.client_id,
                certificate_fingerprint=cert_fp,
                token_id=token_claims.token_id,
                token_issued_at=token_claims.issued_at,
                token_expiry=token_claims.expiry,
                scopes=effective_scopes,
                auth_strength=strength,
                step_up_verified=(token_claims.role == "ROLE_ADMIN"),
            )

        # Step 4: Session Lookup & Revalidation
        session: Optional[SessionRecord] = None
        if principal:
            # Look up or create continuous session
            session_id = headers.get("x-hnx-session-id")
            if session_id:
                valid_sess, sess_reason, session = self.session_manager.validate_and_touch_session(
                    session_id=session_id,
                    presented_certificate_fp=cert_fp,
                    current_posture=current_posture,
                )
                if not valid_sess:
                    auth_error = f"SESSION_INVALID: {sess_reason}"
                    principal = None
            else:
                session = self.session_manager.create_session(principal)

        # Step 5: Risk Evaluation
        risk = self.risk_engine.assess_request(
            source_ip=client_ip,
            is_authenticated=(principal is not None),
            is_known_client=is_known_client,
            cert_binding_match=cert_binding_match,
            dpi_action="ALLOW",  # Pre-DPI estimate
            posture=current_posture,
            body_length=len(body_bytes),
            auth_error=auth_error,
        )

        # Step 6: Construct RequestContext
        req_ctx = RequestContext(
            request_id=request_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            principal=principal,
            resource=path,
            action=action,
            http_method=method,
            source_ip=client_ip,
            body_length=len(body_bytes),
            content_type=headers.get("content-type"),
            risk_score=risk.score,
            posture=current_posture,
            policy_version=self.pdp.policy_version,
        )

        # Step 7: Workload Identity Audit
        is_upstream_valid, workload_reason, _ = self.workload_validator.verify_upstream_workload(
            host=upstream_host, port=upstream_port
        )

        # Step 8: PDP Policy Decision Evaluation
        policy_decision = self.pdp.evaluate(
            ctx=req_ctx,
            client_reg=client_reg,
            is_upstream_valid=is_upstream_valid,
        )

        if not policy_decision.is_allowed():
            primary_reason = policy_decision.reason_codes[0] if policy_decision.reason_codes else "POLICY_DENY"
            status_code = 401 if "IDENTITY_UNKNOWN" in primary_reason or "TOKEN" in primary_reason else 403
            if policy_decision.decision == "STEP_UP":
                status_code = 401

            # Log decision record
            self.logger.log_event(
                event="ZERO_TRUST_DENIED",
                severity="HIGH" if status_code == 403 else "WARNING",
                action="DENY",
                source_ip=client_ip,
                client_id=principal.principal_id if principal else "anonymous",
                details=req_ctx.to_decision_record(policy_decision.decision, policy_decision.reason_codes),
            )

            return EnforcementResult(
                decision=policy_decision.decision,
                status_code=status_code,
                reason_code=primary_reason,
                principal=principal,
                session=session,
                risk_assessment=risk,
                policy_decision=policy_decision,
                dpi_decision=None,
                error_message=f"Access Denied by Zero Trust Policy: {primary_reason}",
            )

        # Step 9: Deep Packet Inspection (DPI)
        dpi_decision = self.dpi_engine.inspect_request(
            method=method,
            path=path,
            headers=headers,
            query_params=query_params,
            body_bytes=body_bytes,
            content_type=headers.get("content-type"),
        )

        if dpi_decision.action == "BLOCK":
            # Re-assess risk with DPI block
            self.risk_engine.assess_request(
                source_ip=client_ip,
                is_authenticated=True,
                is_known_client=True,
                cert_binding_match=True,
                dpi_action="BLOCK",
                posture=current_posture,
                body_length=len(body_bytes),
            )
            self.logger.log_event(
                event="DPI_PAYLOAD_BLOCKED",
                severity="HIGH",
                action="BLOCK",
                source_ip=client_ip,
                client_id=principal.principal_id if principal else "unknown",
                details={"reason": dpi_decision.reason_code, "dpi_details": dpi_decision.details},
            )
            return EnforcementResult(
                decision="DENY",
                status_code=400,
                reason_code=dpi_decision.reason_code,
                principal=principal,
                session=session,
                risk_assessment=risk,
                policy_decision=policy_decision,
                dpi_decision=dpi_decision,
                error_message=f"Request Blocked by Security Gateway: {dpi_decision.reason_code}",
            )

        # Step 10 & 11: Final Allow
        self.logger.log_event(
            event="ZERO_TRUST_AUTHORIZED",
            severity="INFO",
            action="ALLOW",
            source_ip=client_ip,
            client_id=principal.principal_id if principal else "unknown",
            details=req_ctx.to_decision_record("ALLOW", ["POLICY_MATCH_ALLOWED", "DPI_PASS"]),
        )

        return EnforcementResult(
            decision="ALLOW",
            status_code=200,
            reason_code="ALLOW",
            principal=principal,
            session=session,
            risk_assessment=risk,
            policy_decision=policy_decision,
            dpi_decision=dpi_decision,
        )
