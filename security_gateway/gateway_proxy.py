"""Enterprise Host Security Gateway Reverse Proxy for HNX26EPS01 Legal Assistant.

Implements the multi-layer defensive perimeter:
- TLS 1.3 Termination & Mandatory mTLS Client Verification
- Memory-dump Hardening (PR_SET_DUMPABLE=0, RLIMIT_CORE=0)
- Per-Source Token Bucket Rate Limiting (Anti-DoS)
- Connection Concurrency & Deadline Controls
- HMAC-SHA256 Token Authentication & Replay Cache
- Strict RBAC Enforcement Before Upstream Forwarding
- Deep Packet Inspection (DPI) & Anti-SQLi False-Positive Control
- Request Smuggling & Parser Differential Defense
- Isolated Forwarding Exclusively to 127.0.0.1:3000
- Fail-Closed Security State Machine (STARTING, READY, LOCKDOWN)
"""

from __future__ import annotations

import asyncio
import json
import ssl
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure gateway package root is in sys.path
_GATEWAY_DIR = Path(__file__).parent.resolve()
if str(_GATEWAY_DIR) not in sys.path:
    sys.path.insert(0, str(_GATEWAY_DIR))

from config_loader import ConfigLoader, GatewayConfig
from core.client_registry import ClientRegistry
from core.policy_enforcement import PolicyEnforcementPoint
from core.risk_engine import RiskEngine
from core.security_context import SecurityPosture
from core.session_manager import SessionManager
from core.workload_identity import WorkloadIdentityValidator
from core.zero_trust_policy import ZeroTrustPolicyEngine
from dpi_engine import DPIEngine
from incident_response import IncidentResponseManager, SecurityState
from memory_protection import harden_process_memory
from rbac_engine import RBACAccessDeniedError, RBACEngine
from security_logger import SecurityLogger, get_security_logger
from tls_manager import TLSManager, TLSSecurityError
from token_vault import TokenSecurityError, TokenVault
from upstream_connector import RequestSmugglingError, UpstreamConnectionError, UpstreamConnector



class TokenBucketRateLimiter:
    """In-memory thread-safe token bucket rate limiter per client IP."""

    def __init__(self, rate: float = 20.0, burst: int = 40):
        self.rate = rate
        self.burst = burst
        self.buckets: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_update)
        self.total_accepted = 0
        self.total_throttled = 0

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        tokens, last_update = self.buckets.get(key, (float(self.burst), now))
        # Refill tokens
        elapsed = now - last_update
        tokens = min(float(self.burst), tokens + elapsed * self.rate)

        if tokens >= 1.0:
            self.buckets[key] = (tokens - 1.0, now)
            self.total_accepted += 1
            return True
        else:
            self.buckets[key] = (tokens, now)
            self.total_throttled += 1
            return False


class GatewayProxy:
    """Async reverse proxy server enforcing host defensive perimeter."""

    def __init__(self, config: GatewayConfig):
        self.config = config
        self.logger = get_security_logger(self.config.security.log_file)
        self.incident_manager = IncidentResponseManager(
            state_dir=str(self.config.security.log_file).replace("security.log", "")
        )

        # Apply host memory hardening
        self.memory_hardened = harden_process_memory()

        # Initialize cryptographic subsystems
        self.tls_manager = TLSManager(
            server_cert_path=self.config.tls.server_cert_path,
            server_key_path=self.config.tls.server_key_path,
            ca_cert_path=self.config.tls.ca_cert_path,
            require_client_cert=self.config.tls.require_client_certificate,
            pinned_fingerprints=self.config.tls.pinned_fingerprints,
            pinned_spki_hashes=self.config.tls.pinned_spki_hashes,
        )

        self.token_vault = TokenVault(
            key_path=self.config.auth.token_secret_path,
            replay_cache_ttl_seconds=self.config.auth.token_ttl_seconds,
        )

        self.rbac_engine = RBACEngine(self.config.security.rbac_config_path)

        self.dpi_engine = DPIEngine(
            max_body_bytes=self.config.limits.max_body_bytes,
            max_uri_length=self.config.limits.max_uri_length,
            max_header_length=self.config.limits.max_header_bytes,
            max_header_count=self.config.limits.max_header_count,
            max_json_depth=self.config.limits.max_json_depth,
        )

        self.upstream_connector = UpstreamConnector(self.config.upstream)

        self.rate_limiter = TokenBucketRateLimiter(
            rate=self.config.rate_limit.requests_per_second,
            burst=self.config.rate_limit.burst,
        )

        # Zero Trust Core Subsystems Initialization
        from pathlib import Path
        zt_policy_p = Path(self.config.security.rbac_config_path).parent / "zero_trust_policy.yaml"
        if not zt_policy_p.exists():
            zt_policy_p = Path("security_gateway/config/zero_trust_policy.yaml")

        self.client_registry = ClientRegistry(config_path=str(zt_policy_p))
        self.pdp = ZeroTrustPolicyEngine(config_path=str(zt_policy_p))
        self.session_manager = SessionManager(default_ttl_seconds=self.config.auth.token_ttl_seconds)
        self.risk_engine = RiskEngine()
        self.workload_validator = WorkloadIdentityValidator()
        self.security_posture = SecurityPosture(gateway_state=self.incident_manager.current_state.value)

        self.pep = PolicyEnforcementPoint(
            pdp=self.pdp,
            client_registry=self.client_registry,
            token_vault=self.token_vault,
            session_manager=self.session_manager,
            risk_engine=self.risk_engine,
            workload_validator=self.workload_validator,
            dpi_engine=self.dpi_engine,
            posture=self.security_posture,
        )

        self.active_connections = 0
        self.server: Optional[asyncio.Server] = None
        self._is_running = False

        # Transition state machine to READY if not in LOCKDOWN
        if self.incident_manager.current_state != SecurityState.LOCKDOWN:
            self.incident_manager.set_state(SecurityState.READY)

    async def start(self) -> None:
        """Starts the secure TLS 1.3 listener."""
        self._is_running = True
        self.server = await asyncio.start_server(
            self.handle_connection,
            host=self.config.listener.host,
            port=self.config.listener.port,
            ssl=self.tls_manager.ssl_context,
            backlog=128,
        )
        self.logger.log_event(
            event="GATEWAY_LISTENER_STARTED",
            severity="INFO",
            action="ALLOW",
            details={
                "host": self.config.listener.host,
                "port": self.config.listener.port,
                "tls_version": "TLSv1.3",
                "mTLS": self.config.tls.require_client_certificate,
                "memory_hardened": self.memory_hardened,
            },
        )

    async def stop(self) -> None:
        """Gracefully shuts down the gateway listener and connections."""
        self._is_running = False
        self.incident_manager.set_state(SecurityState.SHUTDOWN)
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        await self.upstream_connector.close()
        self.token_vault.close()
        self.logger.log_event(
            event="GATEWAY_LISTENER_STOPPED",
            severity="INFO",
            action="SHUTDOWN",
            details={},
        )

    async def handle_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Processes an incoming TLS client connection with strict limits."""
        peername = writer.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"

        # Concurrency limit
        if self.active_connections >= self.config.limits.max_connections:
            self.logger.log_event(
                event="CONCURRENCY_LIMIT_EXCEEDED",
                severity="WARNING",
                action="BLOCK",
                source_ip=client_ip,
                details={"max": self.config.limits.max_connections},
            )
            await self._send_quick_response(writer, 503, "Service Unavailable: Max Connections Reached")
            return

        self.active_connections += 1
        try:
            # Enforce overall connection timeout deadline
            await asyncio.wait_for(
                self._process_http_stream(reader, writer, client_ip),
                timeout=self.config.limits.request_timeout_seconds,
            )
        except asyncio.TimeoutError:
            self.logger.log_event(
                event="CONNECTION_TIMEOUT_EXCEEDED",
                severity="WARNING",
                action="DROP",
                source_ip=client_ip,
                details={"timeout": self.config.limits.request_timeout_seconds},
            )
        except Exception as e:
            self.logger.log_event(
                event="CONNECTION_ERROR",
                severity="WARNING",
                action="DROP",
                source_ip=client_ip,
                details={"error": str(e)},
            )
        finally:
            self.active_connections = max(0, self.active_connections - 1)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_quick_response(
        self, writer: asyncio.StreamWriter, status_code: int, message: str, headers: Optional[Dict[str, str]] = None
    ) -> None:
        reason_phrases = {
            200: "OK",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            429: "Too Many Requests",
            500: "Internal Server Error",
            503: "Service Unavailable",
        }
        reason = reason_phrases.get(status_code, "Security Response")
        body = json.dumps({"error": message, "status": status_code}).encode("utf-8")

        resp_headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "Connection": "close",
            "X-Content-Type-Options": "nosniff",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
        if headers:
            resp_headers.update(headers)

        header_lines = [f"HTTP/1.1 {status_code} {reason}"]
        for k, v in resp_headers.items():
            header_lines.append(f"{k}: {v}")
        header_lines.append("\r\n")

        raw_resp = "\r\n".join(header_lines).encode("latin1") + body
        try:
            writer.write(raw_resp)
            await writer.drain()
        except Exception:
            pass

    async def _process_http_stream(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, client_ip: str
    ) -> None:
        """Validates mTLS identity, parses HTTP/1.1 framing, applies RBAC/DPI, forwards."""
        # 1. Verify Fail-Closed State Machine
        if not self.incident_manager.can_forward_requests():
            current_state = self.incident_manager.current_state.value
            await self._send_quick_response(
                writer, 503, f"Gateway Inactive: Current Security State is {current_state}"
            )
            return

        # 2. Extract and Validate Client Certificate (mTLS Application Check)
        client_cert_info: Dict[str, Any] = {}
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj and self.config.tls.require_client_certificate:
            try:
                cert_der = ssl_obj.getpeercert(binary_form=True)
                if not cert_der:
                    raise TLSSecurityError("Client certificate missing on mandatory mTLS session")
                client_cert_info = self.tls_manager.verify_client_der_certificate(cert_der)
            except Exception as e:
                self.logger.log_event(
                    event="MTLS_VALIDATION_FAILED",
                    severity="HIGH",
                    action="BLOCK",
                    source_ip=client_ip,
                    details={"error": str(e)},
                )
                await self._send_quick_response(writer, 401, f"mTLS Authentication Failed: {e}")
                return

        client_id = client_cert_info.get("subject", "anonymous")

        # 3. Application-Layer Token Bucket Rate Limiting
        rate_key = client_ip if self.config.rate_limit.per_client else "global"
        if not self.rate_limiter.allow(rate_key):
            self.logger.log_event(
                event="RATE_LIMIT_EXCEEDED",
                severity="WARNING",
                action="BLOCK",
                source_ip=client_ip,
                client_id=client_id,
                details={"rate": self.config.rate_limit.requests_per_second},
            )
            await self._send_quick_response(
                writer, 429, "Too Many Requests: Rate limit exceeded", {"Retry-After": "1"}
            )
            return

        # 4. Parse HTTP Request Line (with strict length limits)
        try:
            line_bytes = await reader.readline()
        except Exception:
            return

        if not line_bytes:
            return

        if len(line_bytes) > self.config.limits.max_uri_length:
            await self._send_quick_response(writer, 414, "URI Too Long")
            return

        request_line = line_bytes.decode("latin1", errors="replace").strip()
        parts = request_line.split(" ")
        if len(parts) != 3:
            await self._send_quick_response(writer, 400, "Malformed HTTP Request Line")
            return

        method, raw_path, http_version = parts
        if http_version not in ("HTTP/1.1", "HTTP/1.0"):
            await self._send_quick_response(writer, 505, "HTTP Version Not Supported")
            return

        # 5. Parse HTTP Headers
        raw_headers: List[Tuple[str, str]] = []
        total_header_bytes = len(line_bytes)
        while True:
            header_line_bytes = await reader.readline()
            if not header_line_bytes or header_line_bytes in (b"\r\n", b"\n"):
                break

            total_header_bytes += len(header_line_bytes)
            if total_header_bytes > self.config.limits.max_header_bytes:
                await self._send_quick_response(writer, 431, "Request Header Fields Too Large")
                return

            if len(raw_headers) >= self.config.limits.max_header_count:
                await self._send_quick_response(writer, 431, "Too Many Request Headers")
                return

            decoded_line = header_line_bytes.decode("latin1", errors="replace").strip()
            if ":" not in decoded_line:
                await self._send_quick_response(writer, 400, "Malformed Header Syntax")
                return

            h_key, h_val = decoded_line.split(":", 1)
            raw_headers.append((h_key.strip(), h_val.strip()))

        header_dict: Dict[str, str] = {k.lower(): v for k, v in raw_headers}

        # 6. Read Request Body (if Content-Length specified)
        body = b""
        content_length_str = header_dict.get("content-length")
        if content_length_str:
            try:
                content_length = int(content_length_str)
                if content_length < 0 or content_length > self.config.limits.max_body_bytes:
                    await self._send_quick_response(writer, 413, "Payload Too Large")
                    return
                body = await reader.readexactly(content_length)
            except (ValueError, asyncio.IncompleteReadError):
                await self._send_quick_response(writer, 400, "Incomplete or Invalid Request Body")
                return

        # 7. Local Diagnostic/Observability Endpoints (/security/status, /security/health)
        clean_url = urllib.parse.urlsplit(raw_path)
        path_only = clean_url.path

        if path_only in ("/security/status", "/security/health"):
            # Check admin authentication or local loopback status
            auth_header = header_dict.get("authorization", "")
            is_admin = False
            token_sub = "local-monitor"
            if auth_header.startswith("Bearer "):
                try:
                    token_str = auth_header[7:].strip()
                    claims = self.token_vault.verify_token(token_str)
                    if claims.role == "ROLE_ADMIN":
                        is_admin = True
                        token_sub = claims.subject
                except Exception:
                    pass

            if not is_admin and client_ip != "127.0.0.1":
                await self._send_quick_response(writer, 403, "Forbidden: Security status requires ROLE_ADMIN")
                return

            status_payload = {
                "gateway_state": self.incident_manager.current_state.value,
                "tls_version": "TLSv1.3",
                "mtls_active": self.config.tls.require_client_certificate,
                "memory_hardened": self.memory_hardened,
                "security_posture": self.security_posture.compute_overall_posture().value,
                "policy_version": self.pdp.policy_version,
                "policy_hash": self.pdp.policy_hash,
                "active_sessions": self.session_manager.active_session_count(),
                "known_clients": len(self.client_registry.list_clients()),
                "upstream": f"{self.config.upstream.host}:{self.config.upstream.port}",
                "active_connections": self.active_connections,
                "rate_limiter": {
                    "accepted": self.rate_limiter.total_accepted,
                    "throttled": self.rate_limiter.total_throttled,
                },
                "client_authenticated": client_id,
                "timestamp": int(time.time()),
            }
            body_resp = json.dumps(status_payload).encode("utf-8")
            resp_headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body_resp)),
                "Connection": "close",
            }
            raw_resp = (
                f"HTTP/1.1 200 OK\r\n"
                + "\r\n".join(f"{k}: {v}" for k, v in resp_headers.items())
                + "\r\n\r\n"
            ).encode("latin1") + body_resp
            writer.write(raw_resp)
            await writer.drain()
            return

        # 8. Zero Trust Policy Enforcement Point (PEP) Evaluation
        query_params = urllib.parse.parse_qs(clean_url.query)
        self.security_posture.gateway_state = self.incident_manager.current_state.value

        enforcement_result = self.pep.enforce_request(
            method=method,
            path=raw_path,
            headers=header_dict,
            query_params=query_params,
            body_bytes=body,
            client_cert_info=client_cert_info,
            client_ip=client_ip,
            upstream_host=self.config.upstream.host,
            upstream_port=self.config.upstream.port,
        )

        if not enforcement_result.is_allowed():
            await self._send_quick_response(
                writer,
                enforcement_result.status_code,
                enforcement_result.error_message or f"Access Denied: {enforcement_result.reason_code}",
            )
            return

        principal = enforcement_result.principal
        sub_name = principal.principal_id if principal else "anonymous"
        sub_role = principal.role if principal else "ROLE_ANONYMOUS"

        # 9. Upstream Forwarding (Strictly to 127.0.0.1:3000)
        try:
            status_code, resp_headers, resp_body = await self.upstream_connector.forward(
                method=method,
                path=raw_path,
                raw_headers=raw_headers,
                body=body,
                client_subject=sub_name,
                client_role=sub_role,
                client_ip=client_ip,
            )
        except RequestSmugglingError as e:
            self.logger.log_event(
                event="REQUEST_SMUGGLING_REJECTED",
                severity="HIGH",
                action="BLOCK",
                source_ip=client_ip,
                client_id=sub_name,
                details={"error": str(e)},
            )
            await self._send_quick_response(writer, 400, f"Bad Request: Ambiguous Framing ({e})")
            return
        except UpstreamConnectionError as e:
            self.logger.log_event(
                event="UPSTREAM_UNAVAILABLE",
                severity="HIGH",
                action="BLOCK",
                source_ip=client_ip,
                client_id=sub_name,
                details={"error": str(e)},
            )
            await self._send_quick_response(writer, 503, "Protected Service Unavailable")
            return

        # 12. Return Upstream Response to Client
        resp_headers["Connection"] = "close"
        resp_headers["Content-Length"] = str(len(resp_body))
        resp_headers["X-Content-Type-Options"] = "nosniff"

        header_lines = [f"HTTP/1.1 {status_code} OK"]
        for k, v in resp_headers.items():
            header_lines.append(f"{k}: {v}")
        header_lines.append("\r\n")

        raw_resp = "\r\n".join(header_lines).encode("latin1") + resp_body
        writer.write(raw_resp)
        await writer.drain()
