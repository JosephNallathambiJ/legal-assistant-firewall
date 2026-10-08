"""Configuration Loader and Security Validator for HNX26EPS01 Security Gateway.

Validates configuration at startup against strict defensive constraints.
Fails closed on any misconfiguration:
- Rejects wildcard/external upstream hosts (prevents SSRF proxying)
- Enforces TLS 1.3 minimum version
- Forbids plaintext listener
- Enforces positive rate limits and timeouts
- Validates certificate and key paths
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


class ConfigurationValidationError(Exception):
    """Raised when configuration violates security baseline policies."""


@dataclass(frozen=True)
class ListenerConfig:
    host: str
    port: int
    allow_external_binding: bool = False


@dataclass(frozen=True)
class UpstreamConfig:
    host: str
    port: int
    unix_socket_path: Optional[str] = None
    timeout_seconds: float = 15.0
    max_response_bytes: int = 10485760


@dataclass(frozen=True)
class TLSConfig:
    min_version: str
    max_version: str
    server_cert_path: str
    server_key_path: str
    ca_cert_path: Optional[str] = None
    require_client_certificate: bool = True
    pinned_fingerprints: List[str] = field(default_factory=list)
    pinned_spki_hashes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class AuthConfig:
    token_secret_path: str
    token_ttl_seconds: int = 900
    enforce_replay_cache: bool = True


@dataclass(frozen=True)
class RateLimitConfig:
    requests_per_second: float = 20.0
    burst: int = 40
    per_client: bool = True


@dataclass(frozen=True)
class LimitsConfig:
    max_connections: int = 128
    max_body_bytes: int = 2097152
    max_header_bytes: int = 8192
    max_header_count: int = 64
    max_uri_length: int = 2048
    max_json_depth: int = 10
    request_timeout_seconds: float = 10.0
    idle_connection_timeout_seconds: float = 30.0


@dataclass(frozen=True)
class SecurityConfig:
    fail_closed: bool = True
    rbac_config_path: str = "security_gateway/config/rbac.yaml"
    hashes_path: str = "security_gateway/config/hashes.json"
    log_file: str = "security_gateway/logs/security.log"
    integrity_check_interval_seconds: int = 60
    watchdog_interval_ms: int = 500


@dataclass(frozen=True)
class WatchdogConfig:
    enabled: bool = True
    lockdown_on_critical: bool = True
    test_mode: bool = False
    watchlist_processes: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class GatewayConfig:
    listener: ListenerConfig
    upstream: UpstreamConfig
    tls: TLSConfig
    auth: AuthConfig
    rate_limit: RateLimitConfig
    limits: LimitsConfig
    security: SecurityConfig
    watchdog: WatchdogConfig


class ConfigLoader:
    """Loads and validates gateway configuration."""

    @classmethod
    def load(cls, config_path: str, base_dir: Optional[str] = None) -> GatewayConfig:
        path = Path(config_path).resolve()
        if not path.exists():
            raise FileNotFoundError(f"Gateway configuration file not found: {path}")

        root_dir = Path(base_dir).resolve() if base_dir else path.parent.parent

        try:
            with open(path, "r", encoding="utf-8") as f:
                raw = yaml.safe_load(f)
        except Exception as e:
            raise ConfigurationValidationError(f"Invalid YAML in gateway configuration: {e}")

        if not isinstance(raw, dict):
            raise ConfigurationValidationError("Configuration root must be a YAML dictionary")

        return cls.validate_and_build(raw, str(root_dir))

    @classmethod
    def validate_and_build(cls, raw: Dict[str, Any], root_dir: str) -> GatewayConfig:
        def resolve_path(p: Optional[str]) -> Optional[str]:
            if not p:
                return None
            path_obj = Path(p)
            if path_obj.is_absolute():
                return str(path_obj)

            # Check direct resolution under root_dir
            candidate1 = Path(root_dir) / path_obj
            if candidate1.exists():
                return str(candidate1)

            # Check if root_dir is already the subdirectory (e.g. security_gateway)
            if path_obj.parts and path_obj.parts[0] == Path(root_dir).name:
                candidate2 = Path(root_dir) / Path(*path_obj.parts[1:])
                if candidate2.exists():
                    return str(candidate2)

            # Check parent directory resolution
            candidate3 = Path(root_dir).parent / path_obj
            if candidate3.exists():
                return str(candidate3)

            return str(candidate1)

        # 1. Listener Validation
        l_raw = raw.get("listener", {})
        l_host = l_raw.get("host", "127.0.0.1")
        l_port = int(l_raw.get("port", 8443))
        allow_ext = bool(l_raw.get("allow_external_binding", False))

        if not (1 <= l_port <= 65535):
            raise ConfigurationValidationError(f"Invalid listener port: {l_port}")
        if (l_host in ("0.0.0.0", "::")) and not allow_ext:
            raise ConfigurationValidationError(
                "Refusing to bind listener to 0.0.0.0 without explicit allow_external_binding flag"
            )

        listener = ListenerConfig(host=l_host, port=l_port, allow_external_binding=allow_ext)

        # 2. Upstream Validation (CRITICAL ANTI-SSRF BOUNDARY)
        u_raw = raw.get("upstream", {})
        u_host = u_raw.get("host", "127.0.0.1")
        u_port = int(u_raw.get("port", 3000))
        u_sock = resolve_path(u_raw.get("unix_socket_path"))
        u_timeout = float(u_raw.get("timeout_seconds", 15.0))
        u_max_resp = int(u_raw.get("max_response_bytes", 10485760))

        # Absolute rule: Upstream must strictly be loopback or unix socket
        if u_host not in ("127.0.0.1", "localhost") and not u_sock:
            raise ConfigurationValidationError(
                f"FATAL: Upstream host '{u_host}' is forbidden. "
                "Upstream must ONLY be 127.0.0.1 or a local Unix socket to prevent SSRF proxying."
            )
        if not (1 <= u_port <= 65535):
            raise ConfigurationValidationError(f"Invalid upstream port: {u_port}")
        if u_timeout <= 0:
            raise ConfigurationValidationError("Upstream timeout must be positive")

        upstream = UpstreamConfig(
            host=u_host,
            port=u_port,
            unix_socket_path=u_sock,
            timeout_seconds=u_timeout,
            max_response_bytes=u_max_resp,
        )

        # 3. TLS Validation
        t_raw = raw.get("tls", {})
        t_min = t_raw.get("min_version", "TLSv1.3")
        t_max = t_raw.get("max_version", "TLSv1.3")
        if t_min != "TLSv1.3":
            raise ConfigurationValidationError(
                f"FATAL: Insecure TLS min_version '{t_min}'. Gateway requires 'TLSv1.3'."
            )

        cert_p = resolve_path(t_raw.get("server_cert_path"))
        key_p = resolve_path(t_raw.get("server_key_path"))
        ca_p = resolve_path(t_raw.get("ca_cert_path"))
        req_client = bool(t_raw.get("require_client_certificate", True))

        if not cert_p or not Path(cert_p).exists():
            raise ConfigurationValidationError(f"Server certificate path does not exist: {cert_p}")
        if not key_p or not Path(key_p).exists():
            raise ConfigurationValidationError(f"Server private key path does not exist: {key_p}")
        if req_client and (not ca_p or not Path(ca_p).exists()):
            raise ConfigurationValidationError(f"Client CA certificate path does not exist: {ca_p}")

        tls = TLSConfig(
            min_version=t_min,
            max_version=t_max,
            server_cert_path=cert_p,
            server_key_path=key_p,
            ca_cert_path=ca_p,
            require_client_certificate=req_client,
            pinned_fingerprints=t_raw.get("pinned_fingerprints", []),
            pinned_spki_hashes=t_raw.get("pinned_spki_hashes", []),
        )

        # 4. Auth Validation
        a_raw = raw.get("auth", {})
        t_sec_p = resolve_path(a_raw.get("token_secret_path"))
        if not t_sec_p or not Path(t_sec_p).exists():
            raise ConfigurationValidationError(f"Token secret path does not exist: {t_sec_p}")

        auth = AuthConfig(
            token_secret_path=t_sec_p,
            token_ttl_seconds=int(a_raw.get("token_ttl_seconds", 900)),
            enforce_replay_cache=bool(a_raw.get("enforce_replay_cache", True)),
        )

        # 5. Rate Limit Validation
        rl_raw = raw.get("rate_limit", {})
        rps = float(rl_raw.get("requests_per_second", 20.0))
        burst = int(rl_raw.get("burst", 40))
        if rps <= 0:
            raise ConfigurationValidationError("Rate limit requests_per_second must be positive")
        if burst < rps:
            raise ConfigurationValidationError("Rate limit burst must be greater than or equal to rate")

        rate_limit = RateLimitConfig(
            requests_per_second=rps,
            burst=burst,
            per_client=bool(rl_raw.get("per_client", True)),
        )

        # 6. Limits Validation
        lim_raw = raw.get("limits", {})
        limits = LimitsConfig(
            max_connections=int(lim_raw.get("max_connections", 128)),
            max_body_bytes=int(lim_raw.get("max_body_bytes", 2097152)),
            max_header_bytes=int(lim_raw.get("max_header_bytes", 8192)),
            max_header_count=int(lim_raw.get("max_header_count", 64)),
            max_uri_length=int(lim_raw.get("max_uri_length", 2048)),
            max_json_depth=int(lim_raw.get("max_json_depth", 10)),
            request_timeout_seconds=float(lim_raw.get("request_timeout_seconds", 10.0)),
            idle_connection_timeout_seconds=float(lim_raw.get("idle_connection_timeout_seconds", 30.0)),
        )

        # 7. Security & Watchdog
        sec_raw = raw.get("security", {})
        security = SecurityConfig(
            fail_closed=bool(sec_raw.get("fail_closed", True)),
            rbac_config_path=str(resolve_path(sec_raw.get("rbac_config_path", "security_gateway/config/rbac.yaml"))),
            hashes_path=str(resolve_path(sec_raw.get("hashes_path", "security_gateway/config/hashes.json"))),
            log_file=str(resolve_path(sec_raw.get("log_file", "security_gateway/logs/security.log"))),
            integrity_check_interval_seconds=int(sec_raw.get("integrity_check_interval_seconds", 60)),
            watchdog_interval_ms=int(sec_raw.get("watchdog_interval_ms", 500)),
        )

        wd_raw = raw.get("watchdog", {})
        watchdog = WatchdogConfig(
            enabled=bool(wd_raw.get("enabled", True)),
            lockdown_on_critical=bool(wd_raw.get("lockdown_on_critical", True)),
            test_mode=bool(wd_raw.get("test_mode", False)),
            watchlist_processes=wd_raw.get("watchlist_processes", []),
        )

        return GatewayConfig(
            listener=listener,
            upstream=upstream,
            tls=tls,
            auth=auth,
            rate_limit=rate_limit,
            limits=limits,
            security=security,
            watchdog=watchdog,
        )
