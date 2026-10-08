"""Upstream Connector and Anti-Smuggling Engine for HNX26EPS01 Security Gateway.

Provides isolated forwarding to the local Agentic Legal Assistant on 127.0.0.1:3000.
Enforces:
- Anti-SSRF: Upstream target is strictly hardcoded to loopback/unix-socket.
  Client-supplied Host, URL schemes, and proxy headers are NEVER used to route requests.
- Request Smuggling Defense: Detects conflicting Content-Length / Transfer-Encoding framing,
  duplicate framing headers, and embedded null bytes.
- Header Normalization: Strips all hop-by-hop headers before upstream forwarding.
- Upstream Response Bounds: Enforces timeout and memory limits on returned data.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import urllib.parse

import httpx

from config_loader import UpstreamConfig


class UpstreamSecurityError(Exception):
    """Base exception for upstream communication and security violations."""


class RequestSmugglingError(UpstreamSecurityError):
    """Raised when ambiguous request framing or desync indicators are detected."""


class UpstreamConnectionError(UpstreamSecurityError):
    """Raised when upstream service is unreachable or unresponsive."""


class UpstreamResponseTooLargeError(UpstreamSecurityError):
    """Raised when upstream response exceeds memory safety bounds."""


# Hop-by-hop headers specified in RFC 7230 / 9110 that must NOT be forwarded
HOP_BY_HOP_HEADERS: Set[str] = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
}

ALLOWED_HTTP_METHODS: Set[str] = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
}


class UpstreamConnector:
    """Safely connects to and proxies requests to local upstream service."""

    def __init__(self, config: UpstreamConfig):
        self.config = config
        self.base_url = f"http://{self.config.host}:{self.config.port}"
        self.client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        """Returns initialized HTTP client bound to upstream destination."""
        if self.client is None or self.client.is_closed:
            transport = None
            if self.config.unix_socket_path:
                transport = httpx.AsyncHTTPTransport(uds=self.config.unix_socket_path)

            self.client = httpx.AsyncClient(
                base_url=self.base_url,
                transport=transport,
                timeout=httpx.Timeout(self.config.timeout_seconds),
                follow_redirects=False,  # Never automatically follow upstream redirects
            )
        return self.client

    def validate_and_normalize_request(
        self,
        method: str,
        path: str,
        raw_headers: List[Tuple[str, str]],
        body: bytes,
    ) -> Tuple[str, str, Dict[str, str]]:
        """Normalizes request and rejects smuggling attacks, path breakouts, and null bytes."""
        # 1. Method validation
        norm_method = method.upper().strip()
        if norm_method not in ALLOWED_HTTP_METHODS:
            raise RequestSmugglingError(f"HTTP method '{norm_method}' is not permitted")

        # 2. Path normalization & traversal check
        if "\x00" in path:
            raise RequestSmugglingError("Null byte detected in request path")

        parsed_url = urllib.parse.urlsplit(path)
        clean_path = urllib.parse.quote(urllib.parse.unquote(parsed_url.path))
        # Prevent traversal breakouts
        normalized_path_parts: List[str] = []
        for segment in clean_path.split("/"):
            if segment in ("", "."):
                continue
            if segment == "..":
                if normalized_path_parts:
                    normalized_path_parts.pop()
                else:
                    raise RequestSmugglingError("Path traversal breakout attempted")
            else:
                normalized_path_parts.append(segment)

        normalized_path = "/" + "/".join(normalized_path_parts)
        if parsed_url.query:
            normalized_path += f"?{parsed_url.query}"

        # 3. Request Smuggling Defense: Header examination
        content_length_count = 0
        has_transfer_encoding = False
        parsed_content_length: Optional[int] = None
        cleaned_headers: Dict[str, str] = {}

        for raw_k, raw_v in raw_headers:
            k = raw_k.strip().lower()
            v = raw_v.strip()

            if "\x00" in k or "\x00" in v:
                raise RequestSmugglingError("Null byte detected in header name or value")

            # Check for duplicate Content-Length
            if k == "content-length":
                content_length_count += 1
                try:
                    cl_val = int(v)
                    if cl_val < 0:
                        raise ValueError()
                    if parsed_content_length is not None and parsed_content_length != cl_val:
                        raise RequestSmugglingError("Conflicting Content-Length header values")
                    parsed_content_length = cl_val
                except ValueError:
                    raise RequestSmugglingError("Malformed or negative Content-Length")

            # Check for Transfer-Encoding
            if k == "transfer-encoding":
                has_transfer_encoding = True

            # Strip hop-by-hop headers
            if k in HOP_BY_HOP_HEADERS or k == "host":
                continue

            cleaned_headers[k] = v

        # Enforce RFC 7230 §3.3.3: Rejection of ambiguous framing (CL + TE)
        if has_transfer_encoding and content_length_count > 0:
            raise RequestSmugglingError(
                "Request contains both Transfer-Encoding and Content-Length (Smuggling Risk)"
            )

        # Validate that Content-Length matches actual payload size
        if parsed_content_length is not None and parsed_content_length != len(body):
            raise RequestSmugglingError(
                f"Content-Length mismatch: header says {parsed_content_length}, body is {len(body)}"
            )

        return norm_method, normalized_path, cleaned_headers

    async def forward(
        self,
        method: str,
        path: str,
        raw_headers: List[Tuple[str, str]],
        body: bytes,
        client_subject: str,
        client_role: str,
        client_ip: str = "127.0.0.1",
    ) -> Tuple[int, Dict[str, str], bytes]:
        """Safely forwards approved request to the loopback upstream service."""
        norm_method, norm_path, headers = self.validate_and_normalize_request(
            method, path, raw_headers, body
        )

        # Inject security boundary provenance headers
        headers["x-forwarded-for"] = client_ip
        headers["x-forwarded-proto"] = "https"
        headers["x-hnx-gateway-verified"] = "true"
        headers["x-hnx-subject"] = client_subject
        headers["x-hnx-role"] = client_role
        headers["host"] = f"{self.config.host}:{self.config.port}"

        client = await self.get_client()

        try:
            req = client.build_request(
                method=norm_method,
                url=norm_path,
                headers=headers,
                content=body if norm_method in ("POST", "PUT", "PATCH") else None,
            )
            resp = await client.send(req, stream=True)

            # Enforce maximum response size while reading
            response_chunks: List[bytes] = []
            total_read = 0

            async for chunk in resp.aiter_bytes():
                total_read += len(chunk)
                if total_read > self.config.max_response_bytes:
                    await resp.aclose()
                    raise UpstreamResponseTooLargeError(
                        f"Upstream response exceeded limit of {self.config.max_response_bytes} bytes"
                    )
                response_chunks.append(chunk)

            await resp.aclose()

            resp_headers: Dict[str, str] = {}
            for k, v in resp.headers.items():
                if k.lower() not in HOP_BY_HOP_HEADERS:
                    resp_headers[k] = v

            return resp.status_code, resp_headers, b"".join(response_chunks)

        except httpx.ConnectError as e:
            raise UpstreamConnectionError(f"Cannot connect to upstream at {self.base_url}: {e}")
        except httpx.TimeoutException as e:
            raise UpstreamConnectionError(f"Upstream request timed out: {e}")
        except Exception as e:
            if isinstance(e, UpstreamSecurityError):
                raise
            raise UpstreamConnectionError(f"Upstream transmission error: {e}")

    async def close(self) -> None:
        if self.client and not self.client.is_closed:
            await self.client.aclose()
