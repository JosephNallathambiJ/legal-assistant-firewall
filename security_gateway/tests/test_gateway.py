"""End-to-End Integration Tests for HNX26EPS01 Security Gateway."""

import asyncio
import json
import ssl
import sys
from pathlib import Path
import pytest
import httpx

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from config_loader import ConfigLoader
from gateway_proxy import GatewayProxy
from token_vault import TokenVault


class MockLegalAssistantServer:
    """Simulates the unprivileged local legal assistant on 127.0.0.1:3000."""

    def __init__(self, host: str = "127.0.0.1", port: int = 3000):
        self.host = host
        self.port = port
        self.server: asyncio.Server | None = None
        self.last_received_headers: dict = {}
        self.last_received_body: bytes = b""

    async def handle_request(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        req_line = await reader.readline()
        headers = {}
        while True:
            line = await reader.readline()
            if not line or line in (b"\r\n", b"\n"):
                break
            k, v = line.decode("latin1").strip().split(":", 1)
            headers[k.strip().lower()] = v.strip()

        self.last_received_headers = headers

        body = b""
        if "content-length" in headers:
            body = await reader.readexactly(int(headers["content-length"]))
        self.last_received_body = body

        resp_body = json.dumps({"status": "SUCCESS", "analysis": "Case review grounded in evidence."}).encode("utf-8")
        resp = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(resp_body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin1") + resp_body

        writer.write(resp)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def start(self):
        self.server = await asyncio.start_server(self.handle_request, self.host, self.port)

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()


def test_end_to_end_gateway_flow():
    asyncio.run(_async_test_end_to_end())


async def _async_test_end_to_end():
    # 1. Start Mock Upstream
    upstream = MockLegalAssistantServer(host="127.0.0.1", port=3000)
    await upstream.start()

    # 2. Start Gateway
    cfg = ConfigLoader.load(str(BASE_DIR / "config" / "gateway.yaml"), base_dir=str(BASE_DIR))
    proxy = GatewayProxy(cfg)
    await proxy.start()

    # Create client SSL context with TLS 1.3 and Client Cert
    certs_dir = BASE_DIR / "certs"
    client_ssl_ctx = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(certs_dir / "ca.crt"),
    )
    client_ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    client_ssl_ctx.load_cert_chain(
        certfile=str(certs_dir / "client.crt"),
        keyfile=str(certs_dir / "client.key"),
    )
    # Check hostname verification with IP SAN
    client_ssl_ctx.check_hostname = False
    client_ssl_ctx.verify_mode = ssl.CERT_REQUIRED

    # Create valid HMAC session token
    token_vault = TokenVault(key_path=cfg.auth.token_secret_path)
    token = token_vault.create_token(
        subject="attorney_jane_doe",
        role="ROLE_LEGAL_QUERY",
        scopes=["legal.query"],
    )

    async with httpx.AsyncClient(
        verify=client_ssl_ctx,
        base_url=f"https://127.0.0.1:{cfg.listener.port}",
        timeout=5.0,
    ) as client:
        # A. Missing Token -> 401 Unauthorized
        res_no_token = await client.post("/api/v1/legal/query", json={"query": "valid contract clause"})
        assert res_no_token.status_code == 401

        # B. Valid Token + Authorized Route -> 200 OK forwarded from upstream
        headers = {"Authorization": f"Bearer {token}"}
        res_valid = await client.post(
            "/api/v1/legal/query",
            headers=headers,
            json={"query": "Review clause 3.1 for arbitration terms"},
        )
        assert res_valid.status_code == 200
        data = res_valid.json()
        assert data["status"] == "SUCCESS"
        assert "evidence" in data["analysis"]

        # Verify Upstream received gateway provenance headers
        assert upstream.last_received_headers["x-hnx-gateway-verified"] == "true"
        assert upstream.last_received_headers["x-hnx-subject"] == "attorney_jane_doe"
        assert upstream.last_received_headers["x-hnx-role"] == "ROLE_LEGAL_QUERY"

        # C. SQL Injection Payload -> 400 Blocked by DPI
        token_c = token_vault.create_token(
            subject="attorney_c", role="ROLE_LEGAL_QUERY", scopes=["legal.query"]
        )
        res_sqli = await client.post(
            "/api/v1/legal/query",
            headers={"Authorization": f"Bearer {token_c}"},
            json={"query": "' OR '1'='1"},
        )
        assert res_sqli.status_code == 400
        assert "Security Gateway" in res_sqli.text

        # D. Forbidden Action via RBAC -> 403 Forbidden
        token_d = token_vault.create_token(subject="attorney_d", role="ROLE_LEGAL_QUERY")
        res_rbac = await client.post(
            "/api/v1/legal/review",  # Requires ROLE_LEGAL_REVIEW, but token has ROLE_LEGAL_QUERY
            headers={"Authorization": f"Bearer {token_d}"},
            json={"case_id": "case_101"},
        )
        assert res_rbac.status_code == 403

        # E. Observability status endpoint
        res_status = await client.get("/security/status")
        assert res_status.status_code == 200
        status_data = res_status.json()
        assert status_data["gateway_state"] == "READY"
        assert status_data["tls_version"] == "TLSv1.3"

    # Clean shutdown
    await proxy.stop()
    await upstream.stop()
