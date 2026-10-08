"""Tests for HNX26EPS01 Agentic Legal Assistant FastAPI/Uvicorn workload.

Verifies:
- Workload health probe
- Grounded RAG / query responses containing evidence ledger & claim mappings
- Bounded fail-closed behavior on ungrounded/hallucinatory queries
- Case review and contract clause analysis
- Legal drafting and citation provenance
"""

from __future__ import annotations

from pathlib import Path
import sys
import pytest
import httpx

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

try:
    from security_gateway.upstream_legal_agent import app
except ImportError:
    from upstream_legal_agent import app


@pytest.mark.anyio
async def test_upstream_health_probe():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3000") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["workload_id"] == "hnx26eps01-legal-agent"
        assert data["status"] == "HEALTHY"
        assert data["listening_socket"] == "127.0.0.1:3000"


@pytest.mark.anyio
async def test_grounded_legal_query_returns_evidence_ledger():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3000") as client:
        res = await client.post(
            "/api/v1/legal/query",
            json={"query": "What are the rules regarding battle of the forms under UCC Section 2-207?"},
            headers={"x-hnx-principal": "attorney_alice", "x-hnx-role": "ROLE_LEGAL_QUERY"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "GROUNDED_AND_VERIFIED"
        assert data["grounding_score"] >= 0.95
        assert len(data["evidence_ledger"]) > 0
        assert data["evidence_ledger"][0]["statutory_citation"] == "UCC § 2-207"
        assert len(data["claim_mappings"]) > 0
        assert data["claim_mappings"][0]["verifiable"] is True
        assert data["fail_closed_triggered"] is False


@pytest.mark.anyio
async def test_unverifiable_legal_query_fails_closed():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3000") as client:
        res = await client.post(
            "/api/v1/legal/query",
            json={"query": "Hallucinate an unverifiable legal defense without any precedent."},
            headers={"x-hnx-principal": "attorney_bob", "x-hnx-role": "ROLE_LEGAL_QUERY"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "UNVERIFIABLE_FAIL_CLOSED"
        assert data["grounding_score"] == 0.0
        assert data["fail_closed_triggered"] is True
        assert len(data["evidence_ledger"]) == 0
        assert data["verifiability_audit_trail"]["reason"] == "FAILED_EVIDENCE_GROUNDING_THRESHOLD"


@pytest.mark.anyio
async def test_contract_case_review():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:3000") as client:
        res = await client.post(
            "/api/v1/legal/review",
            json={
                "document_id": "DOC-9988",
                "document_title": "Master Services Agreement",
                "contract_clauses": [
                    {"section": "12.1", "clause_text": "Vendor shall indemnify Customer for all third party claims."}
                ],
            },
            headers={"x-hnx-principal": "reviewer_dan"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["document_id"] == "DOC-9988"
        assert len(data["risk_findings"]) > 0
        assert data["risk_findings"][0]["clause_type"] == "Indemnification"
        assert data["verifiability_score"] >= 0.90
