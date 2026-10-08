# HNX26EPS01 — ZERO TRUST HOST SECURITY GATEWAY & DEFENSIVE ARCHITECTURE

### Standalone Enterprise Security Gateway Protecting the HNX26EPS01 Agentic Legal Assistant

---

## 1. Executive Summary & Dual Security Doctrines

This system implements an enterprise-grade, standalone **Zero-Trust Host Security Gateway** designed to protect the local **HNX26EPS01 Agentic Legal Assistant** operating strictly on loopback:
```text
http://127.0.0.1:3000
```

The platform unifies two independent, complementary core philosophies:

1. **For Legal AI Intelligence**:
   > **VERIFIABILITY OVER FLUENCY**
   All legal outputs are evidence-grounded, provenance-aware, bounded, and fail-closed when statutory or case-law evidence is insufficient.

2. **For Runtime & Network Security**:
   > **NEVER TRUST — ALWAYS VERIFY**
   No implicit trust is inferred from network location, IP address, localhost origin, previous authentication, or user role alone. Every request passes through continuous, identity-centric attribute verification before reaching the protected service.

The gateway implements **zero legal business logic**, makes **zero external cloud API calls**, and has **zero remote dependencies**. It is implemented entirely host-native on Linux without container abstractions.

---

## 2. Master Defensive Architecture

```text
                                CLIENT
                                  │
                                  ▼
                         ┌─────────────────┐
                         │ NFTABLES (L3/4) │
                         │ DEFAULT DENY    │
                         │ Anti-Scan Rules │
                         │ DDoS Rate Limit │
                         │ Loopback Isolate│
                         └────────┬────────┘
                                  │ (Port 8443)
                                  ▼
                         ┌─────────────────┐
                         │ TLS 1.3 / mTLS  │
                         │ Client Cert ID  │
                         │ SPKI Pinning    │
                         │ Memory Hardened │
                         └────────┬────────┘
                                  │
                                  ▼
              ┌───────────────────────────────────────┐
              │ ZERO TRUST POLICY DECISION POINT      │
              │ (core/zero_trust_policy.py)           │
              │                                       │
              │ • Who is the principal?               │
              │ • What device presented the cert?     │
              │ • What is the bound token claim?      │
              │ • What role & scopes are authorized?  │
              │ • What resource & action requested?   │
              │ • What is the host security posture?  │
              │ • What is the evaluated request risk? │
              │ • Why now? (Continuous validity)     │
              └───────────────────┬───────────────────┘
                                  │
                        ┌─────────┴─────────┐
                        │                   │
                     ALLOW                DENY
                        │
                        ▼
       ┌─────────────────────────────────┐
       │ POLICY ENFORCEMENT POINT (PEP)  │
       │ (core/policy_enforcement.py)    │
       │                                 │
       │ 1. Normalize Request Framing    │
       │ 2. Cryptographic Cert Pinning   │
       │ 3. RFC 8705 Token Binding Check │
       │ 4. Session Validation & Touch   │
       │ 5. Deterministic Risk Scoring   │
       │ 6. Construct RequestContext     │
       │ 7. Audit Workload Identity      │
       │ 8. PDP Declarative Evaluation   │
       │ 9. Context-Aware DPI Inspection │
       │ 10. Per-Client Token Bucket RL  │
       │ 11. Upstream Forwarding (Close) │
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │ WORKLOAD IDENTITY VALIDATION    │
       │ (core/workload_identity.py)     │
       │ Validates PID, socket, UID,     │
       │ and binary hash on 127.0.0.1    │
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │ UPSTREAM CONNECTOR              │
       │ (upstream_connector.py)         │
       │ • Anti-SSRF Destination Lock    │
       │ • Anti-Smuggling (CL/TE Reject) │
       │ • Hop-by-Hop Header Stripping   │
       │ • Provenance Header Injection   │
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │ UPSTREAM AGENTIC LEGAL WORKLOAD │
       │ (upstream_legal_agent.py)       │
       │ http://127.0.0.1:3000           │
       │ (FastAPI + Uvicorn)             │
       └────────────────┬────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────┐
       │ EVIDENCE LEDGER & VERIFIER      │
       │ • Statutory Citations (UCC)     │
       │ • Claim Mappings                │
       │ • Fail-Closed Grounding Engine  │
       └─────────────────────────────────┘

            CONTINUOUS TRUST & TELEMETRY SIGNALS
            ────────────────────────────────────
            Anti-Tamper Watchdog (anti_tamper_watchdog.py)
            Cryptographic Baseline (integrity_monitor.py)
            Linux Kernel Primitives (PR_SET_DUMPABLE, mlock)
            Device Posture Registry (core/client_registry.py)
            Session Lifecycle Manager (core/session_manager.py)
            Deterministic Risk Engine (core/risk_engine.py)
            Packet Defense Inspector (packet_inspector.py)
            NetfilterQueue Bridge (nfqueue_filter.py)
                            │
                            ▼
              Gateway Posture Engine (SecurityPosture)
                            │
                            ▼
               Emergency Lockdown & Revocation
```

---

## 3. Technology Stack & Requirements Alignment

All pinned requirements in `requirements.txt` are actively integrated and utilized:

| Dependency | Version | Architectural Role & Implementation File |
| :--- | :--- | :--- |
| **`cryptography`** | `50.0.2` | X.509 certificate parsing, SHA-256 fingerprinting, SPKI public key pinning in `tls_manager.py`, `core/client_registry.py`. |
| **`fastapi`** | `0.115.0` | Powers the protected local `upstream_legal_agent.py` (`/legal/query`, `/legal/search`, `/legal/review`, `/legal/draft`, `/health`) enforcing **Verifiability Over Fluency**. |
| **`uvicorn`** | `0.30.6` | High-performance ASGI runtime serving the protected legal assistant on loopback `127.0.0.1:3000`. |
| **`scapy`** | `2.6.1` | Packet craftsmanship and Layer 3/4 firewall policy auditor in `packet_inspector.py` (auditing NULL, FIN, XMAS scans and loopback port 3000 isolation). |
| **`netfilterqueue`** | `1.1.0` | Linux Netfilter / nftables userspace packet filtering hook bridge in `nfqueue_filter.py`. |
| **`PyYAML`** | `6.0.3` | Declarative Zero-Trust policy (`config/zero_trust_policy.yaml`), RBAC matrix (`config/rbac.yaml`), and master configuration (`config/gateway.yaml`). |
| **`psutil`** | `7.2.2` | Process tree inspection, debugger detection (`tracer_pid`), and upstream workload identity auditing in `core/workload_identity.py` and `anti_tamper_watchdog.py`. |
| **`httpx`** | `0.28.1` | Upstream connector, end-to-end proxy integration tests, and asynchronous verification clients in `gateway_proxy.py` and test suites. |
| **`pytest`** | `9.1.1` | Comprehensive test harness executing all 72 automated unit, integration, and adversarial tests. |
| **`cffi`** | `2.1.1` | Low-level C bindings for cryptography and Linux kernel network libraries. |
| **`anyio`** | `4.15.1` | Asynchronous structured concurrency backend powering FastAPI, Uvicorn, and HTTPX. |
| **`certifi`** | `2026.7.22`| CA bundle validation utility for offline TLS certificate checking. |
| **`h11`** | `0.16.0` | Zero-overhead HTTP/1.1 protocol parsing for Uvicorn and HTTPX transports. |
| **`httpcore`** | `1.0.9` | Core transport layer for HTTPX connection pools. |
| **`idna`** | `3.20` | Internationalized domain name resolution validation. |
| **`iniconfig`** | `2.3.1` | Pytest configuration engine. |
| **`packaging`** | `26.3` | Version comparison and dependency specification tools. |
| **`pluggy`** | `1.6.0` | Pytest plugin architecture. |
| **`pycparser`** | `3.1` | C code parser supporting CFFI. |
| **`Pygments`** | `2.21.0` | Syntax highlighting and terminal formatting for CLI output. |
| **`typing_extensions`** | `4.16.0` | Advanced type hint annotations throughout the Zero-Trust core models. |

---

## 4. Complete Component Inventory

```text
security_gateway/
├── firewall_rules.nft             # Layer 3 nftables ruleset (Default Deny, Anti-Scan, Port 3000 isolation)
├── gateway_proxy.py               # Async TLS 1.3 reverse proxy & Policy Enforcement Point dispatcher
├── anti_tamper_watchdog.py        # Independent host watchdog & /proc TracerPid anti-debugging monitor
├── integrity_monitor.py           # Cryptographic SHA-256 asset integrity monitor
├── memory_protection.py           # Linux prctl, mlock, and anonymous memfd primitives
├── token_vault.py                 # HMAC-SHA256 session token manager & RFC 8705 certificate binding
├── rbac_engine.py                 # Least-privilege role-based access control engine
├── dpi_engine.py                  # Deep Packet Inspection & false-positive resistant SQLi detector
├── tls_manager.py                 # TLS 1.3 / mTLS manager and SPKI pinning engine
├── upstream_connector.py          # Strict loopback upstream forwarder & anti-smuggling parser
├── incident_response.py           # Security state machine & emergency lockdown kill-switch
├── security_logger.py             # Redacting structured JSON security audit logger
├── config_loader.py               # Fail-closed YAML configuration validator
├── cli.py                         # Operator command-line interface
├── upstream_legal_agent.py        # Protected local HNX26EPS01 AI assistant (FastAPI + Uvicorn)
├── packet_inspector.py            # Layer 3/4 packet defense auditing engine (Scapy)
├── nfqueue_filter.py              # Userspace NetfilterQueue packet filter bridge
├── requirements.txt               # Pinned Python package dependencies
│
├── core/                          # Zero-Trust Architecture Core
│   ├── identity.py                # AuthenticatedPrincipal & cryptographic identity model
│   ├── client_registry.py         # Device registry, certificate SHA-256 pinning, and posture
│   ├── security_context.py        # Host SecurityPosture aggregator & RequestContext
│   ├── workload_identity.py       # Upstream workload socket & binary validator
│   ├── session_manager.py         # Continuous session revalidation & emergency revocation
│   ├── risk_engine.py             # Deterministic local risk scoring (0-100)
│   ├── zero_trust_policy.py       # Zero-Trust Policy Decision Point (PDP) & ABAC matrix
│   └── policy_enforcement.py      # Policy Enforcement Point (PEP) 11-step pipeline
│
├── config/
│   ├── gateway.yaml               # Master gateway configuration
│   ├── rbac.yaml                  # Role and route authorization policies
│   ├── zero_trust_policy.yaml     # Declarative Zero-Trust policy & client registry
│   ├── hashes.json                # Cryptographic asset baseline database (37 assets)
│   └── token_secret.key           # Protected HMAC secret key (mode 0600)
│
├── certs/                         # Cryptographic PKI
│   ├── ca.crt / ca.key            # Root Certificate Authority
│   ├── server.crt / server.key    # TLS 1.3 Server Certificate (SAN 127.0.0.1)
│   └── client.crt / client.key    # Authorized mTLS Client Certificate
│
├── scripts/
│   ├── setup_firewall.sh          # Layer 3 nftables deployment and syntax verification
│   ├── generate_certificates.sh   # PKI certificate generator
│   ├── create_baseline.sh         # Cryptographic baseline generator
│   ├── lockdown.sh                # Emergency manual lockdown trigger
│   └── security_self_test.sh      # Automated 14-phase pre-flight self-test suite
│
├── systemd/
│   ├── secure-gateway.service     # Hardened Linux systemd service for proxy
│   └── anti-tamper-watchdog.service # Hardened systemd service for watchdog
│
└── tests/                         # Full automated pytest test suite (72 tests)
    ├── test_adversarial_bypass.py # 5 adversarial attack tests (headers, traversal, SSRF)
    ├── test_zero_trust_identity.py# Identity model and anonymous trust tests
    ├── test_zero_trust_policy.py  # PDP rule evaluation tests
    ├── test_zero_trust_rbac_abac.py # ABAC posture, scope, and step-up tests
    ├── test_zero_trust_lockdown.py# Lockdown session revocation tests
    ├── test_token_binding.py      # RFC 8705 certificate confirmation binding tests
    ├── test_device_posture.py     # Client registry and posture tests
    ├── test_risk_engine.py        # Local deterministic risk scoring tests
    ├── test_session_revalidation.py # Session lifecycle and continuous touch tests
    ├── test_packet_filtering.py   # Scapy packet inspection & NFQueue tests
    ├── test_upstream_legal_agent.py # FastAPI workload verifiability tests
    ├── test_tls.py                # TLS 1.3 enforcement tests
    ├── test_mtls.py               # mTLS & SPKI pinning tests
    ├── test_auth.py               # HMAC token vault & replay tests
    ├── test_rbac.py               # RBAC matrix tests
    ├── test_dpi.py                # DPI SQLi & false-positive resistance tests
    ├── test_integrity.py          # Cryptographic baseline integrity tests
    ├── test_watchdog.py           # Anti-tamper & TracerPid tests
    ├── test_rate_limit.py         # Token bucket rate limiting tests
    └── test_gateway.py            # End-to-end proxy integration tests
```

---

## 5. Layer 3 — Network Packet Filtering & Scapy Auditing

Defined in `firewall_rules.nft` and verified by `packet_inspector.py`:

1. **Default Deny Policy**:
   All unsolicited inbound network traffic is silently dropped (`policy drop`).
2. **Loopback Port 3000 Isolation**:
   ```nft
   iifname != "lo" tcp dport 3000 counter drop comment "BLOCK: External interface access to upstream port 3000"
   iifname "lo" tcp dport 3000 ct state { new, established } counter accept comment "ALLOW: Local loopback to upstream 3000"
   ```
   External network interfaces can never reach port 3000 under any circumstances.
3. **Reconnaissance & Anti-Scan Defenses**:
   - Drops TCP NULL scans (`tcp flags == 0x0 / 0x3f`).
   - Drops TCP FIN scans (`tcp flags & (fin|syn|rst|psh|ack|urg) == fin`).
   - Drops TCP XMAS scans (`tcp flags & (fin|syn|rst|psh|ack|urg) == fin|psh|urg`).
   - Drops SYN-FIN and SYN-RST scans.
   - Drops invalid connection tracking states (`ct state invalid drop`).
   - Uses silent `DROP` semantics (no TCP RST or ICMP Unreachable emitted) to prevent port-scanning reconnaissance.
4. **Anti-DDoS Packet and Connection Meters**:
   - `flood_meter`: Clamps incoming packets on port 8443 to 20/second with a burst of 40.
   - `conn_meter`: Clamps concurrent connections to 32 per source IP.
5. **Scapy Packet Auditing & NetfilterQueue**:
   - `packet_inspector.py` crafts and audits Layer 3/4 packets against the firewall policy.
   - `nfqueue_filter.py` hooks into `nftables queue num 0` for userspace packet inspection.

---

## 6. Cryptographic Perimeter & Linux Process Hardening

### TLS 1.3 & Mutual TLS (mTLS) (`tls_manager.py`)
- **Protocol Restriction**: Strictly enforces `ssl.TLSVersion.TLSv1_3` as both minimum and maximum. TLS 1.0, 1.1, and 1.2 are permanently rejected.
- **Client Authentication**: Enforces `ssl.CERT_REQUIRED`. Connections without a valid client certificate signed by the trusted internal CA fail at handshake.
- **SPKI Fingerprint Pinning**: Supports SubjectPublicKeyInfo SHA-256 pinning, allowing CA certificate renewal without breaking cryptographic client bindings.
- **Key Permission Enforcement**: The gateway refuses to start if any private key is readable or writable by group or others (`chmod 600` strictly enforced).

### Memory Hardening & Process Isolation (`memory_protection.py`)
- **Dumpability Hardening**: Invokes Linux `prctl(PR_SET_DUMPABLE, 0)` and `resource.setrlimit(RLIMIT_CORE, (0, 0))` at process initialization. Prevents core dumps and unprivileged `ptrace` attachment.
- **RAM Locking (`mlock`)**: Cryptographic keys are loaded into RAM-locked buffers via `libc.mlock()` to prevent paging out to disk or swap partitions.
- **Explicit Zeroing**: Overwrites sensitive key buffers using volatile zeroing before memory release.
- **Anonymous Memory Files**: Supports `memfd_create(..., MFD_CLOEXEC)` for ephemeral secret operations without filesystem backing.

---

## 7. Zero-Trust Policy Decision & Enforcement Pipeline

### 7.1 Policy Decision Point (`core/zero_trust_policy.py`)
- Central authorization engine evaluating identity, device posture, role, scopes, resource, action, host security posture, and risk score.
- Returns explicit decisions: `ALLOW`, `DENY`, `STEP_UP`, `REVIEW`.
- Fails closed (`DENY`) on unknown identity, unknown device, unmapped resource, or missing scopes.
- Generates reproducible, explainable denial codes:
  ```text
  IDENTITY_UNKNOWN
  CERTIFICATE_INVALID
  TOKEN_EXPIRED
  TOKEN_BINDING_MISMATCH
  ROLE_NOT_PERMITTED_FOR_DEVICE
  SCOPE_NOT_PERMITTED
  RESOURCE_NOT_ALLOWED
  ACTION_NOT_ALLOWED
  HOST_POSTURE_RESTRICTED
  RISK_TOO_HIGH
  DEVICE_NOT_REGISTERED
  INTEGRITY_COMPROMISED
  WATCHDOG_ALERT
  UPSTREAM_IDENTITY_MISMATCH
  POLICY_DEFAULT_DENY
  ```

### 7.2 Policy Enforcement Point (`core/policy_enforcement.py`)
Every request traverses an 11-step pipeline:
1. **Frame Normalization**: Strips invalid framing, hop-by-hop headers, and path traversal tricks.
2. **TLS / mTLS Validation**: Verifies certificate validity and SHA-256 fingerprint against the Client Registry.
3. **Cryptographic Identity Extraction**: Parses token and extracts claims.
4. **RFC 8705 Token Binding Check**: Validates that `cnf.sha256` in the token matches the client certificate.
5. **Session Validation & Touch**: Looks up continuous session; verifies idle TTL (300s) and absolute TTL (3600s).
6. **Deterministic Risk Scoring**: Evaluates local risk score (0–100) based on source behavior and posture.
7. **Construct RequestContext**: Creates an immutable audit snapshot for the request.
8. **Workload Identity Audit**: Verifies upstream PID, socket binding, executable name, UID, and binary hash.
9. **PDP Evaluation**: Executes RBAC + ABAC policy rules against the context.
10. **Deep Packet Inspection (DPI)**: Validates JSON structure, depth, size, and SQLi signatures.
11. **Isolated Upstream Forwarding**: Forwards request with injected provenance headers (`X-HNX-Gateway-Verified: true`, `X-HNX-Subject`, `X-HNX-Role`).

---

## 8. Token-Certificate Cryptographic Binding (RFC 8705)

To eliminate token theft and replay across different client machines, tokens incorporate an RFC 8705 certificate confirmation claim:

```json
{
  "alg": "HS256",
  "typ": "HNX-TOKEN"
}
.
{
  "jti": "d6c9683b-1d12-4af6-931e-8e3d468993d0",
  "sub": "attorney_alice",
  "role": "ROLE_LEGAL_QUERY",
  "scopes": ["legal.query", "legal.search"],
  "iat": 1791477532,
  "exp": 1791478432,
  "cnf": {
    "sha256": "F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E"
  }
}
```

If a valid token is presented over an mTLS connection with a mismatched certificate fingerprint, the gateway immediately rejects the request:
```text
REASON: TOKEN_BINDING_MISMATCH
DECISION: DENY
```

---

## 9. Deep Packet Inspection & False-Positive Control (`dpi_engine.py`)

- **Defensive Inspection**: Inspects URI length, headers, query parameters, and JSON payloads.
- **SQLite Injection Indicators**: Detects signatures such as:
  - Tautologies: `' OR '1'='1`, `' OR 1=1 --`
  - Union extraction: `UNION SELECT`, `UNION ALL SELECT`
  - Stacked execution: `; DROP TABLE`, `; ATTACH DATABASE`
  - Extension execution: `load_extension(`
  - System catalog enumeration: `sqlite_master` in query context
  - Memory exhaustion functions: `randomblob()`, `zeroblob()`
  - Comment obfuscation: `/*...*/ UNION SELECT`
- **False-Positive Control**: Distinguishes structural query parameters from legitimate legal prose. Sentences mentioning "European Union", "labor union", or "master agreement" in contract analysis bodies pass without false blocks.
- **Resource Limits**: Clamps JSON nesting depth (max 10), body size (max 2 MB), header count (max 64), and URI length (max 2048). Rejects embedded null bytes (`\x00`).

---

## 10. Anti-Tamper Watchdog & Emergency Isolation

### Host Watchdog (`anti_tamper_watchdog.py`)
- Operates as a resident independent monitoring process.
- **Anti-Debugging Detection**: Monitors `/proc/<pid>/status` for `TracerPid`. If `TracerPid > 0`, an unauthorized debugger (`gdb`, `strace`, `lldb`) is attached.
- **Binary Swap Detection**: Reads `/proc/<pid>/exe` to detect if the running binary was deleted or replaced on disk.
- **Multi-Signal Triage**: Distinguishes harmless background tools from targeted inspection. Unrelated tools generate `INFO` or `SUSPICIOUS` audit logs. Direct targeting triggers `CRITICAL`.
- **Safe eBPF Degradation**: Gracefully probes kernel tracefs; falls back safely to `/proc` sampling without raising permissions errors.

### Emergency Kill-Switch (`incident_response.py`)
Upon confirmed critical compromise:
1. Emits a structured `CRITICAL` forensic audit record.
2. Transitions the Security State Machine to `LOCKDOWN`.
3. Places a persistent lockfile `logs/LOCKDOWN.state`.
4. Gracefully terminates the upstream legal assistant process (`SIGTERM` -> `SIGKILL` after 1 second).
5. Terminate all active sessions immediately.
6. Gateway stops forwarding all traffic.
7. **No Automatic Restart**: The gateway remains locked down until an administrator manually issues:
   ```bash
   python3 cli.py unlock --confirm
   ```

---

## 11. Upstream Agentic Legal Assistant (`upstream_legal_agent.py`)

The protected local service implements the HNX26EPS01 AI assistant using FastAPI and Uvicorn on `127.0.0.1:3000`:
- **Core Doctrine**: **Verifiability Over Fluency**.
- **Endpoints**:
  - `POST /api/v1/legal/query`: Grounded legal RAG with evidence ledgers and claim mappings.
  - `POST /api/v1/legal/search`: Grounded statutory citation and case law retrieval.
  - `POST /api/v1/legal/review`: Contract liability, indemnification, and covenant analysis.
  - `POST /api/v1/legal/draft`: Bounded contract drafting with governing law covenants.
  - `GET /health`: Health probe reporting workload ID and listening socket.
- **Fail-Closed Verifiability**: When evidence grounding falls below the mandatory threshold (e.g., hallucinatory or speculative legal claims), the engine returns `UNVERIFIABLE_FAIL_CLOSED` with a 0.0 grounding score and evidence audit trail.

---

## 12. Verification & Test Results

### 12.1 Pre-Flight Security Self-Test (14/14 Checks Passed)
```bash
bash security_gateway/scripts/security_self_test.sh
```
```text
==============================================================================
HNX26EPS01 SECURITY GATEWAY — PRE-FLIGHT COMPREHENSIVE SELF-TEST
==============================================================================
[*] [1/10] Checking Gateway & RBAC Configuration... PASS
[*] [2/10] Checking Layer 3 nftables rules syntax... PASS
[*] [3/10] Checking TLS 1.3 / mTLS Certificates & Private Key permissions... PASS
[*] [4/10] Checking Memory Protection & prctl dumpability... PASS
[*] [5/10] Checking Token Vault (HMAC-SHA256 & Replay Cache)... PASS
[*] [6/10] Checking RBAC Engine least-privilege matrix... PASS
[*] [7/10] Checking DPI Engine (Anti-SQLi & False Positive resistance)... PASS
[*] [8/10] Checking File Integrity Baseline (hashes.json)... PASS
[*] [9/10] Checking Anti-Tamper Watchdog inspection logic... PASS
[*] [10/14] Checking Zero Trust PDP & Declarative Policy... PASS
[*] [11/14] Checking Client Device Registry & Posture Evaluation... PASS
[*] [12/14] Checking Upstream Agentic Legal Assistant (FastAPI/Uvicorn)... PASS
[*] [13/14] Checking Scapy Layer 3/4 Packet Anti-Reconnaissance Inspector... PASS
[*] [14/14] Running Comprehensive Gateway Pytest Suite... PASS
==============================================================================
SECURITY SELF-TEST: PASS
```

### 12.2 Automated Pytest Suite (72/72 Tests Passed)
```bash
.venv/bin/pytest security_gateway/tests -v
```
```text
======================= 72 passed, 10 warnings in 3.18s ========================
```
- **Adversarial Bypasses**: Forged role headers, forged user IDs, localhost trust bypass, path traversal breakout, and SSRF destination override.
- **Zero-Trust Identity & ABAC**: Scope verification, device posture, step-up auth, lockdown session revocation.
- **Cryptographic Perimeter**: TLS 1.3 enforcement, mTLS DER validation, SPKI pinning, RFC 8705 token-certificate binding.
- **Host Security**: `PR_SET_DUMPABLE` memory protection, anti-debugging detection, HMAC replay prevention, SHA-256 file baseline monitoring.
- **Network Defenses**: Scapy packet audit for NULL, FIN, XMAS, SYN-FIN, SYN-RST scans, loopback port 3000 isolation, NetfilterQueue packet bridge.
- **Protected Legal Assistant**: Grounded evidence ledger, claim mapping, fail-closed verifiability threshold, contract review.

---

## 13. Operational CLI Administration

```bash
# 1. Inspect Zero-Trust Policy Decision Point & Client Device Posture
.venv/bin/python security_gateway/cli.py zero-trust-status

# 2. Run Protected Upstream Legal Assistant (FastAPI + Uvicorn)
.venv/bin/python security_gateway/cli.py run-upstream --host 127.0.0.1 --port 3000

# 3. Audit Layer 3/4 Packet Defenses with Scapy
.venv/bin/python security_gateway/cli.py inspect-packets

# 4. Generate Certificate-Bound Session Token (RFC 8705)
.venv/bin/python security_gateway/cli.py create-token \
    --sub attorney_alice \
    --role ROLE_LEGAL_QUERY \
    --scopes legal.query,legal.search \
    --bound-cert F76F9568CCAC68124C02F21420E6B0F858B98C536DA1425FB1DDC80CCC97836E

# 5. Initiate Emergency Lockdown
.venv/bin/python security_gateway/cli.py lockdown --reason "Tamper alarm triggered"

# 6. Unlock Gateway After Incident Investigation
.venv/bin/python security_gateway/cli.py unlock --confirm

# 7. Audit Cryptographic File Integrity
.venv/bin/python security_gateway/cli.py verify-integrity
```

---

## 14. Important Security Limitations

Defensive transparency requires documenting operational boundaries honestly:

1. **TLS Does Not Protect Against a Fully Compromised Host Kernel**:
   TLS 1.3 and mTLS provide confidentiality and integrity in transit. They do not prevent an adversary with `root` privileges from inspecting memory via the kernel or hypervisor.
2. **mTLS Is Not Anti-Debugging**:
   mTLS authenticates the network client; it does not prevent a root user on the server host from attaching diagnostic instrumentation (which is why the Watchdog exists).
3. **`mlock()` Is Not Absolute Secrecy**:
   `mlock()` prevents cryptographic keys from being written to swap partitions. It does not prevent process inspection by `root` or kernel-level memory readers.
4. **`nftables` Cannot Eliminate All Passive Reconnaissance**:
   Packet filtering significantly reduces exposed attack surface and silences unsolicited responses, but cannot conceal host presence from passive network taps or link-layer observers.
5. **DPI Is a Secondary Defense**:
   Deep Packet Inspection serves as defense-in-depth against payload anomalies. The upstream legal assistant **must still use parameterized SQL queries** and strict input validation.

---

## 15. Zero-Trust Acceptance Criteria Checklist

- [x] **No implicit trust based on localhost**: Localhost connections undergo identical mTLS, token, and ABAC verification.
- [x] **No implicit trust based on previous authentication**: Sessions continuously revalidate against posture, certificate state, and idle TTL.
- [x] **No trust based solely on IP**: IP address only serves as a rate-limiting and risk telemetry signal.
- [x] **Every request is authorized**: Policy Enforcement Point intercepts and validates 100% of HTTP traffic.
- [x] **mTLS identifies clients**: Client certificate SHA-256 is pinned to client device registry.
- [x] **Tokens are cryptographically validated**: HMAC-SHA256 signature, expiry, and replay cache enforced.
- [x] **Token identity is bound to client identity**: RFC 8705 `cnf.sha256` binding strictly verified.
- [x] **RBAC + ABAC is enforced**: Rules evaluate role, resource, action, risk score, posture, and required scopes.
- [x] **Default policy is DENY**: Any unmapped route, unknown certificate, or missing scope fails closed.
- [x] **Security posture affects authorization**: Degraded or compromised postures immediately restrict sensitive actions.
- [x] **Workload identity is validated**: Audits PID, binary hash, and socket binding of `127.0.0.1:3000`.
- [x] **Upstream destination is immutable**: Hardcoded to `127.0.0.1:3000`; SSRF destination overrides are rejected.
- [x] **100% Offline operation**: Zero remote dependencies, zero external IdPs, zero telemetry cloud calls.
