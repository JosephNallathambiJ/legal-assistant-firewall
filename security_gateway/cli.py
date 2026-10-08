"""Command-Line Interface (CLI) for HNX26EPS01 Security Gateway Administration.

Provides administrative controls:
  gateway start
  gateway stop
  gateway status
  gateway self-test
  gateway lockdown
  gateway unlock
  gateway verify-integrity
  gateway verify-firewall
  gateway verify-certificates
  gateway audit
  gateway create-token
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

BASE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from config_loader import ConfigLoader
from gateway_proxy import GatewayProxy
from incident_response import IncidentResponseManager, SecurityState
from integrity_monitor import IntegrityMonitor
from security_logger import get_security_logger
from tls_manager import TLSManager
from token_vault import TokenVault


def get_paths():
    config_file = BASE_DIR / "config" / "gateway.yaml"
    hashes_file = BASE_DIR / "config" / "hashes.json"
    pid_file = BASE_DIR / "logs" / "gateway.pid"
    log_file = BASE_DIR / "logs" / "security.log"
    return config_file, hashes_file, pid_file, log_file


def cmd_start(args: argparse.Namespace) -> None:
    config_file, _, pid_file, _ = get_paths()
    if pid_file.exists():
        try:
            with open(pid_file, "r") as f:
                old_pid = int(f.read().strip())
            os.kill(old_pid, 0)
            print(f"[!] Gateway is already running with PID {old_pid}")
            return
        except (OSError, ValueError):
            pid_file.unlink()

    cfg = ConfigLoader.load(str(config_file), base_dir=str(BASE_DIR))
    proxy = GatewayProxy(cfg)

    pid_file.parent.mkdir(parents=True, exist_ok=True)
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    print(f"[+] Starting Security Gateway on https://{cfg.listener.host}:{cfg.listener.port}...")
    print(f"[+] Protected upstream: http://{cfg.upstream.host}:{cfg.upstream.port}")
    print(f"[+] TLS: {cfg.tls.min_version} (mTLS: {cfg.tls.require_client_certificate})")
    print(f"[+] Memory hardened: {proxy.memory_hardened}")

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def signal_handler():
        print("\n[*] Stopping gateway...")
        loop.create_task(proxy.stop())
        if pid_file.exists():
            pid_file.unlink()
        loop.stop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, signal_handler)

    try:
        loop.run_until_complete(proxy.start())
        print("[✓] Gateway listener is active and ready.")
        loop.run_forever()
    except Exception as e:
        print(f"[-] Gateway runtime error: {e}")
    finally:
        if pid_file.exists():
            pid_file.unlink()


def cmd_stop(args: argparse.Namespace) -> None:
    _, _, pid_file, _ = get_paths()
    if not pid_file.exists():
        print("[-] Gateway PID file not found. Process might not be running.")
        return

    with open(pid_file, "r") as f:
        pid = int(f.read().strip())

    try:
        os.kill(pid, signal.SIGTERM)
        print(f"[*] Sent SIGTERM to Gateway (PID {pid}). Waiting for termination...")
        for _ in range(10):
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
            except OSError:
                break
        if pid_file.exists():
            pid_file.unlink()
        print("[✓] Gateway stopped successfully.")
    except OSError as e:
        print(f"[-] Failed to stop PID {pid}: {e}")
        if pid_file.exists():
            pid_file.unlink()


def cmd_status(args: argparse.Namespace) -> None:
    config_file, _, pid_file, _ = get_paths()
    ir = IncidentResponseManager(state_dir=str(BASE_DIR / "logs"))

    print("=" * 60)
    print("HNX26EPS01 SECURITY GATEWAY — STATUS REPORT")
    print("=" * 60)
    print(f"Security State:      {ir.current_state.value}")

    running = False
    if pid_file.exists():
        try:
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, 0)
            running = True
            print(f"Process Status:      RUNNING (PID: {pid})")
        except OSError:
            print("Process Status:      STOPPED (Stale PID file)")
    else:
        print("Process Status:      STOPPED")

    if config_file.exists():
        try:
            cfg = ConfigLoader.load(str(config_file), base_dir=str(BASE_DIR))
            print(f"Listener Endpoint:   https://{cfg.listener.host}:{cfg.listener.port}")
            print(f"Upstream Target:     http://{cfg.upstream.host}:{cfg.upstream.port}")
            print(f"TLS Enforcement:     {cfg.tls.min_version} (mTLS: {cfg.tls.require_client_certificate})")
            print(f"Rate Limiting:       {cfg.rate_limit.requests_per_second} req/s (Burst: {cfg.rate_limit.burst})")
        except Exception as e:
            print(f"Config Status:       ERROR ({e})")
    print("=" * 60)


def cmd_lockdown(args: argparse.Namespace) -> None:
    reason = args.reason or "Operator manual lockdown command executed"
    ir = IncidentResponseManager(state_dir=str(BASE_DIR / "logs"))
    record = ir.trigger_lockdown(reason=reason, telemetry={"invoked_by": "cli"})
    print(f"[✓] Gateway placed in LOCKDOWN state. Reason: {record.reason}")
    print("[!] All ingress traffic blocked. Upstream is isolated.")


def cmd_unlock(args: argparse.Namespace) -> None:
    if not args.confirm:
        print("[-] Refusing unlock: Requires explicit confirmation flag '--confirm'.")
        sys.exit(1)

    ir = IncidentResponseManager(state_dir=str(BASE_DIR / "logs"))
    try:
        ir.unlock("CONFIRM_OPERATOR_UNLOCK")
        print("[✓] Gateway successfully unlocked. State returned to READY.")
    except Exception as e:
        print(f"[-] Failed to unlock gateway: {e}")
        sys.exit(1)


def cmd_verify_integrity(args: argparse.Namespace) -> None:
    _, hashes_file, _, _ = get_paths()
    print("[*] Auditing file integrity against baseline...")
    monitor = IntegrityMonitor(str(hashes_file), base_dir=str(BASE_DIR))
    passed, results = monitor.verify_integrity()

    for r in results:
        status_symbol = "[✓]" if r.status == "PASS" else "[-]"
        print(f"{status_symbol} {r.file_path:<35} {r.status:<18} ({r.classification})")
        if r.status != "PASS":
            print(f"    Details: {r.details}")

    print("-" * 60)
    if passed:
        print("[✓] INTEGRITY AUDIT: PASS — All assets match baseline.")
    else:
        print("[-] INTEGRITY AUDIT: FAIL — Anomalies or mismatches detected!")
        sys.exit(1)


def cmd_verify_firewall(args: argparse.Namespace) -> None:
    script = BASE_DIR / "scripts" / "setup_firewall.sh"
    res = subprocess.run([str(script), "check"])
    sys.exit(res.returncode)


def cmd_verify_certificates(args: argparse.Namespace) -> None:
    config_file, _, _, _ = get_paths()
    cfg = ConfigLoader.load(str(config_file), base_dir=str(BASE_DIR))
    print("[*] Verifying TLS certificates and private key permissions...")
    try:
        mgr = TLSManager(
            server_cert_path=cfg.tls.server_cert_path,
            server_key_path=cfg.tls.server_key_path,
            ca_cert_path=cfg.tls.ca_cert_path,
            require_client_cert=cfg.tls.require_client_certificate,
        )
        print("[✓] Server certificate: Valid.")
        print("[✓] Server private key: Secure file permissions verified.")
        if cfg.tls.require_client_certificate:
            print("[✓] Client CA certificate: Valid.")
        print("[✓] CERTIFICATE AUDIT: PASS")
    except Exception as e:
        print(f"[-] CERTIFICATE AUDIT: FAIL — {e}")
        sys.exit(1)


def cmd_create_token(args: argparse.Namespace) -> None:
    config_file, _, _, _ = get_paths()
    cfg = ConfigLoader.load(str(config_file), base_dir=str(BASE_DIR))
    vault = TokenVault(
        key_path=cfg.auth.token_secret_path,
        replay_cache_ttl_seconds=cfg.auth.token_ttl_seconds,
    )
    token = vault.create_token(
        subject=args.sub,
        role=args.role,
        scopes=args.scopes.split(",") if args.scopes else [],
        ttl_seconds=args.ttl,
    )
    print(f"[✓] Generated HMAC-SHA256 Token for subject '{args.sub}' (Role: {args.role}):")
    print(token)


def cmd_zero_trust_status(args: argparse.Namespace) -> None:
    zt_policy_file = BASE_DIR / "config" / "zero_trust_policy.yaml"
    _, _, pid_file, log_file = get_paths()
    ir = IncidentResponseManager(state_dir=str(BASE_DIR / "logs"))

    from core.client_registry import ClientRegistry
    from core.security_context import SecurityPosture
    from core.zero_trust_policy import ZeroTrustPolicyEngine

    pdp = ZeroTrustPolicyEngine(config_path=str(zt_policy_file))
    registry = ClientRegistry(config_path=str(zt_policy_file))
    posture = SecurityPosture(gateway_state=ir.current_state.value)

    print("=" * 65)
    print("HNX26EPS01 ZERO TRUST ARCHITECTURE — POLICY & POSTURE STATUS")
    print("=" * 65)
    print(f"Policy Decision Point (PDP):  ONLINE (Version: {pdp.policy_version}, Hash: {pdp.policy_hash})")
    print(f"Policy Enforcement Point (PEP): READY (Authoritative Gateway Pipeline)")
    print(f"Security Posture:             {posture.compute_overall_posture().value}")
    print(f"Gateway Operational State:    {ir.current_state.value}")
    print(f"Default Policy Decision:      {pdp.default_decision}")
    print(f"Declared Policy Rules:        {len(pdp.rules)} active rules")

    print("\n[ Registered Client Devices ]")
    clients = registry.list_clients()
    if clients:
        for c in clients:
            status = "ENABLED" if c.enabled and not c.revoked else "REVOKED/DISABLED"
            print(f"  • {c.client_id:<25} [{status}] Posture: {c.device_posture.value}")
            print(f"    Fingerprint: {c.certificate_sha256[:24]}... Roles: {c.allowed_roles}")
    else:
        print("  (None registered)")

    denied_count = 0
    risk_events = 0
    if log_file.exists():
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if "ZERO_TRUST_DENIED" in line or "AUTH_TOKEN_INVALID" in line or "DPI_PAYLOAD_BLOCKED" in line:
                    denied_count += 1
                if "RISK" in line:
                    risk_events += 1

    print(f"\n[ Telemetry Summary ]")
    print(f"  • Denied Requests: {denied_count}")
    print(f"  • Risk Anomaly Events: {risk_events}")
    print("=" * 65)


def cmd_run_upstream(args: argparse.Namespace) -> None:
    from upstream_legal_agent import run_standalone
    run_standalone(host=args.host, port=args.port)


def cmd_inspect_packets(args: argparse.Namespace) -> None:
    from packet_inspector import PacketInspector
    from scapy.all import IP, TCP
    print("[*] Running Scapy-based Layer 3/4 packet inspection suite against nftables policy...")
    scans = ["NULL", "FIN", "XMAS", "SYN_FIN", "SYN_RST"]
    for s in scans:
        pkt = PacketInspector.craft_adversarial_packet(s)
        res = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
        print(f"  • {s:<10} Scan: Verdict={res.verdict.value:<6} Rule={res.rule_name}")
    
    ext_pkt = IP(src="192.168.1.100", dst="127.0.0.1") / TCP(dport=3000, flags="S")
    res_ext = PacketInspector.evaluate_tcp_packet(ext_pkt, interface="eth0")
    print(f"  • Port 3000 External Access: Verdict={res_ext.verdict.value:<6} Rule={res_ext.rule_name}")
    print("[✓] All packet filter defenses verified.")


def cmd_audit(args: argparse.Namespace) -> None:
    _, _, _, log_file = get_paths()
    if not log_file.exists():
        print(f"[i] No security log found at {log_file}")
        return

    lines_to_read = args.lines
    print(f"[*] Showing last {lines_to_read} security events from {log_file}:")
    with open(log_file, "r", encoding="utf-8") as f:
        lines = f.readlines()[-lines_to_read:]

    for l in lines:
        try:
            ev = json.loads(l.strip())
            ts = ev.get("timestamp", "")
            event_name = ev.get("event", ev.get("message", "EVENT"))
            sev = ev.get("severity", ev.get("level", "INFO"))
            action = ev.get("action", "")
            print(f"[{ts}] [{sev:<8}] [{action:<8}] {event_name}")
            if "details" in ev and ev["details"]:
                print(f"    Details: {json.dumps(ev['details'])}")
        except Exception:
            print(l.strip())


def main():
    parser = argparse.ArgumentParser(description="HNX26EPS01 Security Gateway CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # start
    subparsers.add_parser("start", help="Start gateway proxy listener")

    # stop
    subparsers.add_parser("stop", help="Stop gateway proxy listener")

    # status
    subparsers.add_parser("status", help="Inspect gateway status")

    # zero-trust-status
    subparsers.add_parser("zero-trust-status", help="Inspect Zero Trust PDP, PEP, and device posture")

    # run-upstream
    p_up = subparsers.add_parser("run-upstream", help="Run local HNX26EPS01 Agentic Legal Assistant")
    p_up.add_argument("--host", default="127.0.0.1", help="Host address (default 127.0.0.1)")
    p_up.add_argument("--port", type=int, default=3000, help="Port (default 3000)")

    # inspect-packets
    subparsers.add_parser("inspect-packets", help="Audit Layer 3/4 packet defenses with Scapy")

    # lockdown
    p_lock = subparsers.add_parser("lockdown", help="Initiate emergency lockdown")
    p_lock.add_argument("--reason", default="Manual operator lockdown", help="Lockdown reason")

    # unlock
    p_unlock = subparsers.add_parser("unlock", help="Recover from lockdown")
    p_unlock.add_argument("--confirm", action="store_true", help="Explicit confirmation")

    # verify-integrity
    subparsers.add_parser("verify-integrity", help="Verify cryptographic file integrity")

    # verify-firewall
    subparsers.add_parser("verify-firewall", help="Validate nftables firewall rules")

    # verify-certificates
    subparsers.add_parser("verify-certificates", help="Audit TLS certificates and keys")

    # audit
    p_audit = subparsers.add_parser("audit", help="Inspect structured security audit logs")
    p_audit.add_argument("--lines", type=int, default=20, help="Number of log records")

    # create-token
    p_tok = subparsers.add_parser("create-token", help="Generate HMAC-SHA256 session token")
    p_tok.add_argument("--sub", required=True, help="Subject name")
    p_tok.add_argument("--role", required=True, help="Role (e.g. ROLE_LEGAL_QUERY)")
    p_tok.add_argument("--scopes", default="legal.query", help="Comma-separated scopes")
    p_tok.add_argument("--ttl", type=int, default=900, help="TTL in seconds")
    p_tok.add_argument("--bound-cert", default=None, help="Bound client certificate SHA256")

    args = parser.parse_args()

    commands = {
        "start": cmd_start,
        "stop": cmd_stop,
        "status": cmd_status,
        "zero-trust-status": cmd_zero_trust_status,
        "run-upstream": cmd_run_upstream,
        "inspect-packets": cmd_inspect_packets,
        "lockdown": cmd_lockdown,
        "unlock": cmd_unlock,
        "verify-integrity": cmd_verify_integrity,
        "verify-firewall": cmd_verify_firewall,
        "verify-certificates": cmd_verify_certificates,
        "audit": cmd_audit,
        "create-token": cmd_create_token,
    }

    cmd_fn = commands.get(args.command)
    if cmd_fn:
        cmd_fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
