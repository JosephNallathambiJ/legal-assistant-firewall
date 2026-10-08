"""Packet Inspector & Network Security Verification Engine for HNX26EPS01.

Leverages Scapy to audit Layer 3/4 packet conformance against nftables firewall
specifications, detecting adversarial reconnaissance patterns (NULL, FIN, XMAS,
SYN-FIN, SYN-RST scans) and verifying strict loopback port 3000 isolation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from scapy.all import IP, TCP, Raw, conf  # type: ignore

# Suppress Scapy verbose runtime warnings
conf.verb = 0


class PacketVerdict(str, Enum):
    ACCEPT = "ACCEPT"
    DROP = "DROP"


@dataclass(frozen=True)
class PacketAuditResult:
    verdict: PacketVerdict
    rule_name: str
    reason: str
    details: Dict[str, Any]


class PacketInspector:
    """Evaluates raw network packets against HNX26EPS01 Layer 3/4 nftables defensive rules."""

    GATEWAY_PORT: int = 8443
    UPSTREAM_PORT: int = 3000

    @classmethod
    def evaluate_tcp_packet(
        cls,
        packet: IP,
        interface: str = "eth0",
    ) -> PacketAuditResult:
        """Evaluates an IPv4/TCP packet against nftables policy.

        Returns an audit result with ACCEPT or DROP verdict.
        """
        if not packet.haslayer(TCP):
            return PacketAuditResult(
                verdict=PacketVerdict.ACCEPT,
                rule_name="NON_TCP_PASS",
                reason="Packet is not TCP",
                details={},
            )

        tcp = packet[TCP]
        src_ip = packet.src
        dst_ip = packet.dst
        dport = tcp.dport
        flags = int(tcp.flags)

        # 1. Critical Loopback Isolation: Port 3000 MUST NOT be reached from non-lo
        if dport == cls.UPSTREAM_PORT:
            if interface != "lo" or src_ip != "127.0.0.1" or dst_ip != "127.0.0.1":
                return PacketAuditResult(
                    verdict=PacketVerdict.DROP,
                    rule_name="NFT_ISOLATE_PORT_3000",
                    reason="External interface or non-loopback IP targeting isolated upstream port 3000",
                    details={"interface": interface, "src_ip": src_ip, "dport": dport},
                )

        # 2. Reconnaissance Defense: Malformed TCP Flag Scans
        # TCP flag bitmasks: FIN=0x01, SYN=0x02, RST=0x04, PSH=0x08, ACK=0x10, URG=0x20
        # 0x3F = 63 (all 6 standard flags)

        # NULL Scan (No flags set)
        if (flags & 0x3F) == 0:
            return PacketAuditResult(
                verdict=PacketVerdict.DROP,
                rule_name="NFT_DROP_NULL_SCAN",
                reason="Adversarial TCP NULL scan detected (no flags set)",
                details={"flags": hex(flags)},
            )

        # FIN Scan (Only FIN flag set)
        if (flags & 0x3F) == 0x01:
            return PacketAuditResult(
                verdict=PacketVerdict.DROP,
                rule_name="NFT_DROP_FIN_SCAN",
                reason="Adversarial TCP FIN scan detected",
                details={"flags": hex(flags)},
            )

        # XMAS Scan (FIN, PSH, and URG flags set = 0x29)
        if (flags & 0x3F) == 0x29 or (flags & 0x29) == 0x29:
            return PacketAuditResult(
                verdict=PacketVerdict.DROP,
                rule_name="NFT_DROP_XMAS_SCAN",
                reason="Adversarial TCP XMAS scan detected (FIN+PSH+URG set)",
                details={"flags": hex(flags)},
            )

        # SYN-FIN Scan (SYN and FIN set together = 0x03)
        if (flags & 0x03) == 0x03:
            return PacketAuditResult(
                verdict=PacketVerdict.DROP,
                rule_name="NFT_DROP_SYN_FIN_SCAN",
                reason="Adversarial TCP SYN-FIN scan detected (illegal combination)",
                details={"flags": hex(flags)},
            )

        # SYN-RST Scan (SYN and RST set together = 0x06)
        if (flags & 0x06) == 0x06:
            return PacketAuditResult(
                verdict=PacketVerdict.DROP,
                rule_name="NFT_DROP_SYN_RST_SCAN",
                reason="Adversarial TCP SYN-RST scan detected (illegal combination)",
                details={"flags": hex(flags)},
            )

        # 3. Gateway Inbound Port Acceptance
        if dport == cls.GATEWAY_PORT:
            return PacketAuditResult(
                verdict=PacketVerdict.ACCEPT,
                rule_name="NFT_ACCEPT_GATEWAY_TLS",
                reason="Legitimate packet directed to Security Gateway TLS listener",
                details={"dport": dport, "src_ip": src_ip},
            )

        if dport == cls.UPSTREAM_PORT and interface == "lo":
            return PacketAuditResult(
                verdict=PacketVerdict.ACCEPT,
                rule_name="NFT_ACCEPT_LOOPBACK_UPSTREAM",
                reason="Legitimate loopback packet to upstream legal assistant",
                details={"dport": dport, "src_ip": src_ip},
            )

        # Default Deny for unmapped ports
        return PacketAuditResult(
            verdict=PacketVerdict.DROP,
            rule_name="NFT_DEFAULT_DENY",
            reason=f"Default deny: Unsolicited traffic targeting port {dport}",
            details={"dport": dport, "src_ip": src_ip},
        )

    @classmethod
    def craft_adversarial_packet(
        cls,
        scan_type: str,
        dst_ip: str = "127.0.0.1",
        dport: int = 8443,
    ) -> IP:
        """Utility to craft Scapy packets for firewall test suites."""
        scan_type = scan_type.upper()
        if scan_type == "NULL":
            return IP(dst=dst_ip) / TCP(dport=dport, flags=0)
        elif scan_type == "FIN":
            return IP(dst=dst_ip) / TCP(dport=dport, flags="F")
        elif scan_type == "XMAS":
            return IP(dst=dst_ip) / TCP(dport=dport, flags="FPU")
        elif scan_type == "SYN_FIN":
            return IP(dst=dst_ip) / TCP(dport=dport, flags="SF")
        elif scan_type == "SYN_RST":
            return IP(dst=dst_ip) / TCP(dport=dport, flags="SR")
        elif scan_type == "VALID_SYN":
            return IP(dst=dst_ip) / TCP(dport=dport, flags="S")
        else:
            raise ValueError(f"Unknown scan type: {scan_type}")
