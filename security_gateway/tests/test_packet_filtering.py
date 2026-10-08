"""Tests for Scapy Packet Inspector & NetfilterQueue Packet Filter.

Verifies that Layer 3/4 packet policies strictly match nftables firewall specifications:
- Reconnaissance flag scans (NULL, FIN, XMAS, SYN-FIN, SYN-RST) are dropped.
- External interface access to upstream port 3000 is dropped.
- Legitimate traffic to port 8443 and loopback upstream traffic is accepted.
"""

from __future__ import annotations

from pathlib import Path
import sys

BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))

from scapy.all import IP, TCP, Raw  # type: ignore

from packet_inspector import PacketInspector, PacketVerdict
from nfqueue_filter import NFQueuePacketFilter


def test_null_scan_packet_dropped():
    pkt = PacketInspector.craft_adversarial_packet("NULL")
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
    assert audit.verdict == PacketVerdict.DROP
    assert audit.rule_name == "NFT_DROP_NULL_SCAN"


def test_fin_scan_packet_dropped():
    pkt = PacketInspector.craft_adversarial_packet("FIN")
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
    assert audit.verdict == PacketVerdict.DROP
    assert audit.rule_name == "NFT_DROP_FIN_SCAN"


def test_xmas_scan_packet_dropped():
    pkt = PacketInspector.craft_adversarial_packet("XMAS")
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
    assert audit.verdict == PacketVerdict.DROP
    assert audit.rule_name == "NFT_DROP_XMAS_SCAN"


def test_syn_fin_scan_packet_dropped():
    pkt = PacketInspector.craft_adversarial_packet("SYN_FIN")
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
    assert audit.verdict == PacketVerdict.DROP
    assert audit.rule_name == "NFT_DROP_SYN_FIN_SCAN"


def test_syn_rst_scan_packet_dropped():
    pkt = PacketInspector.craft_adversarial_packet("SYN_RST")
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
    assert audit.verdict == PacketVerdict.DROP
    assert audit.rule_name == "NFT_DROP_SYN_RST_SCAN"


def test_external_port_3000_isolation_dropped():
    pkt = IP(src="192.168.1.50", dst="127.0.0.1") / TCP(dport=3000, flags="S")
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
    assert audit.verdict == PacketVerdict.DROP
    assert audit.rule_name == "NFT_ISOLATE_PORT_3000"


def test_loopback_port_3000_accepted():
    pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(dport=3000, flags="S")
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="lo")
    assert audit.verdict == PacketVerdict.ACCEPT
    assert audit.rule_name == "NFT_ACCEPT_LOOPBACK_UPSTREAM"


def test_gateway_inbound_port_8443_accepted():
    pkt = PacketInspector.craft_adversarial_packet("VALID_SYN", dport=8443)
    audit = PacketInspector.evaluate_tcp_packet(pkt, interface="eth0")
    assert audit.verdict == PacketVerdict.ACCEPT
    assert audit.rule_name == "NFT_ACCEPT_GATEWAY_TLS"


def test_nfqueue_filter_payload_processing():
    filter_bridge = NFQueuePacketFilter(queue_num=0)
    
    # Test valid packet payload
    valid_pkt = IP(src="127.0.0.1", dst="127.0.0.1") / TCP(dport=8443, flags="S")
    raw_valid = bytes(valid_pkt)
    verdict_valid = filter_bridge.handle_packet_payload(raw_valid, interface="eth0")
    assert verdict_valid == PacketVerdict.ACCEPT

    # Test malicious XMAS payload
    xmas_pkt = IP(src="10.0.0.1", dst="127.0.0.1") / TCP(dport=8443, flags="FPU")
    raw_xmas = bytes(xmas_pkt)
    verdict_xmas = filter_bridge.handle_packet_payload(raw_xmas, interface="eth0")
    assert verdict_xmas == PacketVerdict.DROP
