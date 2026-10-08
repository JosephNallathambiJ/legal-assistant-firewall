"""NetfilterQueue (NFQUEUE) Kernel Packet Filter Bridge for HNX26EPS01.

Provides userspace deep packet inspection integration with Linux Netfilter / nftables.
When nftables forwards packets to NFQUEUE via:
    nft add rule inet security_gateway input queue num 0
This bridge inspects IP/TCP packets with Scapy, enforcing anti-reconnaissance drops,
loopback isolation, and Zero Trust packet telemetry.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional

try:
    from netfilterqueue import NetfilterQueue  # type: ignore
    NFQUEUE_AVAILABLE = True
except (ImportError, OSError):
    NFQUEUE_AVAILABLE = False

from scapy.all import IP  # type: ignore
try:
    from security_gateway.packet_inspector import PacketInspector, PacketVerdict
except ImportError:
    from packet_inspector import PacketInspector, PacketVerdict


logger = logging.getLogger("security_gateway.nfqueue")


class NFQueuePacketFilter:
    """Bridges Linux NetfilterQueue to the HNX26EPS01 PacketInspector."""

    def __init__(self, queue_num: int = 0, on_verdict: Optional[Callable[[str, str], None]] = None):
        self.queue_num = queue_num
        self.on_verdict = on_verdict
        self._nfqueue: Optional[NetfilterQueue] = None
        self._running = False

    def handle_packet_payload(self, raw_bytes: bytes, interface: str = "lo") -> PacketVerdict:
        """Inspects raw packet payload bytes using Scapy and returns a verdict."""
        try:
            packet = IP(raw_bytes)
            audit = PacketInspector.evaluate_tcp_packet(packet, interface=interface)
            if self.on_verdict:
                self.on_verdict(audit.verdict.value, audit.reason)
            return audit.verdict
        except Exception as exc:
            logger.warning(f"Error inspecting packet payload: {exc}. Failing closed (DROP).")
            return PacketVerdict.DROP

    def _packet_callback(self, pkt):
        """NetfilterQueue callback for live kernel packet queues."""
        try:
            payload = pkt.get_payload()
            verdict = self.handle_packet_payload(payload, interface="lo")
            if verdict == PacketVerdict.ACCEPT:
                pkt.accept()
            else:
                pkt.drop()
        except Exception as exc:
            logger.error(f"NFQueue processing error: {exc}. Dropping packet.")
            pkt.drop()

    def run(self):
        """Binds to live NetfilterQueue and runs the packet processing loop."""
        if not NFQUEUE_AVAILABLE:
            raise RuntimeError("netfilterqueue C library/module is not available.")
        self._nfqueue = NetfilterQueue()
        try:
            self._nfqueue.bind(self.queue_num, self._packet_callback)
            self._running = True
            logger.info(f"NetfilterQueue bound to queue num {self.queue_num}. Running...")
            self._nfqueue.run()
        except KeyboardInterrupt:
            logger.info("NFQueue interrupted by user.")
        finally:
            if self._nfqueue:
                self._nfqueue.unbind()
            self._running = False
