"""
dns_sniffer.py – Passive DNS cache built from live DNS replies.

Runs scapy's AsyncSniffer on port 53 to capture A/AAAA answers and
maintains an IP→domain mapping.  Falls back gracefully if scapy or
raw sockets are unavailable.
"""

import logging
import threading
from typing import Any

logger = logging.getLogger("netguard.dns_sniffer")

_dns_cache: dict[str, str] = {}
_lock = threading.Lock()
_sniffer = None


def _process_packet(pkt):
    """Callback for each captured packet."""
    try:
        from scapy.layers.dns import DNSRR, DNS
        if not pkt.haslayer(DNS):
            return
        dns = pkt[DNS]
        if dns.qr != 1:  # only replies
            return

        # Extract the query name
        qname = ""
        if dns.qd:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".")

        # Walk the answer section
        for i in range(dns.ancount):
            rr = dns.an[i] if hasattr(dns.an, '__getitem__') else dns.an
            if not isinstance(rr, DNSRR):
                continue
            if rr.type in (1, 28):  # A or AAAA
                ip = rr.rdata
                name = qname or rr.rrname.decode(errors="ignore").rstrip(".")
                with _lock:
                    _dns_cache[ip] = name
    except Exception:
        pass  # never crash the sniffer thread


def start():
    """Start the background DNS sniffer (needs CAP_NET_RAW or root)."""
    global _sniffer
    try:
        from scapy.sendrecv import AsyncSniffer
        _sniffer = AsyncSniffer(
            filter="udp port 53",
            prn=_process_packet,
            store=False,
        )
        _sniffer.start()
        logger.info("DNS sniffer started")
    except PermissionError:
        logger.warning("DNS sniffer needs root / CAP_NET_RAW – disabled")
    except Exception:
        logger.exception("Failed to start DNS sniffer")


def stop():
    """Stop the background sniffer."""
    global _sniffer
    if _sniffer is not None:
        try:
            _sniffer.stop()
        except Exception:
            pass
        _sniffer = None


def get_cache() -> dict[str, str]:
    """Return a snapshot of the current IP→domain mapping."""
    with _lock:
        return dict(_dns_cache)


def lookup(ip: str) -> str:
    """Look up a single IP, returning domain or empty string."""
    with _lock:
        return _dns_cache.get(ip, "")

