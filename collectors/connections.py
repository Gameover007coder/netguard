"""
connections.py – Active connection collector.

Uses psutil to enumerate network connections every cycle, enriching each
with process name, PID, and (when available) the domain resolved by the
DNS sniffer.
"""

import logging
import socket
from typing import Any

import psutil

logger = logging.getLogger("netguard.connections")

# Well-known port labels
_PORT_LABELS = {
    22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}


def _port_label(port: int) -> str:
    return _PORT_LABELS.get(port, str(port))


def _safe_process_name(pid: int | None) -> str:
    if pid is None or pid == 0:
        return "kernel"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return f"pid:{pid}"


def collect(dns_cache: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Return a list of dicts describing every current TCP/UDP connection."""
    dns_cache = dns_cache or {}
    results: list[dict[str, Any]] = []

    for conn in psutil.net_connections(kind="inet"):
        # Skip listeners (no remote address)
        if not conn.raddr:
            continue

        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        local_port = conn.laddr.port if conn.laddr else 0

        # Try the DNS cache first, then a quick reverse lookup
        domain = dns_cache.get(remote_ip)
        if domain is None:
            try:
                domain = socket.getfqdn(remote_ip)
                if domain == remote_ip:
                    domain = ""
            except Exception:
                domain = ""

        results.append({
            "proto":      "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "local_port": local_port,
            "remote_ip":  remote_ip,
            "remote_port": remote_port,
            "port_label": _port_label(remote_port),
            "state":      conn.status if hasattr(conn, "status") else "",
            "pid":        conn.pid,
            "process":    _safe_process_name(conn.pid),
            "domain":     domain,
        })

    return results


def listening_ports() -> list[dict[str, Any]]:
    """Return a list of ports this machine is listening on."""
    results: list[dict[str, Any]] = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == "LISTEN":
            results.append({
                "proto":     "TCP",
                "port":      conn.laddr.port,
                "label":     _port_label(conn.laddr.port),
                "address":   conn.laddr.ip,
                "pid":       conn.pid,
                "process":   _safe_process_name(conn.pid),
            })
    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        key = (r["address"], r["port"], r["pid"])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique

