"""
connections.py – Active connection collector.

Uses psutil to enumerate network connections and enriches them with
process metadata and domains learned by the passive DNS sniffer.
"""

import logging
import socket
from typing import Any

import psutil

logger = logging.getLogger("netguard.connections")

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
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return f"pid:{pid}"


def collect(dns_cache: dict[str, str] | None = None) -> list[dict[str, Any]]:
    """Return current TCP/UDP connections without triggering reverse DNS queries."""
    dns_cache = dns_cache or {}
    results: list[dict[str, Any]] = []

    try:
        active_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        logger.warning("Unable to enumerate network connections: %s", exc)
        return results

    for conn in active_connections:
        if not conn.raddr:
            continue

        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        local_port = conn.laddr.port if conn.laddr else 0

        results.append({
            "proto": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
            "local_port": local_port,
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "port_label": _port_label(remote_port),
            "state": conn.status or "",
            "pid": conn.pid,
            "process": _safe_process_name(conn.pid),
            "domain": dns_cache.get(remote_ip, ""),
        })

    return results


def listening_ports() -> list[dict[str, Any]]:
    """Return a deduplicated list of TCP/UDP sockets this machine is listening on."""
    results: list[dict[str, Any]] = []
    try:
        active_connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as exc:
        logger.warning("Unable to enumerate listening ports: %s", exc)
        return results

    for conn in active_connections:
        if conn.status == "LISTEN" and conn.laddr:
            results.append({
                "proto": "TCP",
                "port": conn.laddr.port,
                "label": _port_label(conn.laddr.port),
                "address": conn.laddr.ip,
                "pid": conn.pid,
                "process": _safe_process_name(conn.pid),
            })

    seen = set()
    unique = []
    for item in results:
        key = (item["address"], item["port"], item["pid"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    return unique
