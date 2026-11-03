"""
traffic.py – Interface bandwidth collector.

Reads /proc/net/dev at regular intervals and calculates bytes-per-second
for each network interface.  Also provides aggregate totals.
"""

import logging
import time
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("netguard.traffic")

_PROC_NET_DEV = Path("/proc/net/dev")

_prev_stats: dict[str, dict[str, int]] = {}
_prev_time: float = 0.0
_current_rates: dict[str, dict[str, float]] = {}
_lock = threading.Lock()


def _read_proc_net_dev() -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev and return {iface: {rx_bytes, tx_bytes, ...}}."""
    result: dict[str, dict[str, int]] = {}
    try:
        lines = _PROC_NET_DEV.read_text().splitlines()
    except FileNotFoundError:
        return result

    for line in lines[2:]:  # skip header lines
        parts = line.split()
        if len(parts) < 17:
            continue
        iface = parts[0].rstrip(":")
        if iface == "lo":
            continue
        result[iface] = {
            "rx_bytes":   int(parts[1]),
            "rx_packets": int(parts[2]),
            "rx_errors":  int(parts[3]),
            "tx_bytes":   int(parts[9]),
            "tx_packets": int(parts[10]),
            "tx_errors":  int(parts[11]),
        }
    return result


def sample() -> dict[str, dict[str, float]]:
    """
    Take a sample from /proc/net/dev and calculate per-interface rates.
    Call this periodically (e.g. every 1-2 seconds).  Returns the computed
    rates dict: {iface: {rx_bps, tx_bps, rx_pps, tx_pps}}.
    """
    global _prev_stats, _prev_time, _current_rates

    now = time.monotonic()
    stats = _read_proc_net_dev()

    if _prev_stats and _prev_time:
        dt = now - _prev_time
        if dt > 0:
            rates: dict[str, dict[str, float]] = {}
            for iface, cur in stats.items():
                prev = _prev_stats.get(iface)
                if prev is None:
                    continue
                rates[iface] = {
                    "rx_bps": (cur["rx_bytes"]   - prev["rx_bytes"])   / dt,
                    "tx_bps": (cur["tx_bytes"]   - prev["tx_bytes"])   / dt,
                    "rx_pps": (cur["rx_packets"] - prev["rx_packets"]) / dt,
                    "tx_pps": (cur["tx_packets"] - prev["tx_packets"]) / dt,
                }
            with _lock:
                _current_rates = rates

    _prev_stats = stats
    _prev_time = now

    with _lock:
        return dict(_current_rates)


def get_rates() -> dict[str, dict[str, float]]:
    """Return the most recently computed rates without sampling."""
    with _lock:
        return dict(_current_rates)


def totals() -> dict[str, float]:
    """Aggregate rx/tx across all interfaces."""
    with _lock:
        rates = dict(_current_rates)
    rx = sum(r.get("rx_bps", 0) for r in rates.values())
    tx = sum(r.get("tx_bps", 0) for r in rates.values())
    return {"rx_bps": rx, "tx_bps": tx}


def interfaces_snapshot() -> list[dict[str, Any]]:
    """Return current absolute counters per interface."""
    stats = _read_proc_net_dev()
    with _lock:
        rates = dict(_current_rates)
    result = []
    for iface, s in stats.items():
        r = rates.get(iface, {})
        result.append({
            "name":       iface,
            "rx_bytes":   s["rx_bytes"],
            "tx_bytes":   s["tx_bytes"],
            "rx_bps":     r.get("rx_bps", 0),
            "tx_bps":     r.get("tx_bps", 0),
        })
    return result

