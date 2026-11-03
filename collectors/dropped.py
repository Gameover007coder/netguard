"""
dropped.py – Firewall-drop log collector.

Tails `journalctl -k -f` looking for lines prefixed with "FW-DROP-IN:"
and parses the nftables log fields into structured dicts.
"""

import logging
import re
import subprocess
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("netguard.dropped")

# nftables log format:  FW-DROP-IN: IN=enp0s3 OUT= SRC=192.168.1.50 DST=...
_RE_FIELD = re.compile(r"(\w+)=([\S]*)")

# Ring buffer of recent drops (last 500)
_MAX_HISTORY = 500
_drops: deque[dict[str, Any]] = deque(maxlen=_MAX_HISTORY)
_lock = threading.Lock()
_running = False


def _parse_drop_line(line: str) -> dict[str, Any] | None:
    """Parse a single kernel log line into a drop record."""
    if "FW-DROP-IN:" not in line:
        return None

    fields: dict[str, str] = {}
    for m in _RE_FIELD.finditer(line):
        fields[m.group(1)] = m.group(2)

    if "SRC" not in fields:
        return None

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_ip":    fields.get("SRC", ""),
        "dst_ip":    fields.get("DST", ""),
        "proto":     fields.get("PROTO", ""),
        "src_port":  int(fields.get("SPT", 0)),
        "dst_port":  int(fields.get("DPT", 0)),
        "in_iface":  fields.get("IN", ""),
        "ttl":       int(fields.get("TTL", 0)),
        "length":    int(fields.get("LEN", 0)),
    }


def _tail_journal():
    """Background thread: tail the kernel journal for drop logs."""
    global _running
    _running = True
    logger.info("Starting journal tail for FW-DROP-IN logs")

    try:
        proc = subprocess.Popen(
            ["journalctl", "-k", "-f", "--no-pager", "-o", "short-unix"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        while _running and proc.poll() is None:
            line = proc.stdout.readline()
            if not line:
                continue
            record = _parse_drop_line(line)
            if record:
                with _lock:
                    _drops.append(record)
    except FileNotFoundError:
        logger.warning("journalctl not found – drop collector disabled")
    except Exception:
        logger.exception("Journal tail crashed")
    finally:
        _running = False


_thread: threading.Thread | None = None


def start():
    """Start the background journal tailer (idempotent)."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return
    _thread = threading.Thread(target=_tail_journal, daemon=True, name="drop-tail")
    _thread.start()


def stop():
    """Signal the tailer to stop."""
    global _running
    _running = False


def recent(n: int = 50) -> list[dict[str, Any]]:
    """Return the *n* most recent drop records (newest first)."""
    with _lock:
        items = list(_drops)
    return list(reversed(items[-n:]))


def top_attackers(n: int = 10) -> list[dict[str, Any]]:
    """Return top-N source IPs by drop count."""
    from collections import Counter
    with _lock:
        counts = Counter(d["src_ip"] for d in _drops)
    return [{"ip": ip, "count": c} for ip, c in counts.most_common(n)]


def top_ports(n: int = 10) -> list[dict[str, Any]]:
    """Return top-N targeted destination ports."""
    from collections import Counter
    with _lock:
        counts = Counter(d["dst_port"] for d in _drops if d["dst_port"])
    return [{"port": p, "count": c} for p, c in counts.most_common(n)]

