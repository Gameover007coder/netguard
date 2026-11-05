"""
app.py – NetGuard Dashboard Backend

Flask-SocketIO server that:
  • Pushes real-time connection, traffic, and drop data over WebSocket
  • Exposes REST endpoints for blocking/unblocking IPs
  • Stores block/unblock history in SQLite
"""

import ipaddress
import json
import logging
import os
from urllib.parse import urlparse
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, render_template, request, jsonify, abort
from flask_socketio import SocketIO

from collectors import connections, dropped, dns_sniffer, traffic, geo

# ── Logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("netguard")

# ── Flask + SocketIO ───────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
socketio = SocketIO(app, async_mode="eventlet", cors_allowed_origins=[])

# ── SQLite (history) ───────────────────────────────────────────────
DB_PATH = Path(__file__).parent / "netguard.db"


def _init_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS block_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            action    TEXT    NOT NULL,   -- 'block' or 'unblock'
            ip        TEXT    NOT NULL,
            success   INTEGER NOT NULL DEFAULT 1,
            error     TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS traffic_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT    NOT NULL,
            rx_bps    REAL,
            tx_bps    REAL
        )
    """)
    conn.commit()
    conn.close()


_init_db()


def _db_log_action(action: str, ip: str, success: bool, error: str = ""):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "INSERT INTO block_log (timestamp, action, ip, success, error) VALUES (?, ?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), action, ip, int(success), error),
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Failed to log to DB")


def _db_log_traffic(rx: float, tx: float):
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.execute(
            "INSERT INTO traffic_history (timestamp, rx_bps, tx_bps) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), rx, tx),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ── IP validation ──────────────────────────────────────────────────
def _validate_ip(ip_str: str) -> str | None:
    """Return a normalized IP string, or None if invalid."""
    try:
        if not isinstance(ip_str, str):
            return None
        addr = ipaddress.ip_address(ip_str.strip())
        # Private LAN addresses remain blockable; reject special-purpose targets.
        if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
            return None
        return str(addr)
    except ValueError:
        return None


# ── nft helpers ────────────────────────────────────────────────────
def _nft_block(ip: str) -> tuple[bool, str]:
    """Add an IP to the nftables blocklist set."""
    ip_obj = ipaddress.ip_address(ip)
    set_name = "blocklist_v6" if ip_obj.version == 6 else "blocklist_v4"
    cmd = ["nft", "add", "element", "inet", "myfw", set_name, "{", ip, "}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)


def _nft_unblock(ip: str) -> tuple[bool, str]:
    """Remove an IP from the nftables blocklist set."""
    ip_obj = ipaddress.ip_address(ip)
    set_name = "blocklist_v6" if ip_obj.version == 6 else "blocklist_v4"
    cmd = ["nft", "delete", "element", "inet", "myfw", set_name, "{", ip, "}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            return True, ""
        return False, result.stderr.strip()
    except Exception as e:
        return False, str(e)


def _nft_list_blocked() -> list[str]:
    """List all IPs in the blocklist sets."""
    blocked: list[str] = []
    for set_name in ("blocklist_v4", "blocklist_v6"):
        try:
            result = subprocess.run(
                ["nft", "-j", "list", "set", "inet", "myfw", set_name],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                for item in data.get("nftables", []):
                    s = item.get("set", {})
                    for elem in s.get("elem", []):
                        if isinstance(elem, str):
                            blocked.append(elem)
                        elif isinstance(elem, dict) and "elem" in elem:
                            blocked.append(str(elem["elem"].get("val", "")))
        except Exception:
            pass
    return blocked


# ── Local-only control protection ─────────────────────────────────
@app.before_request
def protect_control_api():
    if request.path in {'/api/block', '/api/unblock'} and request.method == 'POST':
        origin = request.headers.get('Origin')
        if origin:
            try:
                origin_host = (urlparse(origin).hostname or '').lower()
            except ValueError:
                abort(403)
            if origin_host not in {'127.0.0.1', 'localhost', '::1'}:
                abort(403)
        if request.headers.get('Sec-Fetch-Site') == 'cross-site':
            abort(403)


# ── Routes ─────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/connections")
def api_connections():
    dns_cache = dns_sniffer.get_cache()
    conns = connections.collect(dns_cache)
    # Enrich with geo
    for c in conns:
        c["geo"] = geo.lookup(c["remote_ip"])
    return jsonify(conns)


@app.route("/api/listening")
def api_listening():
    return jsonify(connections.listening_ports())


@app.route("/api/traffic")
def api_traffic():
    return jsonify(traffic.get_rates())


@app.route("/api/drops")
def api_drops():
    return jsonify({
        "recent":    dropped.recent(50),
        "attackers": dropped.top_attackers(10),
        "ports":     dropped.top_ports(10),
    })


@app.route("/api/blocked")
def api_blocked():
    return jsonify(_nft_list_blocked())


@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"ok": False, "error": "Expected a JSON object"}), 400
    raw_ip = data.get("ip", "")
    ip = _validate_ip(raw_ip)
    if ip is None:
        return jsonify({"ok": False, "error": "Invalid IP address"}), 400

    ok, err = _nft_block(ip)
    _db_log_action("block", ip, ok, err)
    if ok:
        socketio.emit("blocked_update", {"blocked": _nft_list_blocked()})
        return jsonify({"ok": True, "ip": ip})
    return jsonify({"ok": False, "error": err}), 500


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(silent=True) or {}
    raw_ip = data.get("ip", "")
    ip = _validate_ip(raw_ip)
    if ip is None:
        return jsonify({"ok": False, "error": "Invalid IP address"}), 400

    ok, err = _nft_unblock(ip)
    _db_log_action("unblock", ip, ok, err)
    if ok:
        socketio.emit("blocked_update", {"blocked": _nft_list_blocked()})
        return jsonify({"ok": True, "ip": ip})
    return jsonify({"ok": False, "error": err}), 500


@app.route("/api/history")
def api_history():
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM block_log ORDER BY id DESC LIMIT 100"
        ).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── WebSocket push loop ────────────────────────────────────────────
def _push_loop():
    """Background thread that emits fresh data every 2 seconds."""
    logger.info("WebSocket push loop started")
    while True:
        try:
            # Sample traffic
            rates = traffic.sample()
            totals = traffic.totals()
            _db_log_traffic(totals["rx_bps"], totals["tx_bps"])

            # Connections
            dns_cache = dns_sniffer.get_cache()
            conns = connections.collect(dns_cache)
            for c in conns:
                c["geo"] = geo.lookup(c["remote_ip"])

            # Drops
            recent_drops = dropped.recent(20)
            for d in recent_drops:
                d["geo"] = geo.lookup(d["src_ip"])

            # Listening ports
            listeners = connections.listening_ports()

            socketio.emit("update", {
                "timestamp":   datetime.now(timezone.utc).isoformat(),
                "traffic":     rates,
                "totals":      totals,
                "connections": conns,
                "drops":       recent_drops,
                "attackers":   dropped.top_attackers(10),
                "top_ports":   dropped.top_ports(10),
                "listening":   listeners,
            })
        except Exception:
            logger.exception("Error in push loop")

        socketio.sleep(2)


# ── Startup ────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    logger.info("Client connected: %s", request.sid)


def main():
    host = os.environ.get("NETGUARD_HOST", "127.0.0.1")
    port = int(os.environ.get("NETGUARD_PORT", "5000"))

    # Initialize subsystems
    geo.init()
    dropped.start()
    dns_sniffer.start()

    # Start the push loop as a SocketIO background task
    socketio.start_background_task(_push_loop)

    logger.info("NetGuard starting on http://%s:%d", host, port)
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()

