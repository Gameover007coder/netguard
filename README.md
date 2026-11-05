# NetGuard – Firewall & Live Traffic Dashboard

A real-time firewall monitoring and control dashboard for Ubuntu/Debian.  
Combines **nftables** packet filtering with a **Flask-SocketIO** web dashboard that shows live bandwidth, active connections, blocked inbound attempts, and lets you block/unblock IPs from the browser.

## Quick Start

```bash
# On your Ubuntu machine:
git clone <this-repo> netguard && cd netguard
sudo bash install.sh
```

Then open **http://127.0.0.1:5000** in your browser.

## Architecture

```
 Kernel (netfilter)          Collectors (Python)            Dashboard
┌─────────────────┐        ┌──────────────────────┐      ┌────────────────┐
│ nftables rules  │──log──▶│ journalctl -k (drops)│      │ Flask/SocketIO │
│ conntrack table │──────▶ │ conntrack / psutil   │─────▶│ + WebSocket    │──▶ Browser
│ /proc/net/dev   │──────▶ │ scapy (DNS/SNI)      │      │ Chart.js UI    │   localhost:5000
└─────────────────┘        └──────────────────────┘      └────────────────┘
        ▲                                                         │
        └──────────── block/unblock IP (nft add element) ◀────────┘
```

## Project Structure

```
netguard/
├── firewall/
│   └── firewall.nft          # nftables ruleset (drop policy, logging, blocklist sets)
├── collectors/
│   ├── __init__.py
│   ├── connections.py         # Active connections via psutil
│   ├── dropped.py             # Dropped packet log parser (journalctl)
│   ├── dns_sniffer.py         # Passive DNS cache via scapy
│   ├── traffic.py             # Bandwidth from /proc/net/dev
│   └── geo.py                 # GeoIP lookups (MaxMind GeoLite2)
├── templates/
│   └── index.html             # Dashboard HTML
├── static/
│   ├── dashboard.js           # Real-time UI logic (Chart.js + Socket.IO)
│   └── style.css              # Dark-themed dashboard styles
├── app.py                     # Flask-SocketIO backend + REST API
├── install.sh                 # One-command installer
├── netguard.service           # systemd unit file
├── requirements.txt           # Python dependencies
└── README.md
```

## Dashboard Panels

| Panel | Description |
|-------|-------------|
| **Live Bandwidth** | Real-time upload/download chart (Chart.js) |
| **Active Connections** | Process, domain, port, country for each connection |
| **Blocked Inbound** | Firewall drops with top attackers and targeted ports |
| **Listening Ports** | All ports your machine exposes |
| **Block/Unblock** | Manual IP blocking with action history |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/connections` | GET | Current active connections |
| `/api/listening` | GET | Listening ports |
| `/api/traffic` | GET | Per-interface bandwidth rates |
| `/api/drops` | GET | Recent drops, top attackers, top ports |
| `/api/blocked` | GET | Currently blocked IPs |
| `/api/block` | POST | Block an IP `{"ip": "1.2.3.4"}` |
| `/api/unblock` | POST | Unblock an IP `{"ip": "1.2.3.4"}` |
| `/api/history` | GET | Block/unblock action log |

## Management

```bash
# Service control
sudo systemctl status netguard
sudo systemctl restart netguard
sudo journalctl -u netguard -f

# Firewall inspection
sudo nft list ruleset
sudo nft list set inet myfw blocklist_v4

# Uninstall
sudo systemctl stop netguard
sudo systemctl disable netguard
sudo rm -rf /opt/netguard /etc/systemd/system/netguard.service
sudo nft flush ruleset
```

## Security Notes

- Dashboard binds to **127.0.0.1 only** – not accessible from the network
- IP inputs are validated with Python's `ipaddress` module (no shell injection)
- nft commands use argument lists, never shell strings
- All data stays on your machine (SQLite database in `/opt/netguard/`)

## Optional: GeoIP

Download the free [GeoLite2-City database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) and place `GeoLite2-City.mmdb` in `/usr/share/GeoIP/` or `/opt/netguard/`.

## Testing

```bash
# From another machine – should appear as blocked drops
sudo nmap -sS <your-ip>

# From this machine – should appear as outbound connection
curl https://example.com
```

## License

MIT
