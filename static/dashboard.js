// ── NetGuard Dashboard Client ────────────────────────────────────
"use strict";

const socket = io();
const MAX_BW_POINTS = 120;  // 4 minutes at 2-second intervals

// ── Utility ─────────────────────────────────────────────────────
function fmtBytes(b) {
    if (b < 0) b = 0;
    const units = ["B/s", "KB/s", "MB/s", "GB/s"];
    let i = 0;
    while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
    return b.toFixed(i === 0 ? 0 : 1) + " " + units[i];
}

function fmtTime(iso) {
    if (!iso) return "";
    const d = new Date(iso);
    return d.toLocaleTimeString();
}

function escHtml(s) {
    const el = document.createElement("span");
    el.textContent = s;
    return el.innerHTML;
}

// ── Connection Status ───────────────────────────────────────────
const statusBadge = document.getElementById("conn-status");

socket.on("connect", () => {
    statusBadge.textContent = "Connected";
    statusBadge.className = "badge badge-ok";
});
socket.on("disconnect", () => {
    statusBadge.textContent = "Disconnected";
    statusBadge.className = "badge badge-danger";
});

// ── Bandwidth Chart ─────────────────────────────────────────────
const bwCtx = document.getElementById("bw-chart").getContext("2d");
const bwLabels = [];
const rxData = [];
const txData = [];

const bwChart = new Chart(bwCtx, {
    type: "line",
    data: {
        labels: bwLabels,
        datasets: [
            {
                label: "↓ Download",
                data: rxData,
                borderColor: "#5b8def",
                backgroundColor: "rgba(91, 141, 239, 0.08)",
                fill: true,
                tension: 0.35,
                pointRadius: 0,
                borderWidth: 2,
            },
            {
                label: "↑ Upload",
                data: txData,
                borderColor: "#4ade80",
                backgroundColor: "rgba(74, 222, 128, 0.08)",
                fill: true,
                tension: 0.35,
                pointRadius: 0,
                borderWidth: 2,
            },
        ],
    },
    options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        interaction: { mode: "index", intersect: false },
        scales: {
            x: {
                display: true,
                ticks: { color: "#8b8fa3", maxTicksLimit: 10, font: { size: 10 } },
                grid: { color: "rgba(46,51,72,0.5)" },
            },
            y: {
                beginAtZero: true,
                ticks: {
                    color: "#8b8fa3",
                    font: { size: 10 },
                    callback: v => fmtBytes(v),
                },
                grid: { color: "rgba(46,51,72,0.5)" },
            },
        },
        plugins: {
            legend: { labels: { color: "#e1e4ed", font: { size: 12 } } },
            tooltip: {
                callbacks: {
                    label: ctx => ctx.dataset.label + ": " + fmtBytes(ctx.parsed.y),
                },
            },
        },
    },
});

// ── Attacker Bar Chart ──────────────────────────────────────────
const atkCtx = document.getElementById("attacker-chart").getContext("2d");
const atkChart = new Chart(atkCtx, {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Drops", data: [], backgroundColor: "#f87171" }] },
    options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        scales: {
            x: { ticks: { color: "#8b8fa3" }, grid: { color: "rgba(46,51,72,0.3)" } },
            y: { ticks: { color: "#e1e4ed", font: { family: "'JetBrains Mono', monospace", size: 10 } }, grid: { display: false } },
        },
        plugins: { legend: { display: false } },
    },
});

// ── Port Bar Chart ──────────────────────────────────────────────
const portCtx = document.getElementById("port-chart").getContext("2d");
const portChart = new Chart(portCtx, {
    type: "bar",
    data: { labels: [], datasets: [{ label: "Hits", data: [], backgroundColor: "#fb923c" }] },
    options: {
        indexAxis: "y",
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 400 },
        scales: {
            x: { ticks: { color: "#8b8fa3" }, grid: { color: "rgba(46,51,72,0.3)" } },
            y: { ticks: { color: "#e1e4ed", font: { family: "'JetBrains Mono', monospace", size: 10 } }, grid: { display: false } },
        },
        plugins: { legend: { display: false } },
    },
});

// ── Main Update Handler ─────────────────────────────────────────
let totalDrops = 0;
const seenDropEvents = new Set();

socket.on("update", (data) => {
    const now = new Date().toLocaleTimeString();

    // ── Stats Cards ─────────────────────────
    document.getElementById("stat-rx").textContent = fmtBytes(data.totals.rx_bps || 0);
    document.getElementById("stat-tx").textContent = fmtBytes(data.totals.tx_bps || 0);
    document.getElementById("stat-conns").textContent = (data.connections || []).length;
    // Recent drop records overlap between updates; count each event only once.
    for (const drop of (data.drops || [])) {
        const key = [drop.timestamp, drop.src_ip, drop.dst_ip, drop.src_port, drop.dst_port].join("|");
        if (!seenDropEvents.has(key)) {
            seenDropEvents.add(key);
            totalDrops += 1;
        }
    }
    if (seenDropEvents.size > 2000) {
        const keep = Array.from(seenDropEvents).slice(-1000);
        seenDropEvents.clear();
        keep.forEach(key => seenDropEvents.add(key));
    }
    document.getElementById("stat-drops").textContent = totalDrops;
    document.getElementById("stat-listen").textContent = (data.listening || []).length;

    // ── Bandwidth Chart ─────────────────────
    bwLabels.push(now);
    rxData.push(data.totals.rx_bps || 0);
    txData.push(data.totals.tx_bps || 0);
    if (bwLabels.length > MAX_BW_POINTS) {
        bwLabels.shift(); rxData.shift(); txData.shift();
    }
    bwChart.update();

    // ── Connection Table ────────────────────
    const connBody = document.querySelector("#conn-table tbody");
    connBody.innerHTML = (data.connections || []).map(c => `
        <tr>
            <td>${escHtml(c.process)}</td>
            <td>${c.proto}</td>
            <td>${escHtml(c.remote_ip)}</td>
            <td>${escHtml(c.domain || "—")}</td>
            <td>${c.remote_port} <span style="color:#8b8fa3">(${escHtml(c.port_label)})</span></td>
            <td>${escHtml(c.state)}</td>
            <td>${escHtml(c.geo?.country || "—")}</td>
            <td><button class="btn btn-danger btn-sm" onclick="blockIP('${escHtml(c.remote_ip)}')">Block</button></td>
        </tr>
    `).join("");

    // ── Drop Table ──────────────────────────
    const dropBody = document.querySelector("#drop-table tbody");
    dropBody.innerHTML = (data.drops || []).map(d => `
        <tr>
            <td>${fmtTime(d.timestamp)}</td>
            <td>${escHtml(d.src_ip)}</td>
            <td>${d.dst_port}</td>
            <td>${escHtml(d.proto)}</td>
            <td>${escHtml(d.geo?.country || "—")}</td>
            <td><button class="btn btn-danger btn-sm" onclick="blockIP('${escHtml(d.src_ip)}')">Block</button></td>
        </tr>
    `).join("");

    // ── Attacker Chart ──────────────────────
    const atk = data.attackers || [];
    atkChart.data.labels = atk.map(a => a.ip);
    atkChart.data.datasets[0].data = atk.map(a => a.count);
    atkChart.update();

    // ── Port Chart ──────────────────────────
    const ports = data.top_ports || [];
    portChart.data.labels = ports.map(p => ":" + p.port);
    portChart.data.datasets[0].data = ports.map(p => p.count);
    portChart.update();

    // ── Listening Ports ─────────────────────
    const listenBody = document.querySelector("#listen-table tbody");
    listenBody.innerHTML = (data.listening || []).map(l => `
        <tr>
            <td>${l.port}</td>
            <td>${escHtml(l.label)}</td>
            <td>${escHtml(l.address)}</td>
            <td>${escHtml(l.process)}</td>
            <td>${l.pid || "—"}</td>
        </tr>
    `).join("");
});

// ── Blocked List Updates ────────────────────────────────────────
socket.on("blocked_update", (data) => {
    renderBlockedList(data.blocked || []);
});

function renderBlockedList(ips) {
    const el = document.getElementById("blocked-list");
    if (ips.length === 0) {
        el.innerHTML = '<span style="color:#8b8fa3; font-size:0.85rem;">No IPs currently blocked</span>';
        return;
    }
    el.innerHTML = ips.map(ip => `
        <span class="tag">
            ${escHtml(ip)}
            <span class="remove" onclick="unblockIP('${escHtml(ip)}')" title="Unblock">✕</span>
        </span>
    `).join("");
}

// Fetch initial blocked list
fetch("/api/blocked")
    .then(r => r.json())
    .then(ips => renderBlockedList(ips))
    .catch(() => {});

// ── Block / Unblock Actions ─────────────────────────────────────
function blockIP(ip) {
    fetch("/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
    })
    .then(r => r.json())
    .then(data => {
        if (!data.ok) alert("Block failed: " + (data.error || "unknown"));
        refreshHistory();
    })
    .catch(e => alert("Error: " + e));
}

function unblockIP(ip) {
    fetch("/api/unblock", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
    })
    .then(r => r.json())
    .then(data => {
        if (!data.ok) alert("Unblock failed: " + (data.error || "unknown"));
        refreshHistory();
    })
    .catch(e => alert("Error: " + e));
}

function manualBlock() {
    const ip = document.getElementById("manual-ip").value.trim();
    if (ip) blockIP(ip);
}

function manualUnblock() {
    const ip = document.getElementById("manual-ip").value.trim();
    if (ip) unblockIP(ip);
}

// ── Action History ──────────────────────────────────────────────
function refreshHistory() {
    fetch("/api/history")
        .then(r => r.json())
        .then(rows => {
            const body = document.querySelector("#history-table tbody");
            body.innerHTML = (rows || []).slice(0, 20).map(r => `
                <tr>
                    <td>${fmtTime(r.timestamp)}</td>
                    <td><span class="badge ${r.action === 'block' ? 'badge-danger' : 'badge-ok'}">${r.action}</span></td>
                    <td>${escHtml(r.ip)}</td>
                    <td>${r.success ? "✓" : "✗ " + escHtml(r.error || "")}</td>
                </tr>
            `).join("");
        })
        .catch(() => {});
}

// Initial history load
refreshHistory();

// Refresh history every 10 seconds
setInterval(refreshHistory, 10000);

