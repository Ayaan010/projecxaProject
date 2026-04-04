"""
Demo Engine — simulates live IDS activity with mock data.

Used when DEMO_MODE=true (e.g. deployed on Render for a public demo).
No network interfaces, raw sockets, or root privileges required.
The real IDS capture pipeline is never touched.
"""

import time
import random
import threading
from datetime import datetime, timedelta

from dashboard.models import ids_state
from database.db import DatabaseManager


# ──────────────────────────────────────────────────────────────
# MOCK DATA
# ──────────────────────────────────────────────────────────────

_ATTACKER_IPS = [
    "185.220.101.47",
    "45.33.32.156",
    "103.21.244.0",
    "198.51.100.42",
    "203.0.113.17",
    "91.108.4.200",
    "5.188.206.26",
    "89.248.167.131",
    "94.102.49.190",
    "77.88.55.80",
]

_VICTIM_IPS = [f"10.0.0.{i}" for i in range(1, 21)]

_PROTOCOLS = ["TCP", "TCP", "TCP", "UDP", "UDP", "ICMP"]

_SUSPICIOUS_PORTS = [4444, 1337, 6666, 31337, 6667, 5555, 1234, 12345]
_COMMON_PORTS     = [22, 80, 443, 3389, 8080, 8443, 21, 25, 110, 3306]

_ALERT_TEMPLATES = [
    {
        "type": "PORT_SCAN",
        "severity": "HIGH",
        "message_tpl": "Port scan detected from {ip} — {count} unique ports in {window}s",
        "count_range": (20, 65),
        "window": 10,
    },
    {
        "type": "BRUTE_FORCE",
        "severity": "HIGH",
        "message_tpl": "Brute-force attempt from {ip} — {count} connection attempts on port {port} in {window}s",
        "count_range": (12, 40),
        "window": 10,
        "ports": [22, 3389, 21, 25],
    },
    {
        "type": "SYN_SCAN",
        "severity": "MEDIUM",
        "message_tpl": "SYN scan detected from {ip} — {count} SYN-only packets in {window}s",
        "count_range": (25, 90),
        "window": 10,
    },
    {
        "type": "TRAFFIC_SPIKE",
        "severity": "HIGH",
        "message_tpl": "Traffic spike from {ip} — {count} packets in {window}s (threshold: 100)",
        "count_range": (110, 450),
        "window": 5,
    },
    {
        "type": "SUSPICIOUS_PORT",
        "severity": "MEDIUM",
        "message_tpl": "Suspicious port activity from {ip} — connection to port {port}",
        "count_range": (1, 1),
        "window": 1,
        "ports": _SUSPICIOUS_PORTS,
    },
    {
        "type": "LARGE_PACKET",
        "severity": "LOW",
        "message_tpl": "Oversized packet from {ip} — {size} bytes (threshold: 1600)",
        "count_range": (1, 1),
        "window": 1,
    },
]


def _build_alert(template: dict, ip: str) -> dict:
    count  = random.randint(*template["count_range"])
    window = template.get("window", 10)
    port   = random.choice(template.get("ports", _COMMON_PORTS))
    size   = random.randint(1601, 9000)
    msg = template["message_tpl"].format(
        ip=ip, count=count, window=window, port=port, size=size
    )
    return {
        "type":     template["type"],
        "severity": template["severity"],
        "src_ip":   ip,
        "message":  msg,
    }


# ──────────────────────────────────────────────────────────────
# HISTORICAL SEED  (fills dashboard on first load)
# ──────────────────────────────────────────────────────────────

def _seed_history(db: DatabaseManager, n: int = 60):
    """Insert historical alerts so the dashboard isn't empty on start."""
    now = datetime.now()
    for i in range(n):
        ip       = random.choice(_ATTACKER_IPS)
        template = random.choice(_ALERT_TEMPLATES)
        alert    = _build_alert(template, ip)

        # Spread timestamps over the last 2 hours
        ts = now - timedelta(minutes=random.randint(1, 120))
        ts_str = ts.strftime("%Y-%m-%d %H:%M:%S")

        # Inject into in-memory state with a back-dated timestamp directly
        with ids_state.lock:
            ids_state.total_alerts += 1
            ids_state.alert_type_counts[alert["type"]] += 1
            src = alert["src_ip"]
            ids_state.ip_alert_counts[src] += 1
            if alert["severity"] == "HIGH":
                ids_state.ip_high_counts[src] += 1
            ids_state.recent_alerts.append({
                "timestamp": ts_str,
                "type":      alert["type"],
                "src_ip":    src,
                "message":   alert["message"],
                "severity":  alert["severity"],
            })

        # Persist to DB
        db.insert_alert({
            "alert_type":       alert["type"],
            "severity":         alert["severity"],
            "source_ip":        alert["src_ip"],
            "destination_ip":   random.choice(_VICTIM_IPS),
            "source_port":      random.randint(1024, 65535),
            "destination_port": random.choice(_COMMON_PORTS),
            "protocol":         "TCP",
            "description":      alert["message"],
            "raw_data":         "",
        })

    # Sort recent_alerts newest-first in one pass
    with ids_state.lock:
        ids_state.recent_alerts.sort(key=lambda a: a["timestamp"], reverse=True)
        ids_state.recent_alerts = ids_state.recent_alerts[:ids_state.MAX_ALERTS]

    # Seed some packet counts so stats aren't all-zero
    for _ in range(800):
        ids_state.record_packet(random.choice(_PROTOCOLS))

    # A few system log entries
    db.insert_system_log("IDS_START",  "Demo mode initialised — simulated IDS activity running", "INFO")
    db.insert_system_log("RULE_LOAD",  "Rule engine loaded: PORT_SCAN, BRUTE_FORCE, SYN_SCAN, SUSPICIOUS_PORT", "INFO")
    db.insert_system_log("ANOMALY",    "Anomaly engine loaded: TRAFFIC_SPIKE, LARGE_PACKET", "INFO")


# ──────────────────────────────────────────────────────────────
# LIVE SIMULATION LOOP
# ──────────────────────────────────────────────────────────────

def run_demo(db: DatabaseManager):
    """
    Background thread: continuously feed mock traffic and alerts
    into ids_state and the SQLite database.
    Call this INSTEAD of start_ids_background() when DEMO_MODE=True.
    """
    ids_state.set_running(True)
    _seed_history(db, n=60)

    # Snapshot loop (mirrors the real IDS snapshot loop)
    def _snapshot_loop():
        while True:
            ids_state.take_traffic_snapshot()
            time.sleep(3)

    threading.Thread(target=_snapshot_loop, daemon=True).start()

    tick = 0
    while True:
        # ── Simulate a burst of packets ──
        burst = random.randint(8, 35)
        for _ in range(burst):
            ids_state.record_packet(random.choice(_PROTOCOLS))

        # ── Randomly fire an alert (~35 % chance per tick) ──
        if random.random() < 0.35:
            ip       = random.choice(_ATTACKER_IPS)
            template = random.choice(_ALERT_TEMPLATES)
            alert    = _build_alert(template, ip)

            ids_state.record_alert(alert)

            db.insert_alert({
                "alert_type":       alert["type"],
                "severity":         alert["severity"],
                "source_ip":        alert["src_ip"],
                "destination_ip":   random.choice(_VICTIM_IPS),
                "source_port":      random.randint(1024, 65535),
                "destination_port": random.choice(_COMMON_PORTS),
                "protocol":         "TCP",
                "description":      alert["message"],
                "raw_data":         "",
            })

            # Occasionally raise a block request for repeat HIGH offenders
            if (alert["severity"] == "HIGH"
                    and random.random() < 0.15
                    and not ids_state.is_blocked(ip)
                    and not any(p["ip"] == ip for p in ids_state.get_pending_blocks())):
                ids_state.request_block(
                    ip,
                    "Triggered multiple HIGH severity alerts (demo simulation)"
                )
                db.insert_system_log(
                    "BLOCK_REQUEST",
                    f"Block request raised for {ip} — awaiting user confirmation",
                    "WARNING",
                )

        # ── Periodic system log entries ──
        if tick % 25 == 0:
            msgs = [
                "Signature database check — all rules up to date",
                "Anomaly baseline recalibrated",
                "Periodic cleanup — expired IP tracking entries removed",
                "Traffic threshold check passed",
            ]
            db.insert_system_log("DEMO", random.choice(msgs), "INFO")

        tick += 1
        time.sleep(random.uniform(0.8, 2.5))
