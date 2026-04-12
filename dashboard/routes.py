"""
Flask Routes — page views & API endpoints
"""

import os
import re
import json
from flask import Blueprint, render_template, jsonify, request, Response

from dashboard.models import ids_state
import config
from database.db import DatabaseManager

bp = Blueprint(
    "dashboard", __name__,
    template_folder="templates",
    static_folder="static",
    static_url_path="/static",
)

LOG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "alerts.log")
CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.py")

# Shared DB instance — created once, reused across all requests
_db = DatabaseManager(config.DATABASE_PATH)

# ──────────────────────────────────────
# AUTHENTICATION
# ──────────────────────────────────────

@bp.before_request
def check_auth():
    # Demo mode with no-auth: let everyone through
    if config.DEMO_NO_AUTH:
        return
    auth = request.authorization
    if not auth or auth.username != config.DASHBOARD_USER or auth.password != config.DASHBOARD_PASSWORD:
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="IDS Dashboard"'},
        )

# ──────────────────────────────────────
# PAGE ROUTES
# ──────────────────────────────────────

@bp.route("/")
def index():
    return render_template("dashboard.html")


@bp.route("/alerts")
def alerts_page():
    return render_template("alerts.html")


@bp.route("/traffic")
def traffic_page():
    return render_template("traffic.html")


@bp.route("/logs")
def logs_page():
    return render_template("logs.html")


@bp.route("/settings")
def settings_page():
    config_vals = _read_config()
    return render_template("settings.html", config=config_vals)


@bp.route("/threat-guide")
def threat_guide_page():
    return render_template("threat_guide.html")


@bp.route("/threat-detail")
def threat_detail_page():
    ip = request.args.get("ip", "").strip()
    return render_template("threat_detail.html", ip=ip)


# ──────────────────────────────────────
# API ROUTES
# ──────────────────────────────────────

@bp.route("/api/status")
def api_status():
    return jsonify(ids_state.get_status())


@bp.route("/api/alerts")
def api_alerts():
    # Try in-memory alerts first; fall back to database
    alerts = ids_state.get_recent_alerts(limit=600)
    if not alerts:
        with _db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, alert_type as type, severity, source_ip as src_ip, description as message
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 200
            ''')
            rows = cursor.fetchall()
            alerts = [dict(row) for row in rows]
    return jsonify(alerts)


@bp.route("/api/alert_stats")
def api_alert_stats():
    """Counts per alert type and per severity — used by breakdown chart."""
    type_counts = ids_state.get_alert_type_counts()
    # Also pull severity buckets from type_counts
    severity_map = {
        "PORT_SCAN": "HIGH", "BRUTE_FORCE": "HIGH", "TRAFFIC_SPIKE": "HIGH",
        "SYN_SCAN": "MEDIUM", "SUSPICIOUS_PORT": "MEDIUM",
        "LARGE_PACKET": "LOW", "SYSTEM": "INFO",
    }
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for t, cnt in type_counts.items():
        sev = severity_map.get(t, "INFO")
        severity_counts[sev] += cnt
    return jsonify({"by_type": type_counts, "by_severity": severity_counts})


@bp.route("/api/top_threats")
def api_top_threats():
    """Top IPs by total alert count."""
    return jsonify(ids_state.get_top_threat_ips(n=10))


@bp.route("/api/ip_detail/<path:ip>")
def api_ip_detail(ip):
    """Full detail for a specific source IP."""
    ip = ip.strip()
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return jsonify({"error": "Invalid IP"}), 400

    detail = ids_state.get_ip_detail(ip)

    # Enrich with DB records if in-memory history is empty
    if not detail["recent_alerts"]:
        with _db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, alert_type as type, severity,
                       source_ip as src_ip, description as message
                FROM alerts
                WHERE source_ip = ?
                ORDER BY timestamp DESC
                LIMIT 50
            ''', (ip,))
            rows = cursor.fetchall()
            db_alerts = [dict(r) for r in rows]

        # Rebuild summary from DB rows
        type_counts = {}
        for a in db_alerts:
            t = a.get("type", "UNKNOWN")
            type_counts[t] = type_counts.get(t, 0) + 1
        high = sum(1 for a in db_alerts if a.get("severity") == "HIGH")
        timestamps = [a["timestamp"] for a in db_alerts if a.get("timestamp")]

        detail["recent_alerts"] = db_alerts
        detail["type_counts"]   = type_counts
        detail["total_alerts"]  = len(db_alerts)
        detail["high_alerts"]   = high
        detail["first_seen"]    = timestamps[-1] if timestamps else None
        detail["last_seen"]     = timestamps[0]  if timestamps else None

    return jsonify(detail)


@bp.route("/api/pending_blocks", methods=["GET"])
def api_pending_blocks_get():
    """Return IPs waiting for block confirmation."""
    return jsonify(ids_state.get_pending_blocks())


@bp.route("/api/pending_blocks", methods=["POST"])
def api_pending_blocks_post():
    """Confirm or dismiss a pending block request.
    Body: {"ip": "x.x.x.x", "action": "confirm"|"dismiss"}
    """
    data = request.get_json(force=True) or {}
    ip = data.get("ip", "").strip()
    action = data.get("action", "").strip()

    import re as _re
    if not _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return jsonify({"error": "Invalid IP address format"}), 400
    if action not in ("confirm", "dismiss"):
        return jsonify({"error": "action must be 'confirm' or 'dismiss'"}), 400

    if action == "confirm":
        ids_state.confirm_block(ip)
        _db.insert_system_log("BLOCK_CONFIRMED", f"IP {ip} blocked by user", "WARNING")
    else:
        ids_state.dismiss_block(ip)
        _db.insert_system_log("BLOCK_DISMISSED", f"Block request for {ip} dismissed by user", "INFO")

    return jsonify({"status": "ok", "ip": ip, "action": action})


@bp.route("/api/blocklist", methods=["GET"])
def api_blocklist_get():
    """Return current blocked IPs."""
    return jsonify({"blocked_ips": ids_state.get_blocked_ips()})


@bp.route("/api/blocklist", methods=["POST"])
def api_blocklist_post():
    """Block or unblock an IP. Body: {"ip": "x.x.x.x", "action": "block"|"unblock"}"""
    data = request.get_json(force=True) or {}
    ip = data.get("ip", "").strip()
    action = data.get("action", "").strip()

    # Validate IP format (basic check)
    import re as _re
    if not _re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return jsonify({"error": "Invalid IP address format"}), 400
    if action not in ("block", "unblock"):
        return jsonify({"error": "action must be 'block' or 'unblock'"}), 400

    if action == "block":
        ids_state.block_ip(ip)
    else:
        ids_state.unblock_ip(ip)

    return jsonify({"status": "ok", "ip": ip, "action": action})


@bp.route("/api/simulate", methods=["POST"])
def api_simulate():
    """Inject a synthetic alert into IDS state for testing/demo purposes.
    Body: {"scenario": "PORT_SCAN"|"BRUTE_FORCE"|"SYN_SCAN"|"TRAFFIC_SPIKE"|"SUSPICIOUS_PORT"|"LARGE_PACKET", "src_ip": "x.x.x.x" (optional)}
    """
    import random as _rand

    data = request.get_json(force=True) or {}
    scenario = data.get("scenario", "").strip().upper()

    SCENARIOS = {
        "PORT_SCAN":       ("HIGH",   "Port scan detected from {ip} — {n} unique ports probed in 10s"),
        "BRUTE_FORCE":     ("HIGH",   "Brute-force attempt from {ip} — {n} login attempts on port 22 in 10s"),
        "SYN_SCAN":        ("MEDIUM", "SYN scan detected from {ip} — {n} SYN-only packets in 10s"),
        "TRAFFIC_SPIKE":   ("HIGH",   "Traffic spike from {ip} — {n} packets in 5s (threshold: 100)"),
        "SUSPICIOUS_PORT": ("MEDIUM", "Suspicious connection from {ip} to port {port} (known C2 port)"),
        "LARGE_PACKET":    ("LOW",    "Oversized packet from {ip} — {size} bytes (threshold: 1600)"),
    }

    if scenario not in SCENARIOS:
        return jsonify({"error": f"Unknown scenario. Valid: {list(SCENARIOS.keys())}"}), 400

    # Validate or assign source IP
    raw_ip = data.get("src_ip", "").strip()
    if raw_ip and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", raw_ip):
        return jsonify({"error": "Invalid src_ip format"}), 400
    src_ip = raw_ip if raw_ip else f"10.{_rand.randint(0,255)}.{_rand.randint(0,255)}.{_rand.randint(1,254)}"

    severity, msg_tpl = SCENARIOS[scenario]
    message = msg_tpl.format(
        ip=src_ip,
        n=_rand.randint(20, 120),
        port=_rand.choice([4444, 1337, 6666, 31337, 6667]),
        size=_rand.randint(1601, 9000),
    )

    alert = {"type": scenario, "severity": severity, "src_ip": src_ip, "message": message}
    ids_state.record_alert(alert)
    # Also feed a burst of fake packets so the traffic chart moves
    for _ in range(_rand.randint(5, 20)):
        ids_state.record_packet(_rand.choice(["TCP", "UDP", "ICMP"]))

    _db.insert_alert({
        "alert_type": scenario, "severity": severity,
        "source_ip": src_ip, "destination_ip": "10.0.0.1",
        "source_port": _rand.randint(1024, 65535), "destination_port": 80,
        "protocol": "TCP", "description": message, "raw_data": "",
    })
    _db.insert_system_log("SIMULATE", f"Manual simulation: {scenario} from {src_ip}", "INFO")

    return jsonify({"status": "ok", "scenario": scenario, "src_ip": src_ip, "severity": severity, "message": message})


@bp.route("/api/traffic")
def api_traffic():
    return jsonify({
        "protocol_distribution": ids_state.get_protocol_distribution(),
        "traffic_snapshots": ids_state.get_traffic_snapshots(),
        "total_packets": ids_state.get_status()["total_packets"],
    })


@bp.route("/api/logs")
def api_logs():
    with _db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT timestamp, event_type, message, status
            FROM system_logs
            ORDER BY timestamp DESC
            LIMIT 300
        ''')
        rows = cursor.fetchall()
        lines = [f"{row['timestamp']} [{row['status']}] {row['event_type']}: {row['message']}" for row in rows]
    return jsonify(lines)


@bp.route("/api/settings", methods=["POST"])
def api_settings():
    if config.DEMO_MODE:
        return jsonify({"error": "Settings are read-only in demo mode"}), 403
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Whitelist of allowed config keys and their types
    allowed = {
        "PORT_SCAN_THRESHOLD": int,
        "BRUTE_FORCE_THRESHOLD": int,
        "TIME_WINDOW": int,
        "PACKET_RATE_THRESHOLD": int,
        "TRAFFIC_TIME_WINDOW": int,
        "LARGE_PACKET_SIZE": int,
        "MAX_TRACKED_IPS": int,
        "CLEANUP_INTERVAL": int,
        "ENABLE_CONSOLE_ALERTS": bool,
        "ENABLE_FILE_LOGGING": bool,
        "DEBUG_MODE": bool,
        "PRINT_PACKETS": bool,
    }

    updates = {}
    for key, value in data.items():
        if key not in allowed:
            continue
        try:
            updates[key] = allowed[key](value)
        except (ValueError, TypeError):
            return jsonify({"error": f"Invalid value for {key}"}), 400

    if not updates:
        return jsonify({"error": "No valid settings provided"}), 400

    _update_config_file(updates)
    return jsonify({"status": "ok", "updated": list(updates.keys())})


# ──────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────

def _parse_log_file():
    """Parse alerts.log into structured list."""
    alerts = []
    if not os.path.isfile(LOG_FILE):
        return alerts

    pattern = re.compile(
        r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},?\d*)\s*-\s*(\w+)\s*-\s*"
        r"\[([^\]]+)\]\s*\|\s*Severity:\s*(\w+)\s*\|\s*Source:\s*(\S+)\s*\|\s*(.*)"
    )

    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pattern.match(line.strip())
            if m:
                alerts.append({
                    "timestamp": m.group(1),
                    "type": m.group(3),
                    "severity": m.group(4),
                    "src_ip": m.group(5),
                    "message": m.group(6),
                })
    alerts.reverse()
    return alerts[:200]


def _read_log_lines(max_lines=300):
    """Return last N lines of the log file."""
    if not os.path.isfile(LOG_FILE):
        return []
    with open(LOG_FILE, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    return [l.rstrip() for l in lines[-max_lines:]]


SAFE_VALUE_PATTERN = re.compile(r"^[A-Za-z0-9_. \-]+$")


def _read_config():
    """Read numeric/bool config values from config.py."""
    config_vals = {}
    if not os.path.isfile(CONFIG_FILE):
        return config_vals
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            m = re.match(r"^(\w+)\s*=\s*(.+)$", line.strip())
            if m:
                key, val = m.group(1), m.group(2).strip()
                if val in ("True", "False"):
                    config_vals[key] = val == "True"
                else:
                    try:
                        config_vals[key] = int(val)
                    except ValueError:
                        try:
                            config_vals[key] = float(val)
                        except ValueError:
                            pass  # skip non-numeric
    return config_vals


def _update_config_file(updates: dict):
    """Safely rewrite config.py with new values for whitelisted keys."""
    if not os.path.isfile(CONFIG_FILE):
        return

    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = []
    for line in lines:
        m = re.match(r"^(\w+)\s*=\s*(.+)$", line.strip())
        if m and m.group(1) in updates:
            key = m.group(1)
            val = updates[key]
            if isinstance(val, bool):
                val = "True" if val else "False"
            new_lines.append(f"{key} = {val}\n")
        else:
            new_lines.append(line)

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.writelines(new_lines)
