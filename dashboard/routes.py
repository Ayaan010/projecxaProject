"""
Flask Routes — page views & API endpoints
"""

import os
import re
import json
from flask import Blueprint, render_template, jsonify, request

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


# ──────────────────────────────────────
# API ROUTES
# ──────────────────────────────────────

@bp.route("/api/status")
def api_status():
    return jsonify(ids_state.get_status())


@bp.route("/api/alerts")
def api_alerts():
    # Try in-memory alerts first; fall back to database
    alerts = ids_state.get_recent_alerts(limit=200)
    if not alerts:
        db = DatabaseManager(config.DATABASE_PATH)
        with db.get_connection() as conn:
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


@bp.route("/api/traffic")
def api_traffic():
    return jsonify({
        "protocol_distribution": ids_state.get_protocol_distribution(),
        "traffic_snapshots": ids_state.get_traffic_snapshots(),
        "total_packets": ids_state.get_status()["total_packets"],
    })


@bp.route("/api/logs")
def api_logs():
    db = DatabaseManager(config.DATABASE_PATH)
    with db.get_connection() as conn:
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
