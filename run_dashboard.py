"""
Run the IDS Web Dashboard
Optionally starts the IDS engine in a background thread.

Usage:
    python run_dashboard.py               # dashboard only
    python run_dashboard.py --demo        # demo mode (simulated data, no capture needed)
    python run_dashboard.py --with-ids    # dashboard + live IDS capture
"""

import sys
import os
import threading
import time
from waitress import serve

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from dashboard.app import create_app
from dashboard.models import ids_state
import config
from database.db import DatabaseManager


def start_ids_background():
    """Run the IDS engine in a daemon thread and feed metrics to the dashboard."""
    import config
    from capture.sniffer import PacketSniffer
    from parser.packet_parser import PacketParser
    from detection.rules import RuleEngine
    from detection.anomaly import AnomalyDetector
    from alerts.alert_system import AlertSystem

    parser = PacketParser()
    rule_engine = RuleEngine()
    anomaly_engine = AnomalyDetector()
    alert_system = AlertSystem(config.LOG_FILE)
    db = DatabaseManager(config.DATABASE_PATH)

    severity_map = {
        "PORT_SCAN": "HIGH",
        "BRUTE_FORCE": "HIGH",
        "SYN_SCAN": "MEDIUM",
        "TRAFFIC_SPIKE": "HIGH",
        "SUSPICIOUS_PORT": "MEDIUM",
        "LARGE_PACKET": "LOW",
        "SYSTEM": "INFO",
    }

    def process_packet(raw_packet):
        parsed = parser.parse(raw_packet)
        if not parser.validate(parsed):
            return

        src_ip = parsed.get("src_ip")

        # Skip packets from auto-blocked IPs
        if src_ip and ids_state.is_blocked(src_ip):
            return

        # Feed traffic stats
        ids_state.record_packet(parsed.get("protocol", "OTHER"))

        # Detection
        rule_alerts = rule_engine.check_rules(parsed)
        anomaly_alerts = anomaly_engine.detect(parsed)

        for alert in rule_alerts + anomaly_alerts:
            alert["severity"] = severity_map.get(alert.get("type"), "INFO")
            ids_state.record_alert(alert)
            alert_system.raise_alert(alert)

            # Ask user to confirm block when IP repeatedly triggers HIGH alerts
            if config.ENABLE_AUTO_BLOCK and src_ip:
                if ids_state.should_request_block(src_ip, config.AUTO_BLOCK_THRESHOLD):
                    ids_state.request_block(
                        src_ip,
                        f"Triggered {config.AUTO_BLOCK_THRESHOLD}+ HIGH alerts"
                    )
                    notify_alert = {
                        "type": "SYSTEM",
                        "src_ip": src_ip,
                        "message": (
                            f"Block request raised for {src_ip} — "
                            f"{config.AUTO_BLOCK_THRESHOLD} HIGH alerts detected. "
                            "Approve in the dashboard."
                        ),
                        "severity": "INFO",
                    }
                    ids_state.record_alert(notify_alert)
                    alert_system.raise_alert(notify_alert)
                    db.insert_system_log(
                        "BLOCK_REQUEST",
                        f"Block request raised for {src_ip} — awaiting user confirmation",
                        "WARNING",
                    )

            # Save to database
            alert_data = {
                'alert_type': alert.get('type', 'Unknown'),
                'severity': alert.get('severity', 'Medium'),
                'source_ip': parsed.get('src_ip'),
                'destination_ip': parsed.get('dst_ip'),
                'source_port': parsed.get('src_port'),
                'destination_port': parsed.get('dst_port'),
                'protocol': parsed.get('protocol'),
                'description': alert.get('message'),
                'raw_data': str(parsed)
            }
            db.insert_alert(alert_data)

    sniffer = PacketSniffer(
        interface=config.INTERFACE,
        packet_callback=process_packet,
    )

    ids_state.set_running(True)

    # Log start
    db.insert_system_log("IDS_START", "IDS Started Successfully", "INFO")

    # Periodic traffic snapshots
    def snapshot_loop():
        while True:
            ids_state.take_traffic_snapshot()
            time.sleep(3)

    threading.Thread(target=snapshot_loop, daemon=True).start()

    try:
        sniffer.start()
    except Exception as e:
        print(f"[IDS] Error: {e}")
        ids_state.set_running(False)
        db.insert_system_log("ERROR", str(e), "ERROR")


def main():
    # Ensure logs directory exists on every machine
    os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"), exist_ok=True)

    demo_mode = "--demo" in sys.argv or config.DEMO_MODE
    with_ids  = "--with-ids" in sys.argv

    if not demo_mode and config.DASHBOARD_PASSWORD == "changeme":
        print("[!] WARNING: Default password in use. Set IDS_PASSWORD env var before exposing to a network.")

    if demo_mode:
        config.DEMO_MODE    = True   # ensure routes/templates see the flag
        config.DEMO_NO_AUTH = True
        print("[*] DEMO MODE -- starting simulated IDS activity (no packet capture)...")
        from demo.demo_engine import run_demo
        _demo_db = DatabaseManager(config.DATABASE_PATH)
        threading.Thread(target=run_demo, args=(_demo_db,), daemon=True).start()
    elif with_ids:
        print("[*] Starting IDS engine in background thread...")
        t = threading.Thread(target=start_ids_background, daemon=True)
        t.start()
    else:
        print("[*] Dashboard-only mode | Use --with-ids for live capture")

    app = create_app()
    host = config.DASHBOARD_HOST
    port = config.DASHBOARD_PORT
    display_host = "127.0.0.1" if host == "0.0.0.0" else host
    if demo_mode:
        print(f"[*] Dashboard -> http://{display_host}:{port}  (no login -- demo mode)")
    else:
        print(f"[*] Dashboard -> http://{display_host}:{port}  (login: {config.DASHBOARD_USER})")
    if host == "0.0.0.0":
        print(f"[*] Also accessible from other PCs at http://<this-machine-ip>:{port}")
    serve(app, host=host, port=port, threads=4)


if __name__ == "__main__":
    main()
