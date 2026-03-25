"""
Run the IDS Web Dashboard
Optionally starts the IDS engine in a background thread.

Usage:
    python run_dashboard.py               # dashboard only
    python run_dashboard.py --with-ids    # dashboard + IDS capture
"""

import sys
import os
import threading
import time

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

        # Feed traffic stats
        ids_state.record_packet(parsed.get("protocol", "OTHER"))

        # Detection
        rule_alerts = rule_engine.check_rules(parsed)
        anomaly_alerts = anomaly_engine.detect(parsed)

        for alert in rule_alerts + anomaly_alerts:
            alert["severity"] = severity_map.get(alert.get("type"), "INFO")
            ids_state.record_alert(alert)
            alert_system.raise_alert(alert)
            
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


def start_demo_simulation():
    """
    Feed randomized fake packets and alerts into ids_state so the
    dashboard can be fully demonstrated without real network capture.
    """
    import random

    PROTOCOLS = ["TCP", "UDP", "ICMP", "OTHER"]
    ALERT_TYPES = [
        ("PORT_SCAN",      "HIGH",   "Port scan detected from {ip}"),
        ("BRUTE_FORCE",    "HIGH",   "Possible brute force attack from {ip}"),
        ("TRAFFIC_SPIKE",  "HIGH",   "High traffic rate detected from {ip}"),
        ("SYN_SCAN",       "MEDIUM", "SYN scan detected from {ip}"),
        ("SUSPICIOUS_PORT","MEDIUM", "Traffic to suspicious port from {ip}"),
        ("LARGE_PACKET",   "LOW",    "Unusually large packet from {ip}"),
        ("SYSTEM",         "INFO",   "IDS health check passed"),
    ]

    def rand_ip():
        return f"192.168.{random.randint(0, 10)}.{random.randint(1, 254)}"

    ids_state.set_running(True)

    # Initialize database
    db = DatabaseManager(config.DATABASE_PATH)

    tick = 0
    while True:
        # Simulate a burst of packets (10–60 per second)
        for _ in range(random.randint(10, 60)):
            p = random.choices(PROTOCOLS, weights=[60, 25, 10, 5])[0]
            ids_state.record_packet(p)

        # Snapshot traffic every ~3 s
        if tick % 3 == 0:
            ids_state.take_traffic_snapshot()

        # Randomly fire an alert (≈30 % chance per second)
        if random.random() < 0.30:
            atype, severity, tmpl = random.choice(ALERT_TYPES)
            ip = rand_ip()
            alert = {
                "type": atype,
                "src_ip": ip,
                "message": tmpl.format(ip=ip),
                "severity": severity,
            }
            ids_state.record_alert(alert)
            
            # Save to database
            alert_data = {
                'alert_type': alert['type'],
                'severity': alert['severity'],
                'source_ip': alert['src_ip'],
                'description': alert['message'],
                'protocol': 'TCP',  # Fake protocol for demo
            }
            db.insert_alert(alert_data)

        tick += 1
        time.sleep(1)


def main():
    with_ids = "--with-ids" in sys.argv
    demo     = "--demo"     in sys.argv

    if with_ids:
        print("[*] Starting IDS engine in background thread…")
        t = threading.Thread(target=start_ids_background, daemon=True)
        t.start()
    elif demo:
        print("[*] Demo mode — simulating fake traffic and alerts…")
        t = threading.Thread(target=start_demo_simulation, daemon=True)
        t.start()
    else:
        print("[*] Dashboard-only mode  |  --demo for simulation  |  --with-ids for live capture")

    app = create_app()
    print("[*] Dashboard is running at http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
