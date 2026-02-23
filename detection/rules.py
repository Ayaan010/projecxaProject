# rules.py
"""
Rule-Based Detection Engine
Detects known attack signatures
"""

from collections import defaultdict
from datetime import datetime, timedelta


class RuleEngine:
    def __init__(self):
        # tracking structures
        self.connection_attempts = defaultdict(list)
        self.port_scan_tracker = defaultdict(set)

        # thresholds
        self.BRUTE_FORCE_THRESHOLD = 10
        self.PORT_SCAN_THRESHOLD = 15
        self.TIME_WINDOW = 10  # seconds

        # suspicious ports list
        self.suspicious_ports = {4444, 1337, 6666, 9999}

    # --------------------------------------------------
    # MAIN CHECK FUNCTION
    # --------------------------------------------------
    def check_rules(self, packet):
        alerts = []

        alerts += self.detect_port_scan(packet)
        alerts += self.detect_bruteforce(packet)
        alerts += self.detect_suspicious_port(packet)
        alerts += self.detect_syn_scan(packet)

        return alerts

    # --------------------------------------------------
    # PORT SCAN DETECTION
    # --------------------------------------------------
    def detect_port_scan(self, packet):
        alerts = []

        src = packet["src_ip"]
        dst_port = packet["dst_port"]

        if dst_port:
            self.port_scan_tracker[src].add(dst_port)

        if len(self.port_scan_tracker[src]) > self.PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN",
                "src_ip": src,
                "message": f"Port scan detected from {src}"
            })
            self.port_scan_tracker[src].clear()

        return alerts

    # --------------------------------------------------
    # BRUTE FORCE DETECTION
    # --------------------------------------------------
    def detect_bruteforce(self, packet):
        alerts = []

        src = packet["src_ip"]
        now = datetime.now()

        self.connection_attempts[src].append(now)

        # remove old timestamps
        self.connection_attempts[src] = [
            t for t in self.connection_attempts[src]
            if now - t < timedelta(seconds=self.TIME_WINDOW)
        ]

        if len(self.connection_attempts[src]) > self.BRUTE_FORCE_THRESHOLD:
            alerts.append({
                "type": "BRUTE_FORCE",
                "src_ip": src,
                "message": f"Possible brute force attack from {src}"
            })
            self.connection_attempts[src].clear()

        return alerts

    # --------------------------------------------------
    # SUSPICIOUS PORT DETECTION
    # --------------------------------------------------
    def detect_suspicious_port(self, packet):
        alerts = []

        if packet["dst_port"] in self.suspicious_ports:
            alerts.append({
                "type": "SUSPICIOUS_PORT",
                "src_ip": packet["src_ip"],
                "message": f"Traffic to suspicious port {packet['dst_port']}"
            })

        return alerts

    # --------------------------------------------------
    # SYN SCAN DETECTION
    # --------------------------------------------------
    def detect_syn_scan(self, packet):
        alerts = []

        if packet["protocol"] == "TCP":
            flags = packet["flags"]

            # SYN only flag indicates scanning
            if flags == "S":
                alerts.append({
                    "type": "SYN_SCAN",
                    "src_ip": packet["src_ip"],
                    "message": f"SYN scan attempt from {packet['src_ip']}"
                })

        return alerts
