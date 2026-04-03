# rules.py
"""
Rule-Based Detection Engine
Detects known attack signatures
"""

from collections import defaultdict
from datetime import datetime, timedelta
import config


class RuleEngine:
    def __init__(self):
        # tracking structures
        self.connection_attempts = defaultdict(list)
        self.port_scan_tracker = defaultdict(dict)   # {src_ip: {dst_port: timestamp}}
        self.syn_tracker = defaultdict(list)          # {src_ip: [timestamps]}

        # thresholds
        self.BRUTE_FORCE_THRESHOLD = config.BRUTE_FORCE_THRESHOLD
        self.PORT_SCAN_THRESHOLD = config.PORT_SCAN_THRESHOLD
        self.SYN_SCAN_THRESHOLD = config.SYN_SCAN_THRESHOLD
        self.TIME_WINDOW = config.TIME_WINDOW

        # suspicious ports — read from config so editing config.py takes effect
        self.suspicious_ports = config.SUSPICIOUS_PORTS

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
    # Tracks unique destination ports per source IP within the time window.
    # Accumulating 15+ unique ports in 10 s is a strong scan indicator.
    # --------------------------------------------------
    def detect_port_scan(self, packet):
        alerts = []

        src = packet["src_ip"]
        dst_port = packet["dst_port"]
        now = datetime.now()

        # Track port with its timestamp (use None check — port 0 is valid)
        if dst_port is not None:
            self.port_scan_tracker[src][dst_port] = now

        # Expire ports seen outside the time window
        self.port_scan_tracker[src] = {
            p: t for p, t in self.port_scan_tracker[src].items()
            if now - t < timedelta(seconds=self.TIME_WINDOW)
        }

        if len(self.port_scan_tracker[src]) > self.PORT_SCAN_THRESHOLD:
            alerts.append({
                "type": "PORT_SCAN",
                "src_ip": src,
                "message": f"Port scan detected from {src}: "
                           f"{len(self.port_scan_tracker[src])} unique ports in "
                           f"{self.TIME_WINDOW}s"
            })
            self.port_scan_tracker[src].clear()

        return alerts

    # --------------------------------------------------
    # BRUTE FORCE DETECTION
    # Only counts repeated attempts to authentication ports
    # --------------------------------------------------
    BRUTE_FORCE_PORTS = {21, 22, 23, 25, 110, 143, 389, 445, 3389, 5900}

    def detect_bruteforce(self, packet):
        alerts = []

        dst_port = packet.get("dst_port")

        # Only track packets aimed at authentication-related ports
        if dst_port not in self.BRUTE_FORCE_PORTS:
            return alerts

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
                "message": f"Possible brute force attack on port {dst_port} from {src}"
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
    # A single SYN packet is normal (every connection starts with one).
    # A flood of SYN-only packets to many ports WITHOUT completing the
    # handshake is a stealth scan — detected by counting SYN packets per
    # source IP within a sliding time window.
    # --------------------------------------------------
    def detect_syn_scan(self, packet):
        alerts = []

        if packet["protocol"] != "TCP" or packet["flags"] != "S":
            return alerts

        src = packet["src_ip"]
        now = datetime.now()

        self.syn_tracker[src].append(now)

        # Remove timestamps outside the time window
        self.syn_tracker[src] = [
            t for t in self.syn_tracker[src]
            if now - t < timedelta(seconds=self.TIME_WINDOW)
        ]

        if len(self.syn_tracker[src]) > self.SYN_SCAN_THRESHOLD:
            alerts.append({
                "type": "SYN_SCAN",
                "src_ip": src,
                "message": f"SYN scan detected from {src}: "
                           f"{len(self.syn_tracker[src])} SYN packets in "
                           f"{self.TIME_WINDOW}s"
            })
            self.syn_tracker[src].clear()

        return alerts
