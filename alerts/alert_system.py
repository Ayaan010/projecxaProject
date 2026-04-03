"""
Alert & Logging System
Handles alert display, logging, and formatting
"""

import logging
from datetime import datetime
from colorama import Fore, Style, init

# initialize colorama
init(autoreset=True)


class AlertSystem:
    def __init__(self, log_file="logs/alerts.log"):

        self.log_file = log_file

        # configure logger
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s - %(message)s"
        )

        # severity mapping
        self.severity_levels = {
            "PORT_SCAN": "HIGH",
            "BRUTE_FORCE": "HIGH",
            "SYN_SCAN": "MEDIUM",
            "TRAFFIC_SPIKE": "HIGH",
            "SUSPICIOUS_PORT": "MEDIUM",
            "LARGE_PACKET": "LOW",
            "SYSTEM": "INFO"
        }

        # Plain-English descriptions shown in the dashboard UI
        self.alert_descriptions = {
            "PORT_SCAN": (
                "A single IP is probing many different ports rapidly. "
                "Attackers do this to find open services they can exploit. "
                "Triggered when one IP hits more than 15 unique ports."
            ),
            "BRUTE_FORCE": (
                "An IP is sending a very high number of connection attempts "
                "to authentication ports (SSH, RDP, FTP, etc.) in a short time. "
                "This usually means an automated password-guessing attack."
            ),
            "SYN_SCAN": (
                "An unusually high number of TCP SYN-only packets are being received "
                "from one IP in a short window (more than 20 SYN packets in 10 seconds). "
                "Normal connections send one SYN then complete the handshake — "
                "a scanner repeatedly sends SYN without ever completing the connection "
                "to silently map which ports are open."
            ),
            "TRAFFIC_SPIKE": (
                "One IP is sending an unusually large number of packets in a very "
                "short window (more than 100 packets in 5 seconds). This could indicate "
                "a flood/DoS attack or a misconfigured device. "
                "After 3 HIGH alerts the IP is automatically blocked."
            ),
            "SUSPICIOUS_PORT": (
                "Traffic was detected on a port commonly used by malware or "
                "remote-access tools (e.g., 4444 — Metasploit default, 1337, 6666, 9999). "
                "Legitimate software rarely uses these ports."
            ),
            "LARGE_PACKET": (
                "A packet larger than 1600 bytes was received. "
                "Standard Ethernet frames max out at ~1514 bytes (including all headers). "
                "Oversized packets may indicate jumbo-frame misconfiguration, "
                "data exfiltration, or a fragmentation-based evasion attempt. "
                "Individually low-risk, but worth investigating if recurring."
            ),
            "SYSTEM": "Internal IDS status message — not a network threat.",
        }

    # --------------------------------------------------
    # MAIN ALERT HANDLER
    # --------------------------------------------------
    def raise_alert(self, alert):
        """
        Processes alert dictionary
        """

        alert_type = alert.get("type", "UNKNOWN")
        src_ip = alert.get("src_ip", "N/A")
        message = alert.get("message", "")
        severity = self.severity_levels.get(alert_type, "INFO")

        formatted = self.format_alert(alert_type, src_ip, severity, message)

        self.print_alert(severity, formatted)
        self.log_alert(severity, formatted)

    # --------------------------------------------------
    # FORMAT ALERT
    # --------------------------------------------------
    def format_alert(self, alert_type, src_ip, severity, message):
        return f"[{alert_type}] | Severity: {severity} | Source: {src_ip} | {message}"

    # --------------------------------------------------
    # PRINT ALERT (COLORED)
    # --------------------------------------------------
    def print_alert(self, severity, text):

        if severity == "HIGH":
            print(Fore.RED + text)

        elif severity == "MEDIUM":
            print(Fore.YELLOW + text)

        elif severity == "LOW":
            print(Fore.CYAN + text)

        else:
            print(Fore.GREEN + text)

    # --------------------------------------------------
    # LOG ALERT TO FILE
    # --------------------------------------------------
    def log_alert(self, severity, text):

        if severity == "HIGH":
            logging.warning(text)

        elif severity == "MEDIUM":
            logging.info(text)

        elif severity == "LOW":
            logging.info(text)

        else:
            logging.info(text)

    # --------------------------------------------------
    # SYSTEM EVENTS (IDS STATUS)
    # --------------------------------------------------
    def system_event(self, message):

        alert = {
            "type": "SYSTEM",
            "src_ip": "LOCALHOST",
            "message": message
        }

        self.raise_alert(alert)


# --------------------------------------------------
# TEST MODE
# --------------------------------------------------
if __name__ == "__main__":

    alert_system = AlertSystem()

    test_alerts = [
        {"type": "PORT_SCAN", "src_ip": "192.168.1.10", "message": "Port scan detected"},
        {"type": "BRUTE_FORCE", "src_ip": "192.168.1.12", "message": "Repeated login attempts"},
        {"type": "TRAFFIC_SPIKE", "src_ip": "192.168.1.15", "message": "Unusual traffic spike"},
        {"type": "LARGE_PACKET", "src_ip": "192.168.1.20", "message": "Oversized packet"},
        {"type": "SYSTEM", "message": "IDS started successfully"}
    ]

    for alert in test_alerts:
        alert_system.raise_alert(alert)