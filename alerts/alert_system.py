# alert_system.py
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
