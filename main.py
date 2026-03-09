"""
Main Controller for Intrusion Detection System
Connects all modules together
"""

import config

from capture.sniffer import PacketSniffer
from parser.packet_parser import PacketParser
from detection.rules import RuleEngine
from detection.anomaly import AnomalyDetector
from alerts.alert_system import AlertSystem


class IDSController:
    def __init__(self):

        # initialize modules
        self.parser = PacketParser()
        self.rule_engine = RuleEngine()
        self.anomaly_engine = AnomalyDetector()
        self.alert_system = AlertSystem(config.LOG_FILE)

        # initialize sniffer with callback
        self.sniffer = PacketSniffer(
            interface=config.INTERFACE,
            packet_callback=self.process_packet
        )

    # --------------------------------------------------
    # MAIN PACKET PIPELINE
    # --------------------------------------------------
    def process_packet(self, raw_packet):
        """
        Full packet processing pipeline
        """

        # Step 1 — Parse packet
        parsed = self.parser.parse(raw_packet)

        if not self.parser.validate(parsed):
            return

        # Optional debug output
        if config.PRINT_PACKETS:
            self.parser.pretty_print(parsed)

        # Step 2 — Rule detection
        rule_alerts = self.rule_engine.check_rules(parsed)

        # Step 3 — Anomaly detection
        anomaly_alerts = self.anomaly_engine.detect(parsed)

        # Step 4 — Combine alerts
        all_alerts = rule_alerts + anomaly_alerts

        # Step 5 — Send alerts
        for alert in all_alerts:
            self.alert_system.raise_alert(alert)

    # --------------------------------------------------
    # START IDS
    # --------------------------------------------------
    def start(self):
        self.alert_system.system_event("IDS Started Successfully")

        try:
            self.sniffer.start()

        except KeyboardInterrupt:
            self.alert_system.system_event("IDS Stopped Manually")

        except Exception as e:
            self.alert_system.system_event(f"System Error: {str(e)}")


# --------------------------------------------------
# RUN IDS
# --------------------------------------------------
if __name__ == "__main__":

    ids = IDSController()
    ids.start()