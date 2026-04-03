
"""
Anomaly Detection Engine
Detects abnormal traffic patterns
"""

from collections import defaultdict
from datetime import datetime, timedelta
import config


class AnomalyDetector:
    def __init__(self):

        # traffic tracking
        self.packet_rate = defaultdict(list)
        self.packet_size_tracker = defaultdict(list)

        # thresholds (read from config)
        self.PACKET_RATE_THRESHOLD = config.PACKET_RATE_THRESHOLD
        self.TIME_WINDOW = config.TRAFFIC_TIME_WINDOW
        self.LARGE_PACKET_SIZE = config.LARGE_PACKET_SIZE

    # --------------------------------------------------
    # MAIN CHECK FUNCTION
    # --------------------------------------------------
    def detect(self, packet):
        alerts = []

        alerts += self.detect_high_traffic(packet)
        alerts += self.detect_large_packets(packet)

        return alerts

    # --------------------------------------------------
    # TRAFFIC SPIKE DETECTION
    # --------------------------------------------------
    def detect_high_traffic(self, packet):
        alerts = []

        src = packet["src_ip"]
        now = datetime.now()

        self.packet_rate[src].append(now)

        # remove old entries
        self.packet_rate[src] = [
            t for t in self.packet_rate[src]
            if now - t < timedelta(seconds=self.TIME_WINDOW)
        ]

        if len(self.packet_rate[src]) > self.PACKET_RATE_THRESHOLD:
            alerts.append({
                "type": "TRAFFIC_SPIKE",
                "src_ip": src,
                "message": f"High traffic rate detected from {src}"
            })
            self.packet_rate[src].clear()

        return alerts

    # --------------------------------------------------
    # LARGE PACKET DETECTION
    # --------------------------------------------------
    def detect_large_packets(self, packet):
        alerts = []

        if packet["packet_size"] > self.LARGE_PACKET_SIZE:
            alerts.append({
                "type": "LARGE_PACKET",
                "src_ip": packet["src_ip"],
                "message": f"Unusually large packet from {packet['src_ip']}"
            })

        return alerts