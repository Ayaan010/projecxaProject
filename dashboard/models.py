"""
Dashboard Data Models
Shared state for IDS metrics accessible by Flask routes
"""

import threading
from collections import defaultdict
from datetime import datetime


class IDSState:
    """Thread-safe singleton holding live IDS metrics."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._init_state()
        return cls._instance

    def _init_state(self):
        self.lock = threading.Lock()
        self.running = False
        self.start_time = None
        self.total_packets = 0
        self.total_alerts = 0

        # Protocol counters
        self.protocol_counts = defaultdict(int)

        # Traffic rate tracking (timestamp list for packets-per-second calc)
        self.recent_packets = []  # list of timestamps
        self.MAX_RECENT = 600     # keep last 600 entries

        # Recent alerts for quick display
        self.recent_alerts = []   # list of dicts
        self.MAX_ALERTS = 200

        # Traffic volume snapshots: list of (timestamp, packet_count)
        self.traffic_snapshots = []
        self.MAX_SNAPSHOTS = 120

    # ---- mutators (called from IDS thread) ----

    def record_packet(self, protocol):
        with self.lock:
            self.total_packets += 1
            self.protocol_counts[protocol] += 1
            now = datetime.now()
            self.recent_packets.append(now)
            if len(self.recent_packets) > self.MAX_RECENT:
                self.recent_packets = self.recent_packets[-self.MAX_RECENT:]

    def record_alert(self, alert_dict):
        with self.lock:
            self.total_alerts += 1
            entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": alert_dict.get("type", "UNKNOWN"),
                "src_ip": alert_dict.get("src_ip", "N/A"),
                "message": alert_dict.get("message", ""),
                "severity": alert_dict.get("severity", "INFO"),
            }
            self.recent_alerts.insert(0, entry)
            if len(self.recent_alerts) > self.MAX_ALERTS:
                self.recent_alerts = self.recent_alerts[:self.MAX_ALERTS]

    def take_traffic_snapshot(self):
        with self.lock:
            self.traffic_snapshots.append(
                (datetime.now().strftime("%H:%M:%S"), self.total_packets)
            )
            if len(self.traffic_snapshots) > self.MAX_SNAPSHOTS:
                self.traffic_snapshots = self.traffic_snapshots[-self.MAX_SNAPSHOTS:]

    def set_running(self, status: bool):
        with self.lock:
            self.running = status
            if status:
                self.start_time = datetime.now()

    # ---- readers (called from Flask routes) ----

    def get_status(self):
        with self.lock:
            uptime = ""
            if self.start_time and self.running:
                delta = datetime.now() - self.start_time
                hours, rem = divmod(int(delta.total_seconds()), 3600)
                minutes, seconds = divmod(rem, 60)
                uptime = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            return {
                "running": self.running,
                "uptime": uptime,
                "total_packets": self.total_packets,
                "total_alerts": self.total_alerts,
            }

    def get_protocol_distribution(self):
        with self.lock:
            return dict(self.protocol_counts)

    def get_traffic_snapshots(self):
        with self.lock:
            return list(self.traffic_snapshots)

    def get_recent_alerts(self, limit=50):
        with self.lock:
            return list(self.recent_alerts[:limit])


# Global instance
ids_state = IDSState()
