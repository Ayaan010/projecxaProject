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

        # Per-alert-type counts (for breakdown chart)
        self.alert_type_counts = defaultdict(int)

        # Per-IP total alert counts (for top-threats table)
        self.ip_alert_counts = defaultdict(int)

        # Per-IP HIGH severity alert counts (drives auto-block logic)
        self.ip_high_counts = defaultdict(int)

        # Blocked IPs — packets from these are skipped entirely
        self.blocked_ips = set()

        # Pending block requests — IPs awaiting user confirmation
        # Each entry: {"ip": str, "reason": str, "high_alerts": int, "timestamp": str}
        self.pending_blocks = []

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
            alert_type = alert_dict.get("type", "UNKNOWN")
            severity = alert_dict.get("severity", "INFO")
            src_ip = alert_dict.get("src_ip", "N/A")

            entry = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": alert_type,
                "src_ip": src_ip,
                "message": alert_dict.get("message", ""),
                "severity": severity,
            }
            self.recent_alerts.insert(0, entry)
            if len(self.recent_alerts) > self.MAX_ALERTS:
                self.recent_alerts = self.recent_alerts[:self.MAX_ALERTS]

            # Track per-type breakdown
            self.alert_type_counts[alert_type] += 1

            # Track per-IP counts
            if src_ip and src_ip != "N/A":
                self.ip_alert_counts[src_ip] += 1
                if severity == "HIGH":
                    self.ip_high_counts[src_ip] += 1

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

    def get_alert_type_counts(self):
        """Return dict of alert_type -> count for breakdown chart."""
        with self.lock:
            return dict(self.alert_type_counts)

    def get_top_threat_ips(self, n=10):
        """Return top-N IPs sorted by total alert count."""
        with self.lock:
            sorted_ips = sorted(self.ip_alert_counts.items(), key=lambda x: x[1], reverse=True)
            return [
                {"ip": ip, "total_alerts": count, "high_alerts": self.ip_high_counts.get(ip, 0)}
                for ip, count in sorted_ips[:n]
            ]

    def is_blocked(self, ip):
        with self.lock:
            return ip in self.blocked_ips

    def block_ip(self, ip):
        with self.lock:
            self.blocked_ips.add(ip)

    def unblock_ip(self, ip):
        with self.lock:
            self.blocked_ips.discard(ip)

    def get_blocked_ips(self):
        with self.lock:
            return sorted(self.blocked_ips)

    def request_block(self, ip, reason):
        """Add IP to pending-block queue if not already blocked or already pending."""
        with self.lock:
            already = any(p["ip"] == ip for p in self.pending_blocks)
            if ip not in self.blocked_ips and not already:
                self.pending_blocks.append({
                    "ip": ip,
                    "reason": reason,
                    "high_alerts": self.ip_high_counts.get(ip, 0),
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                })

    def confirm_block(self, ip):
        """Approve a pending block request — moves IP to blocked set."""
        with self.lock:
            self.pending_blocks = [p for p in self.pending_blocks if p["ip"] != ip]
            self.blocked_ips.add(ip)

    def dismiss_block(self, ip):
        """Dismiss a pending block request without blocking."""
        with self.lock:
            self.pending_blocks = [p for p in self.pending_blocks if p["ip"] != ip]

    def get_pending_blocks(self):
        with self.lock:
            return list(self.pending_blocks)

    def should_request_block(self, ip, threshold):
        """True if IP hit the HIGH threshold and has no existing block or pending request."""
        with self.lock:
            already_pending = any(p["ip"] == ip for p in self.pending_blocks)
            return (
                ip not in self.blocked_ips
                and not already_pending
                and self.ip_high_counts.get(ip, 0) >= threshold
            )

    def get_ip_detail(self, ip):
        """Return all known information about a specific IP for the threat-detail page."""
        with self.lock:
            # All alerts from this IP
            alerts = [a for a in self.recent_alerts if a.get("src_ip") == ip]

            # Per-type breakdown for this IP
            type_counts = defaultdict(int)
            for a in alerts:
                type_counts[a.get("type", "UNKNOWN")] += 1

            # First and last seen
            timestamps = [a["timestamp"] for a in alerts if a.get("timestamp")]
            first_seen = timestamps[-1] if timestamps else None
            last_seen  = timestamps[0]  if timestamps else None

            return {
                "ip": ip,
                "total_alerts": self.ip_alert_counts.get(ip, 0),
                "high_alerts":  self.ip_high_counts.get(ip, 0),
                "is_blocked":   ip in self.blocked_ips,
                "is_pending":   any(p["ip"] == ip for p in self.pending_blocks),
                "type_counts":  dict(type_counts),
                "recent_alerts": alerts[:50],
                "first_seen": first_seen,
                "last_seen":  last_seen,
            }


# Global instance
ids_state = IDSState()
