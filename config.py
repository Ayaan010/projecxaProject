# config.py
"""
Global Configuration File for IDS
Modify values here to tune detection behavior
"""

# ================================
# NETWORK SETTINGS
# ================================

INTERFACE = None
# Example:
# "eth0" for Linux
# "Wi-Fi" for Windows
# None = auto select


# ================================
# RULE ENGINE SETTINGS
# ================================

PORT_SCAN_THRESHOLD = 15
BRUTE_FORCE_THRESHOLD = 10
TIME_WINDOW = 10

SUSPICIOUS_PORTS = {
    4444,
    1337,
    6666,
    9999
}


# ================================
# ANOMALY ENGINE SETTINGS
# ================================

PACKET_RATE_THRESHOLD = 100
TRAFFIC_TIME_WINDOW = 5
LARGE_PACKET_SIZE = 1500


# ================================
# LOGGING SETTINGS
# ================================

LOG_FILE = "logs/alerts.log"


# ================================
# ALERT SETTINGS
# ================================

ENABLE_CONSOLE_ALERTS = True
ENABLE_FILE_LOGGING = True


# ================================
# PERFORMANCE SETTINGS
# ================================

MAX_TRACKED_IPS = 10000
CLEANUP_INTERVAL = 60  # seconds


# ================================
# DEBUG SETTINGS
# ================================

DEBUG_MODE = False
PRINT_PACKETS = False
