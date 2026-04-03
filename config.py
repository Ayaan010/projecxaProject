"""
Global Configuration File for IDS
Modify values here to tune detection behavior
"""

# ================================
# NETWORK SETTINGS
# ================================

INTERFACE = "Wi-Fi"  # Change back from Ethernet
# Change to "Ethernet" if you are on a wired connection.
# Run `py -c "from scapy.all import conf; print(conf.iface)"` to confirm default.
# None = scapy auto-selects (may pick wrong interface)


# ================================
# RULE ENGINE SETTINGS
# ================================

PORT_SCAN_THRESHOLD = 15        # unique ports in TIME_WINDOW seconds
BRUTE_FORCE_THRESHOLD = 10      # connection attempts in TIME_WINDOW seconds
SYN_SCAN_THRESHOLD = 20         # SYN-only packets in TIME_WINDOW seconds
TIME_WINDOW = 10

SUSPICIOUS_PORTS = {
    # Metasploit / common reverse-shell defaults
    4444,
    # Hacker culture / commonly used in CTF shells
    1337,
    # Frequently used by malware C2 channels
    6666,
    9999,
    # Back Orifice (classic RAT)
    31337,
    # IRC — botnet command-and-control
    6667,
    # Android Debug Bridge (ADB) — remote device exploitation
    5555,
    # Generic backdoor
    1234,
    12345,
}


# ================================
# ANOMALY ENGINE SETTINGS
# ================================

PACKET_RATE_THRESHOLD = 100     # packets per TRAFFIC_TIME_WINDOW seconds from one IP
TRAFFIC_TIME_WINDOW = 5
# Ethernet MTU is 1500 bytes for the payload, but Scapy's len(packet) includes
# all headers (Ethernet 14 B + IP 20 B + TCP 20 B = ~54 B overhead).
# Standard maximum frame is ~1514 B.  We use 1600 B to avoid false positives
# on normal large frames while still catching genuinely oversized/jumbo packets.
LARGE_PACKET_SIZE = 1600


# ================================
# LOGGING SETTINGS  (log file path set in PATHS block below)
# ================================


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
# AUTO-BLOCKING SETTINGS
# When an IP triggers HIGH-severity alerts >= AUTO_BLOCK_THRESHOLD times,
# it is automatically added to the blocked list and all further packets
# from that IP are ignored by the detection pipeline.
# ================================

ENABLE_AUTO_BLOCK = True
AUTO_BLOCK_THRESHOLD = 3   # number of HIGH alerts before an IP is blocked

# ================================
# DEBUG SETTINGS
# ================================

DEBUG_MODE = False
PRINT_PACKETS = False

# ================================
# PATHS + PRODUCTION SETTINGS
# All paths are absolute so the app works regardless of working directory.
# Override any value with an environment variable on each machine:
#   set IDS_INTERFACE=Ethernet
#   set IDS_HOST=0.0.0.0
#   set IDS_PORT=5000
#   set IDS_USER=admin
#   set IDS_PASSWORD=yourpassword
#   set IDS_SECRET_KEY=a-long-random-string
# ================================
import os as _os
_BASE_DIR = _os.path.dirname(_os.path.abspath(__file__))

LOG_FILE      = _os.path.join(_BASE_DIR, "logs", "alerts.log")
DATABASE_PATH = _os.path.join(_BASE_DIR, "ids_database.db")

INTERFACE          = _os.environ.get("IDS_INTERFACE", INTERFACE)
DASHBOARD_HOST     = _os.environ.get("IDS_HOST", "0.0.0.0")
DASHBOARD_PORT     = int(_os.environ.get("IDS_PORT", "5000"))
DASHBOARD_USER     = _os.environ.get("IDS_USER", "admin")
DASHBOARD_PASSWORD = _os.environ.get("IDS_PASSWORD", "changeme")
SECRET_KEY         = _os.environ.get("IDS_SECRET_KEY", "ids-dashboard-secret-change-me")
