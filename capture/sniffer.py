
"""
Packet Capture Module for IDS
Captures live packets and forwards them for analysis
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime


class PacketSniffer:
    def __init__(self, interface=None, packet_callback=None):
        """
        interface : network interface to sniff on (None = default)
        packet_callback : function to send parsed packet data to detection engine
        """
        self.interface = interface
        self.packet_callback = packet_callback

    # -----------------------------
    # Packet Processing Function
    # -----------------------------
    def process_packet(self, packet):
        """
        Extract useful information from captured packet
        """

        if not packet.haslayer(IP):
            return  # ignore non-IP packets

        parsed_data = {
            "timestamp": datetime.now(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": None,
            "src_port": None,
            "dst_port": None,
            "packet_size": len(packet)
        }

        # Detect protocol
        if packet.haslayer(TCP):
            parsed_data["protocol"] = "TCP"
            parsed_data["src_port"] = packet[TCP].sport
            parsed_data["dst_port"] = packet[TCP].dport

        elif packet.haslayer(UDP):
            parsed_data["protocol"] = "UDP"
            parsed_data["src_port"] = packet[UDP].sport
            parsed_data["dst_port"] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            parsed_data["protocol"] = "ICMP"

        else:
            parsed_data["protocol"] = "OTHER"

        # Send data to detection engine if callback exists
        if self.packet_callback:
            self.packet_callback(packet)  # pass raw Scapy packet for parser
        else:
            self.default_output(parsed_data)

    # -----------------------------
    # Default Printer (Debug Mode)
    # -----------------------------
    def default_output(self, data):
        print(
            f"[{data['timestamp']}] "
            f"{data['src_ip']}:{data['src_port']} -> "
            f"{data['dst_ip']}:{data['dst_port']} | "
            f"{data['protocol']} | Size: {data['packet_size']}"
        )

    # -----------------------------
    # Start Sniffing
    # -----------------------------
    def start(self):
        print("Starting packet capture...\nPress Ctrl+C to stop.\n")

        sniff(
            iface=self.interface,
            prn=self.process_packet,
            store=False
        )


# -----------------------------
# Standalone Test Mode
# -----------------------------
if __name__ == "__main__":
    sniffer = PacketSniffer()
    sniffer.start()
