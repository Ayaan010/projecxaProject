# packet_parser.py
"""
Packet Parsing Module
Extracts structured information from captured packets
"""

from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP


class PacketParser:
    def __init__(self):
        pass

    # -------------------------------------------------
    # Main parsing function
    # -------------------------------------------------
    def parse(self, packet):
        """
        Extract useful information from packet object
        Returns structured dictionary
        """

        # Ignore non-IP packets
        if not packet.haslayer(IP):
            return None

        parsed_data = {
            "timestamp": datetime.now(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": self.get_protocol(packet),
            "src_port": self.get_src_port(packet),
            "dst_port": self.get_dst_port(packet),
            "packet_size": len(packet),
            "flags": self.get_tcp_flags(packet)
        }

        return parsed_data

    # -------------------------------------------------
    # Protocol Detection
    # -------------------------------------------------
    def get_protocol(self, packet):
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        else:
            return "OTHER"

    # -------------------------------------------------
    # Source Port Extraction
    # -------------------------------------------------
    def get_src_port(self, packet):
        if packet.haslayer(TCP):
            return packet[TCP].sport
        elif packet.haslayer(UDP):
            return packet[UDP].sport
        return None

    # -------------------------------------------------
    # Destination Port Extraction
    # -------------------------------------------------
    def get_dst_port(self, packet):
        if packet.haslayer(TCP):
            return packet[TCP].dport
        elif packet.haslayer(UDP):
            return packet[UDP].dport
        return None

    # -------------------------------------------------
    # TCP Flag Extraction (important for attack detection)
    # -------------------------------------------------
    def get_tcp_flags(self, packet):
        if packet.haslayer(TCP):
            return str(packet[TCP].flags)
        return None

    # -------------------------------------------------
    # Packet Validation
    # -------------------------------------------------
    def validate(self, parsed_packet):
        """
        Basic validation check
        Returns True if packet is usable
        """

        if parsed_packet is None:
            return False

        if parsed_packet["src_ip"] is None or parsed_packet["dst_ip"] is None:
            return False

        if parsed_packet["protocol"] is None:
            return False

        return True

    # -------------------------------------------------
    # Pretty Printer (Debugging)
    # -------------------------------------------------
    def pretty_print(self, data):
        print(
            f"[{data['timestamp']}] "
            f"{data['src_ip']}:{data['src_port']} → "
            f"{data['dst_ip']}:{data['dst_port']} | "
            f"{data['protocol']} | Size={data['packet_size']} | "
            f"Flags={data['flags']}"
        )


# -------------------------------------------------
# Standalone Testing
# -------------------------------------------------
if __name__ == "__main__":

    from scapy.all import sniff

    parser = PacketParser()

    def test(packet):
        parsed = parser.parse(packet)
        if parser.validate(parsed):
            parser.pretty_print(parsed)

    print("Testing Packet Parser... Press Ctrl+C to stop\n")

    sniff(prn=test, store=False)
