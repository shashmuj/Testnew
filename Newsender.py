import sys
from scapy.all import Packet, ByteField, ShortField, IntField, IPField, XShortField, FlagsField, send

class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        # IP header fields
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("id", 54321),
        ShortField("frag", 0),
        ByteField("ttl", 64),
        ByteField("proto", 6),  # TCP protocol number
        XShortField("chksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        
        # TCP header fields
        ShortField("sport", 12345),
        ShortField("dport", 80),
        IntField("seq", 1000),
        IntField("ack", 0),
        ByteField("dataofs", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0x02, 8, "FSRPAUEC"),  # SYN flag set
        ShortField("window", 8192),
        XShortField("tcp_chksum", None),
        ShortField("urgptr", 0)
    ]

def create_packet(src_ip, dst_ip, proto_number):
    # Create the custom packet with given source, destination, and protocol number
    packet = CustomProtocol(src=src_ip, dst=dst_ip, proto=proto_number)
    return packet

def send_packet(packet):
    # Send the packet
    send(packet)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python send_custom_packet.py <src_ip> <dst_ip> <proto_number>")
        sys.exit(1)
    
    src_ip = sys.argv[1]
    dst_ip = sys.argv[2]
    proto_number = int(sys.argv[3])
    
    packet = create_packet(src_ip, dst_ip, proto_number)
    send_packet(packet)
