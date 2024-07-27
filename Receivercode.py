from scapy.all import *
import argparse

# Define the custom protocol with both IPv4 and TCP fields
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        # IPv4 fields
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("len", 0),
        ShortField("id", 1),
        ShortField("frag_off", 0),
        ByteField("ttl", 64),
        ByteField("proto", 253),
        XShortField("chksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        # TCP fields
        ShortField("sport", 12345),
        ShortField("dport", 80),
        IntField("seq", 0),
        IntField("ack", 0),
        ByteField("dataofs", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0, 8, ["F", "S", "R", "P", "A", "U", "E", "C"]),
        ShortField("window", 8192),
        XShortField("tcp_chksum", None),
        ShortField("urgptr", 0)
    ]

def process_packet(packet):
    # Check if the packet has our custom protocol and matches the intended source IP
    if CustomProtocol in packet:
        if packet[CustomProtocol].src == src_ip:
            # Packet is of the custom protocol and from the intended source IP
            print("Received custom protocol packet:")
            packet.show()
        else:
            # Packet is of the custom protocol but from an unexpected source IP
            print("Received custom protocol packet from an unexpected source IP:")
            packet.show()
    else:
        # Packet is not of the custom protocol
        print("Received packet with an unexpected protocol:")
        packet.show()

def main():
    parser = argparse.ArgumentParser(description="Receive and process packets.")
    parser.add_argument("src_ip", help="Source IP address")
    parser.add_argument("dst_ip", help="Destination IP address")
    args = parser.parse_args()
    
    global src_ip  # Use a global variable to access in process_packet
    src_ip = args.src_ip
    
    # Define the filter expression to match packets from the specified source IP and destination IP
    filter_expr = f"ip src {src_ip} and ip dst {args.dst_ip} and ip proto 253"
    
    print("Sniffing for packets...")
    packets = sniff(filter=filter_expr, iface=conf.iface, timeout=10)  # Timeout to prevent indefinite blocking

    if not packets:
        print("No packets received.")

    for packet in packets:
        process_packet(packet)

if __name__ == "__main__":
    main()
