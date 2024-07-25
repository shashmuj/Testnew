from scapy.all import Packet, BitField, ShortField, ByteField, IPField, XShortField, IntField, Raw, send, sniff, checksum
import struct
import argparse
import random

# Function to generate checksum
def checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s = ~s & 0xFFFF
    return s

# Define the custom header class for the sender
class MyCustomHeader(Packet):
    name = "MyCustomHeader"
    fields_desc = [
        BitField("version", 4, 4),
        BitField("ihl", 5, 4),
        ShortField("total_length", 40),
        ShortField("identification", 0),
        BitField("flags", 0, 3),
        BitField("fragment_offset", 0, 13),
        ByteField("ttl", 64),
        ByteField("protocol", 6),
        XShortField("header_checksum", 0),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        ShortField("src_port", 12345),
        ShortField("dst_port", 80),
        IntField("seq_num", 1000),
        IntField("ack_num", 0),
        BitField("data_offset", 5, 4),
        BitField("tcp_flags", 0, 9),
        ShortField("tcp_checksum", 0),
        ShortField("window_size", 8192),
        ShortField("urgent_pointer", 0),
    ]

    def post_build(self, p, pay):
        if self.header_checksum == 0:
            chksum = calculate_ip_checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

def calculate_ip_checksum(header):
    if len(header) % 2 != 0:
        header += b'\x00'
    return checksum(header)

def calculate_tcp_checksum(ip_header, tcp_header, data):
    pseudo_header = struct.pack(
        '!4s4sBBH',
        struct.unpack('!4s', ip_header[12:16])[0],  # Source IP
        struct.unpack('!4s', ip_header[16:20])[0],  # Destination IP
        0,  # Reserved, must be zero
        6,  # Protocol (TCP)
        len(tcp_header) + len(data)  # TCP length
    )
    tcp_data = pseudo_header + tcp_header + data
    return checksum(tcp_data)

def send_custom_ipv4_packet(custom_header_params):
    custom_header = MyCustomHeader(**custom_header_params)
    raw_packet = custom_header.build()
    
    # Send the custom header packet
    packet = IP(src=custom_header.src, dst=custom_header.dst) / Raw(load=raw_packet)
    send(packet)
    print("=== Sent Custom Packet ===")
    packet.show()

def handle_response(packet):
    if packet.haslayer(Raw):
        response = packet[Raw].load.decode('utf-8')
        print("=== Received Response Packet ===")
        print(response)

def main():
    parser = argparse.ArgumentParser(description="Send custom IPv4 packets and receive responses")
    parser.add_argument("--iface", required=True, help="Network interface to use")
    parser.add_argument("--receiver_ip", required=True, help="Receiver IP address")
    parser.add_argument("--port", type=int, default=12345, help="Port number for communication")
    parser.add_argument("--src", default="192.168.1.10", help="Source IP address")
    parser.add_argument("--dst", default="0.0.0.0", help="Destination IP address")
    parser.add_argument("--src_port", type=int, default=12345, help="Source port")
    parser.add_argument("--dst_port", type=int, default=80, help="Destination port")
    parser.add_argument("--seq_num", type=int, default=random.randint(1, 10000), help="Sequence number")
    parser.add_argument("--ack_num", type=int, default=0, help="Acknowledgment number")
    parser.add_argument("--tcp_checksum", type=int, default=0, help="TCP checksum (default: 0)")

    args = parser.parse_args()

    # Prepare and send a custom packet
    custom_header_params = {
        "src": args.src,
        "dst": args.receiver_ip,
        "src_port": args.src_port,
        "dst_port": args.dst_port,
        "seq_num": args.seq_num,
        "ack_num": args.ack_num,
        "tcp_checksum": args.tcp_checksum,  # Placeholder, will be updated
    }
    send_custom_ipv4_packet(custom_header_params)
    
    # Sniff for responses from the receiver IP
    filter_str = f"ip src {args.receiver_ip}"
    print("Starting packet sniffing for responses...")
    sniff(iface=args.iface, filter=filter_str, prn=handle_response)

if __name__ == "__main__":
    main()
