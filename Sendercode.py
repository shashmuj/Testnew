from scapy.all import Packet, BitField, ShortField, ByteField, IPField, XShortField, IntField, Raw, send, sniff, checksum
import struct
import argparse

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

def send_custom_ipv4_packet(custom_header_params):
    custom_header = MyCustomHeader(**custom_header_params)
    raw_packet = custom_header.build()
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        (custom_header.version << 4) | custom_header.ihl,
        0,
        custom_header.total_length,
        custom_header.identification,
        (custom_header.flags << 13) | custom_header.fragment_offset,
        custom_header.ttl,
        custom_header.protocol,
        0,
        struct.unpack('!I', struct.pack('!4s', custom_header.src))[0],
        struct.unpack('!I', struct.pack('!4s', custom_header.dst))[0]
    )
    
    ip_checksum = calculate_ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]

    packet = ip_header + raw_packet

    print("=== Sending Custom Packet ===")
    print(repr(packet))
    send(Raw(packet), count=1)

def handle_response(packet, sender_ip):
    ip_header = packet.getlayer(IP)
    if ip_header and ip_header.src == sender_ip:
        print("=== Received Response Packet ===")
        packet.show()

        if MyCustomHeader in packet:
            custom_header = packet[MyCustomHeader]
            print("=== Response Custom Header ===")
            print(f"Version: {custom_header.version}")
            print(f"IHL: {custom_header.ihl}")
            print(f"Total Length: {custom_header.total_length}")
            print(f"Identification: {custom_header.identification}")
            print(f"Flags: {custom_header.flags}")
            print(f"Fragment Offset: {custom_header.fragment_offset}")
            print(f"TTL: {custom_header.ttl}")
            print(f"Protocol: {custom_header.protocol}")
            print(f"Header Checksum: {hex(custom_header.header_checksum)}")
            print(f"Source IP: {custom_header.src}")
            print(f"Destination IP: {custom_header.dst}")
            print(f"Source Port: {custom_header.src_port}")
            print(f"Destination Port: {custom_header.dst_port}")
            print(f"Sequence Number: {custom_header.seq_num}")
            print(f"Acknowledgment Number: {custom_header.ack_num}")
            print(f"Data Offset: {custom_header.data_offset}")
            print(f"TCP Flags: {custom_header.tcp_flags}")
            print(f"TCP Checksum: {hex(custom_header.tcp_checksum)}")
            print(f"Window Size: {custom_header.window_size}")
            print(f"Urgent Pointer: {custom_header.urgent_pointer}")
        else:
            print("Received a packet with no custom header.")

def main():
    parser = argparse.ArgumentParser(description="Send and receive custom IPv4 packets")
    parser.add_argument("--src_ip", required=True, help="Source IP address")
    parser.add_argument("--dst_ip", required=True, help="Destination IP address")
    parser.add_argument("--src_port", type=int, default=12345, help="Source TCP port")
    parser.add_argument("--dst_port", type=int, default=80, help="Destination TCP port")
    parser.add_argument("--seq_num", type=int, default=1000, help="Sequence number")
    parser.add_argument("--ack_num", type=int, default=0, help="Acknowledgment number")
    parser.add_argument("--data_offset", type=int, default=5, help="Data offset")
    parser.add_argument("--tcp_flags", type=int, default=0, help="TCP flags")
    parser.add_argument("--tcp_checksum", type=int, default=0, help="TCP checksum")
    parser.add_argument("--window_size", type=int, default=8192, help="Window size")
    parser.add_argument("--urgent_pointer", type=int, default=0, help="Urgent pointer")
    parser.add_argument("--protocol", type=int, default=6, help="Protocol number (TCP is 6)")
    parser.add_argument("--ttl", type=int, default=64, help="Time To Live (TTL)")
    parser.add_argument("--identification", type=int, default=1234, help="Identification number")
    parser.add_argument("--flags", type=int, default=0, help="Fragmentation flags")
    parser.add_argument("--fragment_offset", type=int, default=0, help="Fragment offset")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on")
    parser.add_argument("--receiver_ip", required=True, help="Receiver IP address")

    args = parser.parse_args()

    custom_header_params = {
        "src": args.src_ip,
        "dst": args.dst_ip,
        "src_port": args.src_port,
        "dst_port": args.dst_port,
        "seq_num": args.seq_num,
        "ack_num": args.ack_num,
        "data_offset": args.data_offset,
        "tcp_flags": args.tcp_flags,
        "tcp_checksum": args.tcp_checksum,
        "window_size": args.window_size,
        "urgent_pointer": args.urgent_pointer,
        "protocol": args.protocol,
        "ttl": args.ttl,
        "identification": args.identification,
        "flags": args.flags,
        "fragment_offset": args.fragment_offset
    }

    send_custom_ipv4_packet(custom_header_params)

    print("Listening for responses from the receiver...")
    filter_str = f"ip src {args.receiver_ip} and ip dst {args.src_ip}"
    sniff(iface=args.iface, filter=filter_str, prn=lambda p: handle_response(p, args.receiver_ip))

if __name__ == "__main__":
    main()
