from scapy.all import Packet, BitField, ShortField, ByteField, IPField, XShortField, IntField, Raw, send, sniff, IP, TCP
import argparse
import random
import struct

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
        ByteField("protocol", 253),  # Custom protocol number
        XShortField("header_checksum", 0),  # IP header checksum
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        ShortField("src_port", 12345),
        ShortField("dst_port", 80),
        IntField("seq_num", 1000),
        IntField("ack_num", 0),
        BitField("data_offset", 5, 4),
        BitField("tcp_flags", 0, 9),
        ShortField("tcp_checksum", 0),  # TCP checksum
        ShortField("window_size", 8192),
        ShortField("urgent_pointer", 0),
    ]

    def post_build(self, p, pay):
        # Calculate and set the IP header checksum if not set
        if self.header_checksum == 0:
            ip_header = p[:20]  # IP header is the first 20 bytes
            ip_checksum = self.calculate_ip_checksum(ip_header)
            chksum_bytes = struct.pack('!H', ip_checksum)
            p = p[:10] + chksum_bytes + p[12:]

        # TCP checksum will be handled by Scapy
        return p + pay

    def calculate_ip_checksum(self, header):
        if len(header) % 2 != 0:
            header += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(header) // 2), header))
        s = (s >> 16) + (s & 0xFFFF)
        s = ~s & 0xFFFF
        return s

def print_ip_header(ip_layer):
    print("=== IP Header Details ===")
    print(f"Version: {ip_layer.version}")
    print(f"IHL: {ip_layer.ihl}")
    print(f"Total Length: {ip_layer.len}")
    print(f"Identification: {ip_layer.id}")
    print(f"Flags: {ip_layer.flags}")
    print(f"Fragment Offset: {ip_layer.frag}")
    print(f"TTL: {ip_layer.ttl}")
    print(f"Protocol: {ip_layer.proto}")
    print(f"Source IP: {ip_layer.src}")
    print(f"Destination IP: {ip_layer.dst}")

def print_tcp_header(tcp_layer):
    print("=== TCP Header Details ===")
    print(f"Source Port: {tcp_layer.sport}")
    print(f"Destination Port: {tcp_layer.dport}")
    print(f"Sequence Number: {tcp_layer.seq}")
    print(f"Acknowledgment Number: {tcp_layer.ack}")
    print(f"Data Offset: {tcp_layer.dataofs}")
    print(f"TCP Flags: {tcp_layer.flags}")
    print(f"Window Size: {tcp_layer.window}")
    print(f"Urgent Pointer: {tcp_layer.urgptr}")

def send_custom_ipv4_packet(custom_header_params):
    # Create the IP layer
    ip_layer = IP(
        src=custom_header_params["src"],
        dst=custom_header_params["dst"],
        version=custom_header_params["version"],
        ihl=custom_header_params["ihl"],
        len=custom_header_params["total_length"],
        id=custom_header_params["identification"],
        flags=custom_header_params["flags"],
        frag=custom_header_params["fragment_offset"],
        ttl=custom_header_params["ttl"],
        proto=custom_header_params["protocol"]
    )

    # Print IP header details
    print_ip_header(ip_layer)

    # Create the TCP layer
    tcp_layer = TCP(
        sport=custom_header_params["src_port"],
        dport=custom_header_params["dst_port"],
        seq=custom_header_params["seq_num"],
        ack=custom_header_params["ack_num"],
        dataofs=custom_header_params["data_offset"],
        flags=custom_header_params["tcp_flags"],
        window=custom_header_params["window_size"],
        urgptr=custom_header_params["urgent_pointer"]
    )

    # Print TCP header details
    print_tcp_header(tcp_layer)

    # Create the custom header
    custom_header = MyCustomHeader(**custom_header_params)

    # Build the final packet
    raw_packet = custom_header.build()
    
    # Combine IP layer and TCP layer with custom header
    packet = ip_layer / tcp_layer / Raw(load=raw_packet)

    # Send the packet
    send(packet)
    print("=== Sent Custom Packet ===")
    packet.show()

def handle_response(packet):
    if packet.haslayer(Raw):
        response = packet[Raw].load
        # Extract IP and TCP layers from the response
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        print("=== Received Response Packet ===")
        print_ip_header(ip_layer)
        print_tcp_header(tcp_layer)
        print("Payload:")
        print(response.decode('utf-8', errors='ignore'))  # Decode and handle non-UTF8 responses gracefully

def main():
    parser = argparse.ArgumentParser(description="Send custom IPv4 packets and receive responses")
    parser.add_argument("--iface", required=True, help="Network interface to use")
    parser.add_argument("--src", required=True, help="Source IP address")
    parser.add_argument("--dst", required=True, help="Destination IP address")
    parser.add_argument("--src_port", type=int, default=12345, help="Source port")
    parser.add_argument("--dst_port", type=int, default=80, help="Destination port")
    parser.add_argument("--seq_num", type=int, default=random.randint(1, 10000), help="Sequence number")
    parser.add_argument("--ack_num", type=int, default=0, help="Acknowledgment number")
    parser.add_argument("--data_offset", type=int, default=5, help="Data offset")
    parser.add_argument("--tcp_flags", type=int, default=0, help="TCP flags")
    parser.add_argument("--window_size", type=int, default=8192, help="Window size")
    parser.add_argument("--urgent_pointer", type=int, default=0, help="Urgent pointer")

    args = parser.parse_args()

    # Prepare and send a custom packet
    custom_header_params = {
        "version": 4,
        "ihl": 5,
        "total_length": 40,
        "identification": 0,
        "flags": 0,
        "fragment_offset": 0,
        "ttl": 64,
        "protocol": 253,  # Custom protocol number
        "header_checksum": 0,  # Placeholder for IP checksum
        "src": args.src,
        "dst": args.dst,
        "src_port": args.src_port,
        "dst_port": args.dst_port,
        "seq_num": args.seq_num,
        "ack_num": args.ack_num,
        "data_offset": args.data_offset,
        "tcp_flags": args.tcp_flags,
        "tcp_checksum": 0,  # Placeholder for TCP checksum
        "window_size": args.window_size,
        "urgent_pointer": args.urgent_pointer
    }
    send_custom_ipv4_packet(custom_header_params)
    
    # Sniff for responses from the receiver IP
    filter_str = f"ip src {args.dst}"
    print("Starting packet sniffing for responses...")
    sniff(iface=args.iface, filter=filter_str, prn=handle_response)

if __name__ == "__main__":
    main()
