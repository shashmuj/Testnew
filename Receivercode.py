from scapy.all import sniff, IP, send, Raw, Packet, checksum
from scapy.fields import BitField, ShortField, ByteField, IPField, XShortField, IntField
import struct
import argparse
import sys

# Define the custom header class for the receiver
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

def handle_packet(packet, sender_ip):
    ip_header = packet.getlayer(IP)

    if MyCustomHeader in packet:
        custom_header = packet[MyCustomHeader]
        
        # Ensure the packet is from the sender IP
        if ip_header.src == sender_ip:
            print("=== Received Packet ===")
            packet.show()

            # Print the details of the custom header
            print("=== Custom Header ===")
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

            # Validate IP header checksum
            ip_header_data = struct.pack(
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
            if custom_header.header_checksum != calculate_ip_checksum(ip_header_data):
                print("Invalid IP checksum.")
            else:
                print("Valid IP checksum.")

            # Validate TCP checksum
            tcp_header = struct.pack(
                '!HHLLBBHHH',
                custom_header.src_port,
                custom_header.dst_port,
                custom_header.seq_num,
                custom_header.ack_num,
                (custom_header.data_offset << 4) | (custom_header.tcp_flags >> 8),
                custom_header.tcp_flags & 0xFF,
                custom_header.tcp_checksum,
                custom_header.window_size,
                custom_header.urgent_pointer
            )
            if custom_header.tcp_checksum != calculate_tcp_checksum(ip_header_data, tcp_header, b''):
                print("Invalid TCP checksum.")
            else:
                print("Valid TCP checksum.")

            # Prepare and send a response packet
            response = IP(src=ip_header.dst, dst=ip_header.src) / Raw(load="Packet received")
            print("=== Sending Response Packet ===")
            response.show()
            send(response)

        else:
            print(f"Ignored packet from {ip_header.src} as it is not from the sender {sender_ip}")

def main():
    parser = argparse.ArgumentParser(description="Receive and respond to custom IPv4 packets")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on")
    parser.add_argument("--sender_ip", required=True, help="Sender IP address")

    args = parser.parse_args()

    filter_str = f"ip src {args.sender_ip}"

    try:
        print("Starting packet sniffing...")
        sniff(iface=args.iface, filter=filter_str, prn=lambda packet: handle_packet(packet, args.sender_ip))
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
