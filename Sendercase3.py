import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP
import random

def send_tcp_packet(src_ip, dst_ip, proto):
    # Generate random source and destination ports
    src_port = random.randint(1024, 65535)  # Random port number between 1024 and 65535
    dst_port = random.randint(1024, 65535)  # Random port number between 1024 and 65535

    # Create IP and TCP layers
    ip = IP(
        version=4,
        ihl=5,
        tos=random.randint(0, 255),
        id=random.randint(0, 65535),
        frag=0,
        ttl=random.randint(1, 255),
        proto=proto,
        chksum=None,
        src=src_ip,
        dst=dst_ip
    )
    tcp = TCP(
        sport=src_port,
        dport=dst_port,
        flags=random.choice("FSRPAUEC"),  # Random flag from TCP flags
        seq=random.randint(0, 4294967295),  # Random sequence number
        ack=random.randint(0, 4294967295),  # Random acknowledgment number
        dataofs=random.randint(5, 15),  # Random data offset (header length)
        reserved=random.randint(0, 7),  # Random reserved bits
        window=random.randint(0, 65535),  # Random window size
        chksum=None,  # Checksum will be calculated by Scapy
        urgptr=random.randint(0, 65535)  # Random urgent pointer
    )

    # Combine IP and TCP layers to form the packet
    packet = ip / tcp

    # Send the packet
    send(packet)
    print("Packet sent:")
    packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send a TCP packet with specified source and destination IPs and protocol.')
    
    # Required arguments
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('proto', type=int, help='IP protocol number')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Call function with arguments
    send_tcp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        proto=args.proto
    )
