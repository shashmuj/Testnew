import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP

def send_udp_packet(src_ip, dst_ip):
    # Define default ports
    src_port = 12345
    dst_port = 80

    # Create IP and UDP layers with all header fields
    ip = IP(
        version=4,
        ihl=None,  # Internet Header Length (default is calculated automatically)
        tos=0,  # Type of Service
        len=None,  # Total Length (default is calculated automatically)
        id=54321,  # Identification
        flags=0,  # Flags
        frag=0,  # Fragment Offset
        ttl=64,  # Time to Live
        proto='udp',  # Protocol
        chksum=None,  # Header Checksum (default is calculated automatically)
        src=src_ip,  # Source IP Address
        dst=dst_ip  # Destination IP Address
    )
    udp = UDP(
        sport=src_port,  # Source Port
        dport=dst_port,  # Destination Port
        len=None,  # Length (default is calculated automatically)
        chksum=None  # Checksum (default is calculated automatically)
    )

    # Combine IP and UDP layers to form the packet
    packet = ip / udp

    # Send the packet
    send(packet)
    print("Packet sent:")
    packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send a UDP packet with specified source and destination IPs.')
    
    # Required arguments
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Call function with arguments
    send_udp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip
    )
