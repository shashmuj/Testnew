import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP

def send_udp_packet(src_ip, dst_ip, src_port, dst_port, proto):
    # Create IP and UDP layers
    ip = IP(
        version=4,
        ihl=5,
        tos=0,
        id=54321,
        frag=0,
        ttl=64,
        proto=proto,
        chksum=None,
        src=src_ip,
        dst=dst_ip
    )
    udp = UDP(
        sport=src_port,
        dport=dst_port,
        len=8,  # Length of UDP header + payload
        chksum=None
    )

    # Combine IP and UDP layers to form the packet
    packet = ip / udp

    # Send the packet
    send(packet)
    print("Packet sent:")
    packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send a UDP packet with specified source and destination IPs and ports.')
    
    # Required arguments
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('src_port', type=int, help='Source port number')
    parser.add_argument('dst_port', type=int, help='Destination port number')
    parser.add_argument('proto', type=int, help='IP protocol number')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Call function with arguments
    send_udp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        proto=args.proto
    )
