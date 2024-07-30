import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP

def send_tcp_packet(src_ip, dst_ip, src_port, dst_port, proto):
    # Create IP and TCP layers
    ip = IP(
        version=4,
        ihl=5,  # IP header length (5 means no options, total header length is 20 bytes)
        tos=0,
        id=54321,
        frag=0,
        ttl=64,
        proto=proto,  # Custom protocol number
        chksum=None,
        src=src_ip,
        dst=dst_ip
    )
    tcp = TCP(
        sport=src_port,
        dport=dst_port,
        flags="S",  # SYN flag set
        seq=1000,
        ack=0,
        dataofs=5,  # TCP header length (5 means no options, total header length is 20 bytes)
        reserved=0,
        window=8192,
        chksum=None,
        urgptr=0
    )

    # Combine IP and TCP layers to form the packet
    packet = ip / tcp

    # Send the packet
    send(packet)
    print("Packet sent:")
    packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send a TCP packet with specified source and destination IPs and ports.')
    
    # Required arguments
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('src_port', type=int, help='Source port number')
    parser.add_argument('dst_port', type=int, help='Destination port number')
    parser.add_argument('proto', type=int, help='IP protocol number')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Call function with arguments
    send_tcp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        proto=args.proto
    )
