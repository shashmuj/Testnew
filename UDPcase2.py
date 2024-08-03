import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP
import random

def send_udp_packet(src_ip, src_port, dst_ip, dst_port):
    # Randomize UDP length
    udp_length = random.randint(8, 65535)  # Minimum UDP packet length is 8 bytes

    # Create IP and UDP layers with all header fields
    ip = IP(
        version=4,
        ihl=None,
        tos=0,
        len=None,
        id=54321,
        flags=0,
        frag=0,
        ttl=64,
        proto='udp',
        chksum=None,
        src=src_ip,
        dst=dst_ip
    )
    udp = UDP(
        sport=src_port,
        dport=dst_port,
        len=udp_length,
        chksum=None
    )

    # Combine IP and UDP layers to form the packet
    packet = ip / udp

    # Send the packet
    send(packet)
    print("Packet sent:")
    packet.show2()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send a UDP packet with specified source and destination IPs and ports. UDP length is randomized.')
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('src_port', type=int, help='Source port')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('dst_port', type=int, help='Destination port')
    args = parser.parse_args()
    send_udp_packet(
        src_ip=args.src_ip,
        src_port=args.src_port,
        dst_ip=args.dst_ip,
        dst_port=args.dst_port
    )
