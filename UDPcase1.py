import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP
import random

def send_udp_packet(src_ip, dst_ip, dst_port):
    # Randomize source port
    src_port = random.randint(1024, 65535)

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
        len=None,
        chksum=None
    )

    # Combine IP and UDP layers to form the packet
    packet = ip / udp

    # Send the packet
    send(packet)
    print("Packet sent:")
    packet.show2()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send a UDP packet with a random source port and specified source and destination IPs and port.')
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('dst_port', type=int, help='Destination port')
    args = parser.parse_args()
    send_udp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        dst_port=args.dst_port
    )
