import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP
import random

def send_tcp_packet(src_ip, dst_ip, src_port, dst_port, proto, num_packets):
    for i in range(num_packets):
        # Random integer to add to sequence number
        random_offset = random.randint(1, 5000)
        
        # Create IP and TCP layers
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
        tcp = TCP(
            sport=src_port,
            dport=dst_port,
            flags="S",
            seq=1000 + (i * 1000) + random_offset,  # More randomized sequence numbers
            ack=0,
            dataofs=5,
            reserved=0,
            window=8192,
            chksum=None,
            urgptr=0
        )

        # Combine IP and TCP layers to form the packet
        packet = ip / tcp

        # Send the packet
        send(packet)
        print(f"Packet {i + 1} sent:")
        packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send TCP packets with specified source and destination IPs and ports.')
    
    # Required arguments
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('src_port', type=int, help='Source port number')
    parser.add_argument('dst_port', type=int, help='Destination port number')
    parser.add_argument('proto', type=int, help='IP protocol number')
    parser.add_argument('--num_packets', type=int, default=3, help='Number of packets to send')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Call function with arguments
    send_tcp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        proto=args.proto,
        num_packets=args.num_packets
    )
