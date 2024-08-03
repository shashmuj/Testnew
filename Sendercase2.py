import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP

def send_tcp_packet(src_ip, dst_ip, src_port, dst_port, proto, num_packets):
    for i in range(num_packets):
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
            seq=1000,
            ack=0,
            dataofs=0,  # Set data offset to 0 (invalid value)
            reserved=0,
            window=8192,
            chksum=None,
            urgptr=0
        )

        # Combine IP and TCP layers to form the packet
        packet = ip / tcp

        # Send the packet
        send(packet)
        print(f"Packet {i + 1} sent with data offset {tcp.dataofs}:")
        packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send TCP packets with invalid data offset values.')
    
    # Required arguments
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('src_port', type=int, help='Source port number')
    parser.add_argument('dst_port', type=int, help='Destination port number')
    parser.add_argument('proto', type=int, help='IP protocol number')
    parser.add_argument('--num_packets', type=int, default=1, help='Number of packets to send')
    
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
