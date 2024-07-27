import argparse
from scapy.all import *

def main():
    parser = argparse.ArgumentParser(description='Send a TCP packet using Scapy.')
    
    # Compulsory arguments
    parser.add_argument('src_ip', help='Source IP address')
    parser.add_argument('dst_ip', help='Destination IP address')
    
    # Optional arguments for TCP packet fields
    parser.add_argument('--src_port', type=int, default=12345, help='Source port (default: 12345)')
    parser.add_argument('--dst_port', type=int, default=80, help='Destination port (default: 80)')
    parser.add_argument('--seq', type=int, default=1000, help='Sequence number (default: 1000)')
    parser.add_argument('--ack', type=int, default=0, help='Acknowledgment number (default: 0)')
    parser.add_argument('--flags', default='S', help='TCP flags (e.g., S for SYN, A for ACK)')
    parser.add_argument('--data', default='', help='Payload data')

    args = parser.parse_args()

    # Convert flags to bitfield
    flag_bits = ''.join(['1' if flag in args.flags else '0' for flag in "SRAUEC"])
    flags_int = int('0b' + flag_bits, 2)

    # Create the IP and TCP layers
    ip = IP(src=args.src_ip, dst=args.dst_ip)
    tcp = TCP(sport=args.src_port, dport=args.dst_port, seq=args.seq, ack=args.ack, flags=args.flags, window=8192)

    # Create the packet
    packet = ip / tcp / Raw(load=args.data.encode())

    # Send the packet
    send(packet)

    # Print packet details
    print("Sent Packet Details:")
    print(f"Source IP: {args.src_ip}")
    print(f"Destination IP: {args.dst_ip}")
    print(f"Source Port: {args.src_port}")
    print(f"Destination Port: {args.dst_port}")
    print(f"Sequence Number: {args.seq}")
    print(f"Acknowledgment Number: {args.ack}")
    print(f"Flags: {args.flags}")
    print(f"Payload: {args.data}")

if __name__ == "__main__":
    main()
