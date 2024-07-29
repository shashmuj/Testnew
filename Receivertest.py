import argparse
import array
from scapy.all import *

def checksum(packet):
    if len(packet) % 2 == 1:
        packet += b'\x00'
    s = sum(array.array("H", packet))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def send_custom_packet(interface, src_ip, dst_ip, protocol, src_port, dst_port, seq, ack_seq, flags, window, urgent):
    # Create the IP header
    ip = IP(src=src_ip, dst=dst_ip, proto=protocol)
    
    # Create the TCP-like header
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack_seq, flags=flags, window=window, urgptr=urgent)
    
    # Manually calculate the checksum for the pseudo-header
    pseudo_header = bytes(ip) + bytes(tcp)
    tcp.chksum = checksum(pseudo_header)

    # Create the full packet
    packet = ip / tcp
    
    # Manually calculate the checksum for the IP header
    ip.chksum = checksum(bytes(ip))
    
    # Send the packet
    send(packet, iface=interface)
    print(f'Packet sent from {src_ip}:{src_port} to {dst_ip}:{dst_port} with protocol {protocol}')

    # Sniff and print the response packets
    print("Waiting for response packets...")
    sniff(filter=f"src {dst_ip}", prn=lambda x: x.show(), iface=interface, timeout=10)

def main():
    parser = argparse.ArgumentParser(description='Send a custom protocol packet using Scapy')
    parser.add_argument('interface', type=str, help='Network interface to use')
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('--protocol', type=int, default=253, help='Protocol number (default: 253)')
    parser.add_argument('--src_port', type=int, default=50000, help='Source port (default: 50000)')
    parser.add_argument('--dst_port', type=int, default=54321, help='Destination port (default: 54321)')
    parser.add_argument('--seq', type=int, default=0, help='Sequence number (default: 0)')
    parser.add_argument('--ack_seq', type=int, default=0, help='Acknowledgment number (default: 0)')
    parser.add_argument('--flags', type=str, default='S', help='TCP flags (default: SYN)')
    parser.add_argument('--window', type=int, default=8192, help='Window size (default: 8192)')
    parser.add_argument('--urgent', type=int, default=0, help='Urgent pointer (default: 0)')

    args = parser.parse_args()

    send_custom_packet(args.interface, args.src_ip, args.dst_ip, args.protocol, args.src_port, args.dst_port, args.seq, args.ack_seq, args.flags, args.window, args.urgent)

if __name__ == '__main__':
    main()
