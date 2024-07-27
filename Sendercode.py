from scapy.all import *
import argparse
from scapy.layers import IP,TCP

def create_packet(dst_ip, src_ip, iface, protocol, sport, dport, seq, ack, flags, window, data_offset, ttl, tos, id, frag, ihl, version, length, checksum, options):
    # Create the IP header
    ip = IP(dst=dst_ip, src=src_ip, proto=protocol, ttl=ttl, tos=tos, id=id, flags=frag, ihl=ihl, version=version, len=length, chksum=checksum, options=options)
    
    # Create the TCP header
    tcp = TCP(
        sport=sport,
        dport=dport,
        seq=seq,
        ack=ack,
        flags=flags,
        dataofs=data_offset,
        window=window,
        chksum=checksum
    )
    
    packet = ip/tcp
    
    # Calculate checksums
    packet[IP].chksum = None
    packet[TCP].chksum = None
    
    return packet

def main():
    parser = argparse.ArgumentParser(description="Create and send a custom TCP packet.")
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument("src_ip", help="Source IP address")
    parser.add_argument("iface", help="Network interface to use")
    
    # TCP and IP fields
    parser.add_argument("--protocol", type=int, default=253, help="Protocol number (default: 253)")
    parser.add_argument("--sport", type=int, default=12345, help="Source port (default: 12345)")
    parser.add_argument("--dport", type=int, default=80, help="Destination port (default: 80)")
    parser.add_argument("--seq", type=int, default=1000, help="Sequence number (default: 1000)")
    parser.add_argument("--ack", type=int, default=0, help="Acknowledgment number (default: 0)")
    parser.add_argument("--flags", default="S", help="TCP flags (e.g., 'S' for SYN) (default: 'S')")
    parser.add_argument("--window", type=int, default=8192, help="Window size (default: 8192)")
    parser.add_argument("--data_offset", type=int, default=5, help="TCP Data Offset (default: 5)")
    parser.add_argument("--ttl", type=int, default=64, help="IP TTL (Time to Live) (default: 64)")
    parser.add_argument("--tos", type=int, default=0, help="IP TOS (Type of Service) (default: 0)")
    parser.add_argument("--id", type=int, default=1, help="IP ID (default: 1)")
    parser.add_argument("--frag", default="DF", help="IP Flags (e.g., 'DF' for Don't Fragment) (default: 'DF')")
    parser.add_argument("--ihl", type=int, default=5, help="IP IHL (Internet Header Length) (default: 5)")
    parser.add_argument("--version", type=int, default=4, help="IP Version (default: 4)")
    parser.add_argument("--length", type=int, default=0, help="IP Total Length (0 for automatic calculation, default: 0)")
    parser.add_argument("--checksum", type=int, default=0, help="IP Header Checksum (0 for automatic calculation, default: 0)")
    parser.add_argument("--options", default=[], help="IP Options (default: [])")

    args = parser.parse_args()

    packet = create_packet(args.dst_ip, args.src_ip, args.iface, args.protocol, args.sport, args.dport, args.seq, args.ack, args.flags, args.window, args.data_offset, args.ttl, args.tos, args.id, args.frag, args.ihl, args.version, args.length, args.checksum, args.options)
    
    print("Sending packet with the following header:")
    packet.show()

    # Send packet
    send(packet, iface=args.iface)

    print("Packet sent. Waiting for response...")

    # Sniff for response packet
    response = sniff(filter=f"ip src {args.dst_ip} and ip dst {args.src_ip}", iface=args.iface, count=1)
    if response:
        print("Received response:")
        response[0].show()

if __name__ == "__main__":
    main()
