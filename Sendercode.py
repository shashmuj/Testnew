from scapy.all import *
import argparse

def create_packet(dst_ip, src_ip, protocol, flags, data_offset, randomize):
    ip = IP(dst=dst_ip, src=src_ip, proto=protocol)
    
    if randomize:
        # Randomize TCP fields
        tcp = TCP(
            sport=RandShort(),
            dport=RandShort(),
            seq=RandInt(),
            ack=RandInt(),
            flags=flags,
            dataofs=data_offset,
            window=RandShort(),
            chksum=0
        )
    else:
        # Default TCP fields
        tcp = TCP(
            sport=12345,
            dport=80,
            seq=1000,
            ack=0,
            flags=flags,
            dataofs=data_offset,
            window=8192,
            chksum=0
        )
    
    packet = ip/tcp
    
    # Calculate checksums
    packet[IP].chksum = None
    packet[TCP].chksum = None
    
    return packet

def packet_sniff_filter(packet):
    if IP in packet and packet[IP].proto == 6:  # Only TCP packets
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Create and send a custom TCP packet.")
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument("src_ip", help="Source IP address")
    parser.add_argument("iface", help="Network interface to use")
    parser.add_argument("--protocol", type=int, default=6, help="Protocol number")
    parser.add_argument("--flags", default="S", help="TCP flags (e.g., 'S' for SYN)")
    parser.add_argument("--data_offset", type=int, default=5, help="TCP Data Offset")
    parser.add_argument("--randomize", action="store_true", help="Randomize TCP header fields")
    args = parser.parse_args()

    packet = create_packet(args.dst_ip, args.src_ip, args.protocol, args.flags, args.data_offset, args.randomize)
    
    # Send packet
    send(packet, iface=args.iface)

    print("Packet sent. Waiting for response...")

    # Sniff for response packet
    response = sniff(filter="tcp", iface=args.iface, count=1, prn=lambda x: x.summary())
    if response:
        print("Received response:")
        response[0].show()

if __name__ == "__main__":
    main()
