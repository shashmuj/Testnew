from scapy.all import *
import argparse

# Define the custom protocol with both IPv4 and TCP fields
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        # IPv4 fields
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("len", 0),
        ShortField("id", 1),
        ShortField("frag_off", 0),
        ByteField("ttl", 64),
        ByteField("proto", 253),
        XShortField("chksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        # TCP fields
        ShortField("sport", 12345),
        ShortField("dport", 80),
        IntField("seq", 0),
        IntField("ack", 0),
        ByteField("dataofs", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0, 8, ["F", "S", "R", "P", "A", "U", "E", "C"]),
        ShortField("window", 8192),
        XShortField("tcp_chksum", None),
        ShortField("urgptr", 0)
    ]

def create_packet(dst_ip, src_ip, iface, custom_protocol_args):
    packet = CustomProtocol(
        version=custom_protocol_args['version'],
        ihl=custom_protocol_args['ihl'],
        tos=custom_protocol_args['tos'],
        id=custom_protocol_args['id'],
        frag_off=custom_protocol_args['frag_off'],
        ttl=custom_protocol_args['ttl'],
        proto=custom_protocol_args['proto'],
        src=src_ip,
        dst=dst_ip,
        sport=custom_protocol_args['sport'],
        dport=custom_protocol_args['dport'],
        seq=custom_protocol_args['seq'],
        ack=custom_protocol_args['ack'],
        dataofs=custom_protocol_args['dataofs'],
        flags=custom_protocol_args['flags'],
        window=custom_protocol_args['window'],
        urgptr=custom_protocol_args['urgptr']
    )
    
    # Calculate checksums
    packet.chksum = None
    packet.tcp_chksum = None
    
    return packet

def main():
    parser = argparse.ArgumentParser(description="Send a custom protocol packet and receive response.")
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument("src_ip", help="Source IP address")
    parser.add_argument("iface", help="Network interface to use")
    # Command-line arguments for custom protocol fields
    parser.add_argument("--version", type=int, default=4, help="IP version")
    parser.add_argument("--ihl", type=int, default=5, help="IP header length")
    parser.add_argument("--tos", type=int, default=0, help="Type of service")
    parser.add_argument("--id", type=int, default=1, help="Identification")
    parser.add_argument("--frag_off", type=int, default=0, help="Fragment offset")
    parser.add_argument("--ttl", type=int, default=64, help="Time to live")
    parser.add_argument("--proto", type=int, default=253, help="Protocol number")
    parser.add_argument("--sport", type=int, default=12345, help="Source port")
    parser.add_argument("--dport", type=int, default=80, help="Destination port")
    parser.add_argument("--seq", type=int, default=0, help="Sequence number")
    parser.add_argument("--ack", type=int, default=0, help="Acknowledgment number")
    parser.add_argument("--dataofs", type=int, default=5, help="Data offset")
    parser.add_argument("--flags", type=int, default=0x02, help="Flags (e.g., 0x02 for SYN)")
    parser.add_argument("--window", type=int, default=8192, help="Window size")
    parser.add_argument("--urgptr", type=int, default=0, help="Urgent pointer")
    args = parser.parse_args()

    custom_protocol_args = vars(args)
    packet = create_packet(args.dst_ip, args.src_ip, args.iface, custom_protocol_args)
    
    # Print the packet to be sent
    print("Sending packet:")
    packet.show()

    # Send packet
    sendp(Ether()/packet, iface=args.iface)
    print("Packet sent. Waiting for response...")

    # Define the filter expression for receiving the response
    filter_expr = f"ip src {args.dst_ip} and ip dst {args.src_ip} and ip proto 253"
    
    # Sniff for response packet
    response = sniff(filter=filter_expr, iface=args.iface, timeout=10)  # Timeout to prevent indefinite blocking
    
    if not response:
        print("No custom protocol packets received.")
    else:
        for pkt in response:
            if CustomProtocol in pkt:
                print("Received custom protocol response:")
                pkt.show()
            else:
                print("Received packet with unexpected protocol:")
                pkt.show()

if __name__ == "__main__":
    main()
