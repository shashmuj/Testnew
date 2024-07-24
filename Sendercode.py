from scapy.all import sniff, IP, send, Packet, BitField, ShortField, ByteField, IPField, XShortField, IntField, checksum
import struct
import argparse
import sys

class MyCustomHeader(Packet):
    name = "MyCustomHeader"
    fields_desc = [
        BitField("version", 4, 4),
        BitField("header_length", 5, 4),
        ShortField("total_length", 40),
        ShortField("identification", 0),
        BitField("flags", 0, 3),
        BitField("fragment_offset", 0, 13),
        ByteField("ttl", 0),
        ByteField("protocol", 0),
        XShortField("checksum", 0),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        IntField("seq_num", 0)
    ]

    def post_build(self, p, pay):
        if self.checksum == 0:
            chksum = checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

def send_custom_ipv4_packet(custom_header_params):
    custom_header = MyCustomHeader(**custom_header_params)
    ip_packet = IP(dst=custom_header_params['dst'], proto=custom_header_params['protocol']) / custom_header
    print("=== Sending Custom Packet ===")
    custom_header.show()
    print(repr(ip_packet))
    send(ip_packet, count=1)

def handle_response(packet, receiver_ip):
    ip_header = packet.getlayer(IP)
    if ip_header and ip_header.src == receiver_ip:
        print("=== Received Response Packet ===")
        packet.show()
        # Optionally print packet summary for quick debug
        print(f"Response Packet Summary: {packet.summary()}")
    else:
        print(f"Ignored packet from {ip_header.src} as it is not from the receiver {receiver_ip}")

def main():
    parser = argparse.ArgumentParser(description="Send and receive custom IPv4 packets")
    parser.add_argument("--src_ip", required=True, help="Source IP address")
    parser.add_argument("--dst_ip", required=True, help="Destination IP address")
    parser.add_argument("--seq_num", type=int, default=1, help="Sequence number")
    parser.add_argument("--protocol", type=int, default=253, help="Protocol number")
    parser.add_argument("--ttl", type=int, default=64, help="Time To Live (TTL)")
    parser.add_argument("--identification", type=int, default=1234, help="Identification number")
    parser.add_argument("--flags", type=int, default=0, help="Flags")
    parser.add_argument("--fragment_offset", type=int, default=0, help="Fragment offset")
    parser.add_argument("--iface", required=True, help="Network interface to sniff on")
    parser.add_argument("--receiver_ip", required=True, help="Receiver IP address")

    args = parser.parse_args()

    custom_header_params = {
        "protocol": args.protocol,
        "src": args.src_ip,
        "dst": args.dst_ip,
        "seq_num": args.seq_num,
        "ttl": args.ttl,
        "identification": args.identification,
        "flags": args.flags,
        "fragment_offset": args.fragment_offset
    }

    send_custom_ipv4_packet(custom_header_params)

    print("Listening for responses from the receiver...")
    # Capture packets with a filter for the response
    filter_str = f"ip src {args.receiver_ip} and ip dst {args.src_ip}"
    sniff(iface=args.iface, filter=filter_str, prn=lambda p: handle_response(p, args.receiver_ip))

if __name__ == "__main__":
    main()
