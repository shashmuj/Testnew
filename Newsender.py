from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
import argparse

class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        # IP header fields
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("id", 54321),
        ShortField("frag", 0),
        ByteField("ttl", 64),
        ByteField("proto", 6),  # TCP protocol number
        XShortField("chksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        
        # TCP header fields
        ShortField("sport", 12345),
        ShortField("dport", 80),
        IntField("seq", 1000),
        IntField("ack", 0),
        ByteField("dataofs", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0x02, 8, "FSRPAUEC"),  # SYN flag set
        ShortField("window", 8192),
        XShortField("tcp_chksum", None),
        ShortField("urgptr", 0)
    ]

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            chksum = checksum(p)
            p = p[:10] + struct.pack("H", chksum) + p[12:]
        return p

bind_layers(Ether, CustomProtocol, type=0x0800)

def send_custom_packet(src_ip, dst_ip, src_port, dst_port, proto):
    # Create the custom protocol packet
    packet = CustomProtocol(
        version=4,
        ihl=5,
        tos=0,
        id=54321,
        frag=0,
        ttl=64,
        proto=proto,
        chksum=None,
        src=src_ip,
        dst=dst_ip,
        sport=src_port,
        dport=dst_port,
        flags="S",  # SYN flag set
        seq=1000,
        ack=0,
        dataofs=5,
        reserved=0,
        window=8192,
        tcp_chksum=None,
        urgptr=0
    )

    # Send the packet
    send(packet)
    print("Packet sent:")
    packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Send a custom protocol packet with specified source and destination IPs and ports.')
    
    # Required arguments
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('src_port', type=int, help='Source port number')
    parser.add_argument('dst_port', type=int, help='Destination port number')
    parser.add_argument('proto', type=int, help='IP protocol number')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Call function with arguments
    send_custom_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        proto=args.proto
    )
