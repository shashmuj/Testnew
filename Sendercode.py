from scapy.all import Packet, ByteField, ShortField, IntField, XShortField, IPField, FlagsField, send, sniff
import argparse
import socket
import struct
from scapy.layers.inet import IP

class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
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

def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def calculate_checksums(packet):
    ip_header = bytes(packet)[:packet.ihl * 4]
    ip_checksum = calculate_checksum(ip_header)
    packet.chksum = ip_checksum
    
    tcp_header = bytes(packet)[packet.ihl * 4:]
    pseudo_header = b''.join([
        socket.inet_aton(packet.src),
        socket.inet_aton(packet.dst),
        b'\x00\x06',
        struct.pack('!H', len(tcp_header))
    ])
    tcp_checksum = calculate_checksum(pseudo_header + tcp_header)
    packet.tcp_chksum = tcp_checksum

def create_packet(dst_ip, src_ip, iface, custom_protocol_args):
    try:
        packet = CustomProtocol(
            version=custom_protocol_args['version'],
            ihl=custom_protocol_args['ihl'],
            tos=custom_protocol_args['tos'],
            len=custom_protocol_args['ihl']*4 + 20,
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
        calculate_checksums(packet)
        return packet
    except Exception as e:
        print(f"Error creating packet: {e}")
        return None

def send_custom_packet(packet, iface):
    if packet:
        send(IP(src=packet.src, dst=packet.dst, proto=packet.proto)/packet, iface=iface)
    else:
        print("No packet to send.")

def main():
    parser = argparse.ArgumentParser(description="Send a custom protocol packet and receive response.")
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument("src_ip", help="Source IP address")
    parser.add_argument("iface", help="Network interface to use")
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
    
    if packet:
        print("Sending packet:")
        packet.show()
        send_custom_packet(packet, args.iface)
        print("Packet sent. Waiting for response...")
        
        filter_expr = f"ip src {args.dst_ip} and ip dst {args.src_ip} and ip proto {custom_protocol_args['proto']}"
        response = sniff(filter=filter_expr, iface=args.iface, timeout=10)
        
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
