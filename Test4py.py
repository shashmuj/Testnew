import argparse
from scapy.all import *
from scapy.layers.inet import TCP,IP

def calculate_checksum(packet):
    if len(packet) % 2 == 1:
        packet += b'\0'
    s = sum(struct.unpack("!%dH" % (len(packet) // 2), packet))
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def create_ip_header(src_ip, dst_ip, proto):
    ip = IP(src=src_ip, dst=dst_ip, proto=proto)
    return ip

def create_tcp_header(src_port, dst_port, seq, ack_seq, flags, window, payload):
    tcp = TCP(sport=src_port, dport=dst_port, seq=seq, ack=ack_seq, flags=flags, window=window)
    return tcp

def send_packet(interface, sender_ip, receiver_ip, src_port, dst_port, seq, ack_seq, flags, window, payload, proto):
    ip_header = create_ip_header(sender_ip, receiver_ip, proto)
    tcp_header = create_tcp_header(src_port, dst_port, seq, ack_seq, flags, window, payload)

    packet = ip_header / tcp_header / Raw(load=payload)

    send(packet, iface=interface)
    print(f'Packet sent to {receiver_ip}')

def main():
    parser = argparse.ArgumentParser(description='Custom Transport Protocol Sender using Scapy')
    parser.add_argument('interface', type=str, help='Network interface to use')
    parser.add_argument('sender_ip', type=str, help='Sender IP address')
    parser.add_argument('receiver_ip', type=str, help='Receiver IP address')
    parser.add_argument('--src_port', type=int, default=12345, help='Source port')
    parser.add_argument('--dst_port', type=int, default=80, help='Destination port')
    parser.add_argument('--seq', type=int, default=0, help='Sequence number')
    parser.add_argument('--ack_seq', type=int, default=0, help='Acknowledgment number')
    parser.add_argument('--flags', type=str, default='S', help='TCP flags')  # SYN flag
    parser.add_argument('--window', type=int, default=5840, help='TCP window size')
    parser.add_argument('--payload', type=str, default='', help='Payload data')
    parser.add_argument('--proto', type=int, default=253, help='Protocol number')

    args = parser.parse_args()

    send_packet(args.interface, args.sender_ip, args.receiver_ip, args.src_port, args.dst_port, args.seq, args.ack_seq, args.flags, args.window, args.payload, args.proto)

if __name__ == '__main__':
    main()
