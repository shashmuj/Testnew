import argparse
from scapy.all import *
from scapy.layers.inet import  TCP,IP

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

def packet_callback(packet):
    if IP in packet and packet[IP].src == args.sender_ip:
        print(f'Received packet from {packet[IP].src}')
        packet.show()

        # Prepare response packet
        payload = 'ACK'
        ip_header = create_ip_header(args.receiver_ip, packet[IP].src, args.proto)
        tcp_header = create_tcp_header(packet[TCP].dport, packet[TCP].sport, 1, packet[TCP].seq + 1, 'A', 5840, payload)

        response_packet = ip_header / tcp_header / Raw(load=payload)

        send(response_packet, iface=args.interface)
        print(f'Sent response to {packet[IP].src}')

def main():
    parser = argparse.ArgumentParser(description='Custom Transport Protocol Receiver using Scapy')
    parser.add_argument('interface', type=str, help='Network interface to use')
    parser.add_argument('sender_ip', type=str, help='Sender IP address')
    parser.add_argument('receiver_ip', type=str, help='Receiver IP address')
    parser.add_argument('--proto', type=int, default=253, help='Protocol number')

    global args
    args = parser.parse_args()

    # Sniff packets on the specified interface
    sniff(iface=args.interface, prn=packet_callback, filter=f'ip and src host {args.sender_ip}', store=0)

if __name__ == '__main__':
    main()
