import argparse
from scapy.all import *

def packet_callback(packet):
    if packet[IP].src == args.src_ip:
        print("Received packet:")
        packet.show()

        # Create a response packet
        ip = IP(src=packet[IP].dst, dst=packet[IP].src, proto=packet[IP].proto)
        tcp = TCP(sport=packet[TCP].dport, dport=packet[TCP].sport, seq=packet[TCP].ack, ack=packet[TCP].seq + 1, flags='A')
        
        # Manually calculate the checksum for the pseudo-header
        pseudo_header = bytes(ip) + bytes(tcp)
        tcp.chksum = checksum(pseudo_header)
        
        response_packet = ip / tcp
        send(response_packet, iface=args.interface)
        print("Sent response packet:")
        response_packet.show()

def main():
    parser = argparse.ArgumentParser(description='Receive custom protocol packets and send a response using Scapy')
    parser.add_argument('interface', type=str, help='Network interface to use')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter')

    global args
    args = parser.parse_args()

    print("Starting packet capture...")
    sniff(iface=args.interface, prn=packet_callback, store=0)

if __name__ == '__main__':
    main()
