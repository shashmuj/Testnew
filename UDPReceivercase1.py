import argparse
from scapy.all import sniff

def packet_callback(packet, src_ip):
    if UDP in packet and packet[IP].src == src_ip:
        print("Captured UDP Packet from source IP {}:".format(src_ip))
        packet.show()

def start_sniffing(src_ip):
    print("Starting to sniff for UDP packets from source IP {}...".format(src_ip))
    sniff(prn=lambda pkt: packet_callback(pkt, src_ip), filter="udp", store=0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Capture UDP packets from a specific source IP address.')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter packets')
    args = parser.parse_args()
    start_sniffing(src_ip=args.src_ip)
