import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP

def packet_callback(packet):
    if IP in packet and TCP in packet:
        print("Packet received:")
        packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Capture TCP packets from a specific source IP and print their headers.')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter packets')

    # Parse arguments
    args = parser.parse_args()
    src_ip = args.src_ip

    # Start sniffing
    print(f"Sniffing packets from {src_ip}...")
    sniff(filter=f"src host {src_ip}", prn=packet_callback)
