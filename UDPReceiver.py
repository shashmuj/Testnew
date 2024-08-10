import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP

#This function is used for processing packets that are captured by the receiver.
def packet_callback(packet):

    
    # The packet header fields are displayed after receiving the packets.
    if IP in packet and UDP in packet:
        print("Packet received:")
        print("IP Header:")
        print(f"  Version: {packet[IP].version}")
        print(f"  IHL: {packet[IP].ihl}")
        print(f"  TOS: {packet[IP].tos}")
        print(f"  Length: {packet[IP].len}")
        print(f"  ID: {packet[IP].id}")
        print(f"  Flags: {packet[IP].flags}")
        print(f"  Fragment Offset: {packet[IP].frag}")
        print(f"  TTL: {packet[IP].ttl}")
        print(f"  Protocol: {packet[IP].proto}")
        print(f"  Checksum: {packet[IP].chksum}")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print("UDP Header:")
        print(f"  Source Port: {packet[UDP].sport}")
        print(f"  Destination Port: {packet[UDP].dport}")
        print(f"  Length: {packet[UDP].len}")
        print(f"  Checksum: {packet[UDP].chksum}")


# Here the command line arguments are parsed, and UDP packets are sniffed based on the source IP address.

if __name__ == "__main__":
   
    parser = argparse.ArgumentParser(description='Capture and display UDP packets from mentioned source IP.')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter packets')
    args = parser.parse_args()
    src_ip = args.src_ip


    print(f"Sniffing packets from {src_ip}...")
    sniff(filter=f"src host {src_ip} and udp", prn=packet_callback)
