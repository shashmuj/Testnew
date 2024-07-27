from scapy.all import *
from scapy import TCP,IP
import argparse

def packet_sniff_filter(packet, sender_ip):
    if IP in packet and packet[IP].src == sender_ip:  # Only packets from the sender IP
        return True
    return False

def respond_to_packet(packet):
    # Print received packet header
    print("Received packet:")
    packet.show()

    # Create a response packet
    ip = IP(dst=packet[IP].src, src=packet[IP].dst, proto=253)
    tcp = TCP(
        sport=packet[TCP].dport,
        dport=packet[TCP].sport,
        seq=packet[TCP].ack,
        ack=packet[TCP].seq + 1,
        flags="A",
        window=8192,
        chksum=0
    )

    response = ip/tcp

    # Calculate checksums
    response[IP].chksum = None
    response[TCP].chksum = None

    print("Sending response with the following header:")
    response.show()

    # Send response packet
    send(response, iface=conf.iface)
    print("Response sent.")

def main():
    parser = argparse.ArgumentParser(description="Sniff for packets from a specific sender IP and respond.")
    parser.add_argument("sender_ip", help="Sender IP address")
    parser.add_argument("iface", help="Network interface to use")
    args = parser.parse_args()

    print("Sniffing for packets...")
    sniff(filter=f"ip src {args.sender_ip}", iface=args.iface, prn=lambda p: respond_to_packet(p))

if __name__ == "__main__":
    main()
