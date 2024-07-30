import argparse
from scapy.all import *
from scapy.layers.inet import IP,UDP
def packet_callback(packet):
    if IP in packet and UDP in packet:
        # Extract source IP and port
        src_ip = packet[IP].src
        src_port = packet[UDP].sport
        
        # Display the received packet
        print("Received QUIC-like packet:")
        packet.show2()

        # Create a response packet
        response = IP(dst=src_ip) / UDP(dport=src_port) / Raw(load="Response from receiver")

        # Send the response packet
        print(f"Sending response to {src_ip}:{src_port}")
        send(response)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Receive QUIC-like packets and send a response.')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter')
    args = parser.parse_args()

    # Ensure the correct network interface is used
    iface = conf.iface  # Default interface, modify if needed

    print("Sniffing for QUIC-like packets...")
    sniff(iface=iface, filter=f"udp and src host {args.src_ip}", prn=packet_callback, timeout=10)
