import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP

def validate_checksum(packet):
    # Validates the checksum for both IP and UDP layers
    ip_checksum_valid = packet[IP].chksum == IP(bytes(packet[IP]))[IP].chksum
    udp_checksum_valid = packet[UDP].chksum == UDP(bytes(packet[UDP]))[UDP].chksum
    return ip_checksum_valid and udp_checksum_valid

def packet_callback(packet):
    if IP in packet and UDP in packet:
        if validate_checksum(packet):
            print("Packet received:")
            packet.show2()
            # Send response packet
            send_response_packet(packet)
        else:
            print("Invalid checksum.")

def send_response_packet(packet):
    # Extract details from received packet
    src_ip = packet[IP].dst
    dst_ip = packet[IP].src
    src_port = packet[UDP].dport
    dst_port = packet[UDP].sport
    proto = packet[IP].proto

    # Create response packet
    ip = IP(
        src=src_ip,
        dst=dst_ip,
        proto=proto
    )
    udp = UDP(
        sport=src_port,
        dport=dst_port
    )

    response_packet = ip / udp

    # Send the response packet
    send(response_packet)
    print("Response packet sent:")
    response_packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Capture and respond to UDP packets from a specific source IP.')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter packets')

    # Parse arguments
    args = parser.parse_args()
    src_ip = args.src_ip

    # Start sniffing
    print(f"Sniffing packets from {src_ip}...")
    sniff(filter=f"src host {src_ip} and udp", prn=packet_callback)
