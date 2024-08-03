import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP

def validate_checksum(packet):
    # Validates the checksum for both IP and TCP layers
    ip_checksum_valid = packet[IP].chksum == IP(bytes(packet[IP]))[IP].chksum
    tcp_checksum_valid = packet[TCP].chksum == TCP(bytes(packet[TCP]))[TCP].chksum
    return ip_checksum_valid and tcp_checksum_valid

def packet_callback(packet):
    if IP in packet and TCP in packet:
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
    src_port = packet[TCP].dport
    dst_port = packet[TCP].sport
    proto = packet[IP].proto

    # Create response packet
    ip = IP(
        src=src_ip,
        dst=dst_ip,
        proto=proto
    )
    tcp = TCP(
        sport=src_port,
        dport=dst_port,
        flags="SA",  # SYN-ACK flags
        seq=2000,
        ack=packet[TCP].seq + 1,
        window=8192
    )

    response_packet = ip / tcp

    # Send the response packet
    send(response_packet)
    print("Response packet sent:")
    response_packet.show2()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description='Capture and respond to TCP packets from a specific source IP.')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter packets')

    # Parse arguments
    args = parser.parse_args()
    src_ip = args.src_ip

    # Start sniffing
    print(f"Sniffing packets from {src_ip}...")
    sniff(filter=f"src host {src_ip}", prn=packet_callback)
