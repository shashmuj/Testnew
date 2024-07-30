import argparse
import random
from scapy.all import *
from scapy.layers.inet import UDP, IP

def random_bytes(length):
    return bytes([random.randint(0, 255) for _ in range(length)])

def send_quic_packet(src_ip, dst_ip):
    # Create IP and UDP layers
    ip = IP(src=src_ip, dst=dst_ip)
    udp = UDP(sport=random.randint(1024, 65535), dport=443)

    # Create a QUIC-like initial packet header
    flags = random_bytes(1)  # 1 byte for flags
    connection_id = random_bytes(8)  # 8 bytes for connection ID
    packet_number = random_bytes(4)  # 4 bytes for packet number
    quic_header = flags + connection_id + packet_number

    # Create a QUIC payload with random values
    ack_frame = random_bytes(8)  # Example length
    flow_control_frame = random_bytes(8)  # Example length
    stream_frame_header = random_bytes(8)  # Example length
    stream_frame_payload = random_bytes(20)  # Example length
    http_data = random_bytes(20)  # Example length
    quic_mac = random_bytes(16)  # Example length

    # Combine all parts to form the QUIC payload
    quic_payload = ack_frame + flow_control_frame + stream_frame_header + stream_frame_payload + http_data + quic_mac

    # Combine the layers to form the packet
    packet = ip / udp / quic_header / quic_payload

    # Send the packet
    send(packet)
    print("QUIC-like packet sent:")
    packet.show2()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send a QUIC-like packet with specified source and destination IPs.')
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    args = parser.parse_args()

    send_quic_packet(args.src_ip, args.dst_ip)
