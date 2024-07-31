from scapy.all import *
import argparse
import random
import os

def generate_random_port():
    return random.randint(49152, 65535)

def generate_random_bytes(length):
    return os.urandom(length)

def handle_packet(packet):
    if Raw in packet:
        payload = packet[Raw].load
        print("Received Packet Payload:", payload)
    else:
        print("NO response")

def build_initial_packet(dst_ip, dst_port):
    src_port = generate_random_port()
    
    ip = IP(dst=dst_ip)
    udp = UDP(sport=src_port, dport=dst_port)
    
    header_form = 1 << 7
    fixed_bit = 1 << 6
    long_packet_type = 0 << 4
    reserved_bits = 0 << 2
    packet_number_length = 0
    first_byte = header_form | fixed_bit | long_packet_type | reserved_bits
    
    version = 1
    
    dst_conn_id_length = 8
    dst_conn_id = generate_random_bytes(dst_conn_id_length)
    src_conn_id_length = 5
    src_conn_id = generate_random_bytes(src_conn_id_length)
    
    packet_number = generate_random_bytes(packet_number_length + 1)
    
    quic_initial_header = (
        bytes([first_byte]) +
        version.to_bytes(4, 'big') +
        bytes([dst_conn_id_length]) +
        dst_conn_id + 
        bytes([src_conn_id_length]) +
        src_conn_id +
        len(b'').to_bytes(1, 'big') +
        bytes.fromhex('41 03') +
        packet_number + 
        generate_random_bytes(258)
    )
    
    padding_length = 1200 - len(quic_initial_header)
    if padding_length > 0:
        padding = bytes(padding_length)
        quic_initial_header += padding
        
    print("QUIC Initial Header Length:", len(quic_initial_header))
    
    initial_packet = ip / udp / Raw(load=quic_initial_header)
    # return initial_packet
    send(initial_packet)
    
    print(f"Listening for response on port {src_port}...")
    sniff(filter=f"udp and port {src_port}", prn=handle_packet, count=1, timeout=10)
    
    
parser = argparse.ArgumentParser(description="Process IP and port")
parser.add_argument('--ip', type=str, default='192.168.244.130')
parser.add_argument('--port', type=int, default=443)
args = parser.parse_args()

destination_ip = args.ip
destination_port = args.port
    
build_initial_packet(destination_ip, destination_port)