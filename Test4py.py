from scapy.all import *

def send_udp_packet(src_ip, dst_ip, src_port, dst_port, message):
    # Create the IP header
    ip = IP(src=src_ip, dst=dst_ip)

    # Create the UDP header
    udp = UDP(sport=src_port, dport=dst_port)

    # Create the payload with the message
    payload = Raw(load=message)

    # Combine the IP, UDP headers, and payload to form the full packet
    packet = ip / udp / payload

    # Send the packet
    send(packet)
    print(
        f'UDP packet sent from {src_ip}:{src_port} to {dst_ip}:{dst_port} with message: {message}')

def main():
    src_ip = "192.41.114.225"
    dst_ip = "128.110.217.36"  # Replace with the server IP address
    src_port = 12345         # Replace with your source port
    dst_port = 54321         # Replace with the destination port
    message = "Hello, Server!"  # Custom message to send

    send_udp_packet(src_ip,dst_ip, src_port, dst_port, message)

if __name__ == '__main__':
    main()
