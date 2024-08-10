import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP



#  We have defined this function to validate checksum of IP and TCP headers.
def validate_checksum(packet):
    ip_checksum_valid = packet[IP].chksum == IP(bytes(packet[IP]))[IP].chksum
    tcp_checksum_valid = packet[TCP].chksum == TCP(bytes(packet[TCP]))[TCP].chksum
    return ip_checksum_valid and tcp_checksum_valid

# This function is defined to capture packets and process them.
def packet_callback(packet):
    if IP in packet and TCP in packet:
        if validate_checksum(packet):
            print("Packet received:")
            packet.show2()
            send_response_packet(packet)
        else:
            print("Invalid checksum.")



# This function is used to create a response packet and send the packet.

def send_response_packet(packet):
    src_ip = packet[IP].dst
    dst_ip = packet[IP].src
    src_port = packet[TCP].dport
    dst_port = packet[TCP].sport
    proto = packet[IP].proto

    
    ip = IP(
        src=src_ip,
        dst=dst_ip,
        proto=proto
    )
    tcp = TCP(
        sport=src_port,
        dport=dst_port,
        flags="SA", 
        seq=2000,
        ack=packet[TCP].seq + 1,
        window=8192
    )

    response_packet = ip / tcp

 
    # The response packets are sent to the sender machine.

    send(response_packet)
    print("Response packet sent:")
    response_packet.show2()


# Command line arguments are parsed here and the packets are sniffed using source IP address.

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Capture the TCP packets from a specific source IP.')
    parser.add_argument('src_ip', type=str, help='Source IP address for filtering packets')
    args = parser.parse_args()
    src_ip = args.src_ip


    print(f"Sniffing packets from {src_ip}...")
    sniff(filter=f"src host {src_ip}", prn=packet_callback)
