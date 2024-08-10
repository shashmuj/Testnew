import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP


# This function is defined to check the checksum for both IP and TCP layers.
def validate_checksum(packet):
    ip_checksum_valid = packet[IP].chksum == IP(bytes(packet[IP]))[IP].chksum
    tcp_checksum_valid = packet[TCP].chksum == TCP(bytes(packet[TCP]))[TCP].chksum
    return ip_checksum_valid and tcp_checksum_valid

# This function is used whenever a packet is captured.
def packet_callback(packet):
    if IP in packet and TCP in packet:
        if validate_checksum(packet):
            print("Packet received:")
            packet.show2()
           
            send_response_packet(packet)
        else:
            print("Invalid checksum.")

#This function is used for sending response packet back to the receiver.
def send_response_packet(packet):
    
    src_ip = packet[IP].dst
    dst_ip = packet[IP].src
    src_port = packet[TCP].dport
    dst_port = packet[TCP].sport
    proto = packet[IP].proto

   
   #IP and TCP layers of response packets are constructed.
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

    #The response packet is constructed having IP and TCP layers.
    response_packet = ip / tcp

    # The response packet is sent to the receiver.
    send(response_packet)
    print("Response packet sent:")
    response_packet.show2()

# Here the packets are sniffed from the sender and the command line arguments are parsed.
if __name__ == "__main__":
   
    parser = argparse.ArgumentParser(description='Capture and respond to TCP packets from a specific source IP.')
    parser.add_argument('src_ip', type=str, help='Source IP address to filter packets')
    args = parser.parse_args()
    src_ip = args.src_ip
    print(f"Sniffing packets from {src_ip}...")
    sniff(filter=f"src host {src_ip}", prn=packet_callback)
