import argparse
from scapy.all import *
from scapy.layers.inet import UDP, IP
import random


# This function will create UDP packet and sent to the receiver.
def send_udp_packet(src_ip, src_port, dst_ip, dst_port):
    

    # The UDP length is randomized here.
    udp_length = random.randint(8, 65535) 

   
   #The IP layer and UDP layer header fields are defined here.
    ip = IP(
        version=4,
        ihl=None,
        tos=0,
        len=None,
        id=54321,
        flags=0,
        frag=0,
        ttl=64,
        proto='udp',
        chksum=None,
        src=src_ip,
        dst=dst_ip
    )
    udp = UDP(
        sport=src_port,
        dport=dst_port,
        len=udp_length,
        chksum=None
    )

   
    #The IP and UDP layer are combined to form the packet.
    packet = ip / udp

   
    # The packets are sent to the receiver.
    send(packet)
    print("Packet sent:")
    packet.show2()


# The command line arguments are parsed here and function is called to send UDP packets with the usage of given arguments.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send a UDP packet with specified source and destination IPs and ports. UDP length is randomized.')
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('src_port', type=int, help='Source port')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('dst_port', type=int, help='Destination port')
    args = parser.parse_args()
    send_udp_packet(
        src_ip=args.src_ip,
        src_port=args.src_port,
        dst_ip=args.dst_ip,
        dst_port=args.dst_port
    )
