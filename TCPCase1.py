import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP
import random


# Function for defining the TCP header fields and IP header fields.
def send_tcp_packet(src_ip, dst_ip, src_port, dst_port, proto, num_packets):

    # This loop sends number of packets.
    for i in range(num_packets):
        


        # Here we have defined a random offset for sequence numbers for displaying broken behaviour.
        random_offset = random.randint(1, 5000)
        

        # We have defined IP header fields here.
        ip = IP(
            version=4,
            ihl=5,
            tos=0,
            id=54321,
            frag=0,
            ttl=64,
            proto=proto,
            chksum=None,
            src=src_ip,
            dst=dst_ip
        )



        # Here the TCP header fields have been defined.
        tcp = TCP(
            sport=src_port,
            dport=dst_port,
            flags="S",
            seq=1000 + (i * 1000) + random_offset, 
            ack=0,
            dataofs=5,
            reserved=0,
            window=8192,
            chksum=None,
            urgptr=0
        )



        # We built the packet with IP and TCP layers.
        packet = ip / tcp

        send(packet)
        print(f"Packet {i + 1} sent:")
        packet.show2()


# Here the required and optional arguments have been defined, which should be passed through the command line.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Send TCP packets with specified source and destination IPs and ports.')
    
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('src_port', type=int, help='Source port number')
    parser.add_argument('dst_port', type=int, help='Destination port number')
    parser.add_argument('proto', type=int, help='IP protocol number')
    parser.add_argument('--num_packets', type=int, default=3, help='Number of packets to send')
    
    args = parser.parse_args()
    



#The function is called to send packets to the receiver destinaton IP address.
    send_tcp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        proto=args.proto,
        num_packets=args.num_packets
    )
