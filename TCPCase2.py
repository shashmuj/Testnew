import argparse
from scapy.all import *
from scapy.layers.inet import TCP, IP



# This is the function to send TCP packets with IP and TCP headers.
def send_tcp_packet(src_ip, dst_ip, src_port, dst_port, proto, num_packets):
    for i in range(num_packets):
        
        # Now we create IP and TCP layers.
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
        tcp = TCP(
            sport=src_port,
            dport=dst_port,
            flags="S",
            seq=1000,
            ack=0,
            dataofs=0,  # Data offset is set to zero to configure a broken behaviour.
            reserved=0,
            window=8192,
            chksum=None,
            urgptr=0
        )

        # Here we join IP and TCP layers to form the packet
        packet = ip / tcp

        # The packets are sent.
        send(packet)
        print(f"Packet {i + 1} sent with data offset {tcp.dataofs}:")
        packet.show2()

#Here we have defined the command line arguments which are compulsory and optional.
if __name__ == "__main__":
   
    parser = argparse.ArgumentParser(description='Send TCP packets with invalid data offset values.')
    
   
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dst_ip', type=str, help='Destination IP address')
    parser.add_argument('src_port', type=int, help='Source port number')
    parser.add_argument('dst_port', type=int, help='Destination port number')
    parser.add_argument('proto', type=int, help='IP protocol number')
    parser.add_argument('--num_packets', type=int, default=1, help='Number of packets to send')
    
   
    args = parser.parse_args()
    
    # Here we call the function to provide command line arguments.
    send_tcp_packet(
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        src_port=args.src_port,
        dst_port=args.dst_port,
        proto=args.proto,
        num_packets=args.num_packets
    )
