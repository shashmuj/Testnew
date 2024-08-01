from scapy.all import *
from scapy.layers.inet import IP, TCP

class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        # IP header fields
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("id", 54321),
        ShortField("frag", 0),
        ByteField("ttl", 64),
        ByteField("proto", 6),  # TCP protocol number
        XShortField("chksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        
        # TCP header fields
        ShortField("sport", 12345),
        ShortField("dport", 80),
        IntField("seq", 1000),
        IntField("ack", 0),
        ByteField("dataofs", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0x02, 8, "FSRPAUEC"),  # SYN flag set
        ShortField("window", 8192),
        XShortField("tcp_chksum", None),
        ShortField("urgptr", 0)
    ]

    def post_build(self, p, pay):
        p += pay
        if self.chksum is None:
            chksum = checksum(p)
            p = p[:10] + struct.pack("H", chksum) + p[12:]
        return p

bind_layers(Ether, CustomProtocol, type=0x0800)


import argparse
from scapy.all import *

def packet_callback(packet):
    if CustomProtocol in packet:
        # Extract source IP and port
        src_ip = packet[CustomProtocol].src
        src_port = packet[CustomProtocol].sport

        # Display the received packet
        print("Received custom protocol packet:")
        packet.show2()

        # Create a response packet
        response = CustomProtocol(
            version=4,
            ihl=5,
            tos=0,
            id=54321,
            frag=0,
            ttl=64,
            proto=packet[CustomProtocol].proto,
            chksum=None,
            src=packet[CustomProtocol].dst,
            dst=packet[CustomProtocol].src,
            sport=packet[CustomProtocol].dport,
            dport=packet[CustomProtocol].sport,
            flags="A",  # ACK flag set
            seq=packet[CustomProtocol].ack,
            ack=packet[CustomProtocol].seq + 1,
            dataofs=5,
            reserved=0,
            window=8192,
            tcp_chksum=None,
            urgptr=0
        )

        # Send the response packet
        print(f"Sending response to {src_ip}:{src_port}")
        send(response)
        print("Response packet sent:")
        response.show2()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Receive custom protocol packets and send a response.')
    parser.add_argument('iface', type=str, help='Network interface to listen on')
    args = parser.parse_args()

    print("Sniffing for custom protocol packets...")
    sniff(iface=args.iface, filter="ip", prn=packet_callback, timeout=10)

