from scapy.all import sniff, IP, send, Raw, Packet
from scapy.fields import BitField, ShortField, ByteField, IPField, XShortField, checksum
import struct
import argparse
import sys

class MyCustomHeader(Packet):
    name = "MyCustomHeader"
    fields_desc = [
        BitField("version", 4, 4),
        BitField("header_length", 5, 4),
        ShortField("total_length", 40),
        ShortField("identification", 0),
        BitField("flags", 0, 3),
        BitField("fragment_offset", 0, 13),
        ByteField("ttl", 0),
        ByteField("protocol", 0),
        XShortField("checksum", 0),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0")
    ]

    def post_build(self, p, pay):
        if self.checksum == 0:
            chksum = checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

def handle_packet(packet, sender_ip):
    ip_header = packet.getlayer(IP)
    if ip_header and ip_header.src == sender_ip:
        print("=== Received Packet ===")
        packet.show()

        if MyCustomHeader in packet:
            custom_header = packet[MyCustomHeader]
            print("=== Custom Header ===")
            print(f"Version: {custom_header.version}")
            print(f"Header Length: {custom_header.header_length}")
            print(f"Total Length: {custom_header.total_length}")
            print(f"Identification: {custom_header.identification}")
            print(f"Flags: {custom_header.flags}")
            print(f"Fragment Offset: {custom_header.fragment_offset}")
            print(f"TTL: {custom_header.ttl}")
            print(f"Protocol: {custom_header.protocol}")
            print(f"Checksum: {hex(custom_header.checksum)}")
            print(f"Source IP: {custom_header.src}")
            print(f"Destination IP: {custom_header.dst}")
        else:
            print("Received a packet with no custom header.")

        # Prepare and send a response packet
        response = IP(src=ip_header.dst, dst=ip_header.src) / Raw(load="Packet received")
        print("=== Sending Response Packet ===")
        response.show()
        send(response)
        print(f"Response sent from {response.src} to {response.dst}")

