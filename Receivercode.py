from scapy.all import sniff, IP, Raw, send
from scapy.packet import Packet
from scapy.fields import BitField, ShortField, ByteField, IPField, XShortField
import struct

# Define the custom header class for the receiver
class MyCustomHeader(Packet):
    name = "MyCustomHeader"
    fields_desc = [
        BitField("version", 4, 4),                  # IPv4 version
        BitField("header_length", 5, 4),            # Header length (5 words)
        ShortField("total_length", 40),             # Total length of IP header + payload
        ShortField("identification", 1234),         # Identification number
        BitField("flags", 0, 3),                    # Flags
        BitField("fragment_offset", 0, 13),         # Fragment offset
        ByteField("ttl", 64),                       # Time To Live (TTL)
        ByteField("protocol", 253),                 # Protocol number (custom protocol number)
        XShortField("checksum", 0),                 # Checksum (initially set to 0, will be calculated later)
        IPField("src", "128.110.217.129"),          # Source IP address
        IPField("dst", "128.110.217.149")           # Destination IP address
    ]

    def post_build(self, p, pay):
        if self.checksum == 0:
            chksum = checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

def handle_packet(packet):
    """Handle incoming packets."""
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        if ip_layer.src == "128.110.217.129" and ip_layer.dst == "128.110.217.149" and ip_layer.proto == 253:
            print(f"Received packet from {ip_layer.src} to {ip_layer.dst}")

            # Extract and parse custom header from the payload
            if packet.haslayer(Raw):
                custom_header = MyCustomHeader(packet[Raw].load)
                print("Custom Header Info:")
                print(f"  Version: {custom_header.version}")
                print(f"  Header Length: {custom_header.header_length}")
                print(f"  Total Length: {custom_header.total_length}")
                print(f"  Identification: {custom_header.identification}")
                print(f"  Flags: {custom_header.flags}")
                print(f"  Fragment Offset: {custom_header.fragment_offset}")
                print(f"  TTL: {custom_header.ttl}")
                print(f"  Protocol: {custom_header.protocol}")
                print(f"  Checksum: {custom_header.checksum}")
                
                # Send a response back to the sender
                response = IP(src=ip_layer.dst, dst=ip_layer.src) / Raw(load="Packet received")
                send(response)
            else:
                print("Received packet does not contain Raw layer")
        else:
            print(f"Received non-custom protocol packet from {ip_layer.src} to {ip_layer.dst}")

def main():
    """Main function to start packet sniffing."""
    print("Starting packet sniffing...")
    sniff(iface="eno1", prn=handle_packet)  # Capture all packets on the specified interface

if __name__ == "__main__":
    main()
