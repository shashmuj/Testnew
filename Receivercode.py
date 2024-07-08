from scapy.all import sniff, IP, send, Raw, Packet
from scapy.fields import BitField, ShortField, ByteField, IPField, XShortField, checksum
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
        IPField("src", "128.110.217.197"),          # Source IP address
        IPField("dst", "128.110.217.203")           # Destination IP address
    ]

    def post_build(self, p, pay):
        if self.checksum == 0:
            chksum = checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

def handle_packet(packet):
    """Handle incoming packets."""
    if MyCustomHeader in packet:
        custom_header = packet[MyCustomHeader]
        print(f"Received packet from {custom_header.src} to {custom_header.dst}")
        
        # Send a response back to the sender
        response = IP(src=custom_header.dst, dst=custom_header.src) / Raw(load="Packet received")
        send(response)
    else:
        print("Received packet does not match custom protocol")

def main():
    """Main function to start packet sniffing."""
    print("Starting packet sniffing...")
    sniff(filter="ip proto 253", iface="eno1", prn=handle_packet)

if __name__ == "__main__":
    main()
