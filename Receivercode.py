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
        IPField("src", "37.203.171.5"),          # Source IP address
        IPField("dst", "128.110.217.192")           # Destination IP address
    ]

    def post_build(self, p, pay):
        if self.checksum == 0:
            chksum = checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

def handle_packet(packet):
    """Handle incoming packets."""
    print("=== Received Packet ===")
    packet.show()
    if IP in packet:
        ip_header = packet[IP]
        print(f"Source IP: {ip_header.src}")
        print(f"Destination IP: {ip_header.dst}")
        print(f"Protocol: {ip_header.proto}")

        # Print IP header details
        print("=== IP Header ===")
        print(f"Version: {ip_header.version}")
        print(f"IHL: {ip_header.ihl}")
        print(f"TOS: {ip_header.tos}")
        print(f"Total Length: {ip_header.len}")
        print(f"Identification: {ip_header.id}")
        print(f"Flags: {ip_header.flags}")
        print(f"Fragment Offset: {ip_header.frag}")
        print(f"TTL: {ip_header.ttl}")
        print(f"Checksum: {hex(ip_header.chksum)}")
        print(f"Options: {ip_header.options}")

        # Check if the packet has a custom header
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

            # Send a response back to the sender
            response = IP(src=custom_header.dst, dst=custom_header.src) / Raw(load="Packet received")
            send(response)

def main():
    """Main function to start packet sniffing."""
    print("Starting packet sniffing...")
    sniff(filter="ip and src host 37.203.171.5", iface="eno1", prn=handle_packet)

if __name__ == "__main__":
    main()
