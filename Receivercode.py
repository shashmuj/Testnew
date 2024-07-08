from scapy.all import sniff, IP, Raw, send, Packet, BitField, ShortField, ByteField, IPField, XShortField, IntField, checksum
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
        IPField("dst", "128.110.217.203"),          # Destination IP address
        IntField("seq_num", 0)                      # Sequence number
    ]

def verify_checksum(packet):
    """Verify the checksum of the custom header."""
    header = bytes(packet[MyCustomHeader])
    calc_checksum = checksum(header)
    return calc_checksum == 0

def handle_packet(packet):
    if MyCustomHeader in packet:
        custom_header = packet[MyCustomHeader]
        print(f"Received packet from {custom_header.src} to {custom_header.dst}")
        print(f"  Version: {custom_header.version}")
        print(f"  Header Length: {custom_header.header_length}")
        print(f"  Total Length: {custom_header.total_length}")
        print(f"  Identification: {custom_header.identification}")
        print(f"  Flags: {custom_header.flags}")
        print(f"  Fragment Offset: {custom_header.fragment_offset}")
        print(f"  TTL: {custom_header.ttl}")
        print(f"  Protocol: {custom_header.protocol}")
        print(f"  Checksum: {custom_header.checksum}")
        print(f"  Sequence Number: {custom_header.seq_num}")
        print(f"  Source IP: {custom_header.src}")
        print(f"  Destination IP: {custom_header.dst}")
        
        # Verify checksum
        if verify_checksum(packet):
            print("Checksum is valid")
            
            # Send a response back to the sender
            response = IP(src=custom_header.dst, dst=custom_header.src) / Raw(load="Packet received")
            send(response)
        else:
            print("Checksum is invalid")
    else:
        print("Received packet does not match custom protocol")

def main():
    print("Starting packet sniffing...")
    sniff(filter="ip proto 253", iface="eno1", prn=handle_packet)

if __name__ == "__main__":
    main()
