from scapy.all import sniff, IP

def handle_packet(packet):
    """Handle incoming packets."""
    if IP in packet:
        print("=== Received Packet ===")
        print(f"IP Layer:")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  Protocol: {packet[IP].proto}")

        # If the packet has a custom header, print its details
        if hasattr(packet, 'MyCustomHeader'):
            custom_header = packet.MyCustomHeader
            print(f"Custom Header:")
            print(f"  Version: {custom_header.version}")
            print(f"  Header Length: {custom_header.header_length}")
            print(f"  Total Length: {custom_header.total_length}")
            print(f"  Identification: {custom_header.identification}")
            print(f"  Flags: {custom_header.flags}")
            print(f"  Fragment Offset: {custom_header.fragment_offset}")
            print(f"  TTL: {custom_header.ttl}")
            print(f"  Protocol: {custom_header.protocol}")
            print(f"  Checksum: {hex(custom_header.checksum)}")
            print(f"  Source IP: {custom_header.src}")
            print(f"  Destination IP: {custom_header.dst}")

        # You can add more handling logic or processing here

def main():
    """Main function to start packet sniffing."""
    print("Starting packet sniffing...")
    sniff(filter="ip", iface="eno1", prn=handle_packet)

if __name__ == "__main__":
    main()
