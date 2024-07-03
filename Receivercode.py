from scapy.all import sniff, send, Packet, BitField, ShortField, ByteField, IPField, IP, XShortField, checksum

# Define a custom header class for the receiver
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
        ByteField("protocol", 143),                 # Protocol number (customize as needed)
        XShortField("checksum", 0),                 # Checksum (initially set to 0, will be calculated later)
        ShortField("seq_num", 0),                   # Sequence number
        IPField("src", "128.110.217.106"),          # Source IP address
        IPField("dst", " 128.110.217.79")            # Destination IP address
    ]

    def post_build(self, pkt, pay):
        # Calculate checksum if not provided
        if self.checksum == 0:
            chksum = checksum(bytes(pkt))
            self.checksum = chksum
        return pkt + pay

# Function to validate checksum
def validate_checksum(packet):
    chksum = packet[MyCustomHeader].checksum
    packet[MyCustomHeader].checksum = 0
    computed_chksum = checksum(bytes(packet[MyCustomHeader]))
    return chksum == computed_chksum

# Function to handle incoming packets
def handle_packet(packet):
    if MyCustomHeader in packet and validate_checksum(packet):
        custom_header = packet[MyCustomHeader]
        print(f"Received packet: {custom_header.summary()}")

        # Create an acknowledgment packet
        ack_header = MyCustomHeader(
            src=custom_header.dst,  # Swap src and dst for the response
            dst=custom_header.src,
            protocol=custom_header.protocol,
            seq_num=custom_header.seq_num + 1  # Increment sequence number
        )
        ack_ip = IP(src=custom_header.dst, dst=custom_header.src)
        ack_packet = ack_ip / ack_header

        # Send the acknowledgment packet
        send(ack_packet)
        print(f"Sent acknowledgment packet: {ack_packet.summary()}")

# Function to start sniffing
def start_sniffing(interface="eno1"):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, filter="ip proto 143", prn=handle_packet)

if __name__ == "__main__":
    # Ensure you have the correct network interface
    interface = "eno1"  # Replace with the correct interface name if needed
    start_sniffing(interface)
