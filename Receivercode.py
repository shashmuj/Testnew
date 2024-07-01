from scapy.all import sniff, send, Packet, BitField, ShortField, ByteField, IPField, IP, XShortField, checksum

class MyCustomHeader(Packet):
    name = "MyCustomHeader"
    fields_desc = [
        BitField("version", 4, 4),
        BitField("header_length", 5, 4),
        ShortField("total_length", 40),
        ShortField("identification", 1234),
        BitField("flags", 0, 3),
        BitField("fragment_offset", 0, 13),
        ByteField("ttl", 64),
        ByteField("protocol", 143),
        XShortField("checksum", 0),
        ShortField("seq_num", 0),
        IPField("src", "192.168.163.1"),
        IPField("dst", "192.168.89.128")
    ]

# Function to verify the checksum
def verify_checksum(packet):
    original_checksum = packet[MyCustomHeader].checksum
    packet[MyCustomHeader].checksum = 0
    computed_checksum = checksum(bytes(packet[MyCustomHeader]))
    packet[MyCustomHeader].checksum = original_checksum
    return original_checksum == computed_checksum

# Function to handle incoming packets
def handle_packet(packet):
    if MyCustomHeader in packet:
        custom_header = packet[MyCustomHeader]
        print(f"Received packet: {custom_header.summary()}")

        # Validate checksum
        if verify_checksum(packet):
            print("Checksum is valid.")
        else:
            print("Checksum is invalid.")

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
    else:
        print("Received packet does not match MyCustomHeader")

# Function to start sniffing
def start_sniffing(interface="ens33"):
    print(f"Starting packet sniffing on interface: {interface}")
    sniff(iface=interface, filter="ip", prn=handle_packet, store=0)

if __name__ == "__main__":
    interface = "ens33"
    start_sniffing(interface)
