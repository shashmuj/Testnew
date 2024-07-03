from scapy.all import IP, send, sniff, Packet, BitField, ShortField, ByteField, IPField, XShortField, checksum
import struct
import time

# Define a custom header class for the sender
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
        ShortField("ack_num", 0),                   # Acknowledgment number
        IPField("src", "128.110.217.142"),          # Source IP address
        IPField("dst", "128.110.217.34")            # Destination IP address
    ]

    def post_build(self, p, pay):
        # Calculate checksum if not provided
        if self.checksum == 0:
            chksum = checksum(p)
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

# Function to handle incoming packets on the sender
def handle_packet(packet):
    if MyCustomHeader in packet:
        custom_header = packet[MyCustomHeader]
        print(f"Received packet: {custom_header.summary()}")
        if custom_header.flags == 0b010:  # SYN-ACK received
            print("Received SYN-ACK, sending ACK")
            # Create ACK packet
            ack_header = MyCustomHeader(
                src=custom_header.dst,
                dst=custom_header.src,
                seq_num=custom_header.ack_num,
                ack_num=custom_header.seq_num + 1,
                flags=0b001  # ACK
            )
            ack_ip = IP(src=custom_header.dst, dst=custom_header.src)
            ack_packet = ack_ip / ack_header
            send(ack_packet)
            print(f"Sent ACK packet: {ack_packet.summary()}")

# Function to send SYN packet
def send_syn(target_ip):
    custom_header = MyCustomHeader(
        src="128.110.217.142",
        dst=target_ip,
        seq_num=100,
        flags=0b001  # SYN
    )
    ip_packet = IP(dst=target_ip) / custom_header
    send(ip_packet)
    print(f"Sent SYN packet: {ip_packet.summary()}")

# Start sniffing on sender
def start_sniffing(interface="eno1"):
    sniff(iface=interface, prn=handle_packet)

if __name__ == "__main__":
    target_ip = "128.110.217.34"
    interface = "eno1"  # Replace with the correct interface name if needed

    # Send SYN packet
    send_syn(target_ip)

    # Start sniffing for SYN-ACK and ACK responses
    start_sniffing(interface)
