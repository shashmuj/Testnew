from scapy.all import IP, send, Packet, BitField, ShortField, ByteField, IPField, XShortField, checksum
import struct

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
        ByteField("protocol",143),                 # Protocol number (customize as needed)
        XShortField("checksum", 0),                 # Checksum (initially set to 0, will be calculated later)
        IPField("src", "128.110.217.163"),          # Source IP address
        IPField("dst", "128.110.217.192")            # Destination IP address (remove extra spaces)
    ]

    def post_build(self, p, pay):
        # Calculate checksum if not provided
        if self.checksum == 0:
            chksum = checksum(p)
            # Convert the checksum to bytes using struct.pack for Python 2.7 compatibility
            chksum_bytes = struct.pack('!H', chksum)
            p = p[:10] + chksum_bytes + p[12:]
        return p + pay

# Function to send custom packets
def send_custom_ipv4_packets(target_ip, custom_header_params, num_packets=10):
    for _ in range(num_packets):
        # Craft the IP packet with custom header
        custom_header = MyCustomHeader(**custom_header_params)
        ip_packet = IP(dst=target_ip) / custom_header

        # Send the packet
        send(ip_packet)

# Example usage
if __name__ == "__main__":
    target_ip = "128.110.217.192"  # Corrected destination IP address

    # Define custom header parameters
    custom_header_params = {
        "protocol":143,
        "src": "128.110.217.163",
        "dst": target_ip
    }

    # Send 10 custom IPv4 packets
    send_custom_ipv4_packets(target_ip, custom_header_params, num_packets=10)

