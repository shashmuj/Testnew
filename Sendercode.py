from scapy.all import IP, send, Packet, BitField, ShortField, ByteField, IPField, XShortField, checksum

# Define a custom header class
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
        IPField("src", "192.168.163.1"),            # Source IP address
        IPField("dst", "192.168.89.128")            # Destination IP address
    ]

    def post_build(self, p, pay):
        # Calculate checksum if not provided
        if self.checksum == 0:
            chksum = checksum(p)
            p = p[:10] + chksum.to_bytes(2, byteorder='big') + p[12:]
        return p + pay

# Function to send custom packets
def send_custom_ipv4_packet(target_ip, custom_header_params):
    # Craft the IP packet with custom header
    custom_header = MyCustomHeader(**custom_header_params)
    ip_packet = IP(dst=target_ip) / custom_header

    # Send the packet
    send(ip_packet)

# Example usage
if __name__ == "__main__":
    target_ip = "192.168.89.128"

    # Define custom header parameters
    custom_header_params = {
        "protocol": 143,
        "src": "192.168.163.1",
        "dst": target_ip
    }

    # Send the custom IPv4 packet
    send_custom_ipv4_packet(target_ip, custom_header_params)
