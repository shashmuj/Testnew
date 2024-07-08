from scapy.all import IP, send, Packet, BitField, ShortField, ByteField, IPField, XShortField
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

# Function to send custom packets
def send_custom_ipv4_packet(target_ip, custom_header_params):
    custom_header = MyCustomHeader(**custom_header_params)
    ip_packet = IP(dst=target_ip, proto=253) / custom_header
    
    # Print detailed packet information before sending
    print("Sending packet:")
    print(ip_packet.show())

    # Send the packet
    send(ip_packet)

# Example usage
if __name__ == "__main__":
    target_ip = "128.110.217.203"
    custom_header_params = {
        "protocol": 253,  # Using protocol number 253 for experimentation
        "src": "128.110.217.197",
        "dst": target_ip
    }
    send_custom_ipv4_packet(target_ip, custom_header_params)
