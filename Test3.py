from scapy.all import *
import argparse
import socket
import struct

# Define a custom protocol
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        ByteField("version", 1),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("length", 0),
        ShortField("id", 0),
        ShortField("frag_off", 0),
        ByteField("ttl", 64),
        ByteField("proto", 253),  # Custom protocol number
        XShortField("checksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        ShortField("src_port", 1234),
        ShortField("dst_port", 80),
        IntField("seq", 0),
        IntField("ack", 0),
        ByteField("data_offset", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0, 8, ["F", "S", "R", "P", "A", "U", "E", "C"]),
        ShortField("window", 8192),
        XShortField("tcp_checksum", None),
        ShortField("urg_ptr", 0)
    ]

# Function to calculate the checksum
def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

# Calculate IP checksum
def calculate_ip_checksum(ip_header):
    return calculate_checksum(ip_header)

# Calculate TCP checksum
def calculate_custom_protocol_checksum(packet):
    ip_header = bytes(packet)[:packet.ihl * 4]  # Extract IP header
    proto_header = bytes(packet)[packet.ihl * 4:]  # Extract custom protocol header
    pseudo_header = struct.pack('!4s4sBBH',
                                socket.inet_aton(packet.src),
                                socket.inet_aton(packet.dst),
                                0,      # Reserved
                                packet.proto,  # Protocol number for custom protocol
                                len(proto_header))  # Length of custom protocol header
    return calculate_checksum(pseudo_header + proto_header)

# Create a custom protocol packet
def create_packet(dst_ip, src_ip, iface, custom_protocol_args):
    packet = CustomProtocol(
        version=custom_protocol_args['version'],
        ihl=custom_protocol_args['ihl'],
        tos=custom_protocol_args['tos'],
        length=custom_protocol_args['ihl'] * 4 + 20,  # Total length: IP header + custom protocol header
        id=custom_protocol_args['id'],
        frag_off=custom_protocol_args['frag_off'],
        ttl=custom_protocol_args['ttl'],
        proto=custom_protocol_args['proto'],
        src=src_ip,
        dst=dst_ip,
        src_port=custom_protocol_args['src_port'],
        dst_port=custom_protocol_args['dst_port'],
        seq=custom_protocol_args['seq'],
        ack=custom_protocol_args['ack'],
        data_offset=custom_protocol_args['data_offset'],
        flags=custom_protocol_args['flags'],
        window=custom_protocol_args['window'],
        urg_ptr=custom_protocol_args['urg_ptr']
    )
    
    # Calculate and set checksums
    ip_header = bytes(packet)[:packet.ihl * 4]
    packet.checksum = calculate_ip_checksum(ip_header)
    proto_header = bytes(packet)[packet.ihl * 4:]
    packet.tcp_checksum = calculate_custom_protocol_checksum(packet)
    
    return packet

# Send the custom packet
def send_custom_packet(packet, iface):
    ip_packet = IP(src=packet.src, dst=packet.dst, proto=packet.proto) / packet
    send(ip_packet, iface=iface)

# Main function to handle command-line arguments and send the packet
def main():
    parser = argparse.ArgumentParser(description="Send a custom protocol packet and receive response.")
    parser.add_argument("dst_ip", help="Destination IP address")
    parser.add_argument("src_ip", help="Source IP address")
    parser.add_argument("iface", help="Network interface to use")
    parser.add_argument("--version", type=int, default=1, help="IP version")
    parser.add_argument("--ihl", type=int, default=5, help="IP header length")
    parser.add_argument("--tos", type=int, default=0, help="Type of service")
    parser.add_argument("--id", type=int, default=0, help="Identification")
    parser.add_argument("--frag_off", type=int, default=0, help="Fragment offset")
    parser.add_argument("--ttl", type=int, default=64, help="Time to live")
    parser.add_argument("--proto", type=int, default=253, help="Protocol number")
    parser.add_argument("--src_port", type=int, default=1234, help="Source port")
    parser.add_argument("--dst_port", type=int, default=80, help="Destination port")
    parser.add_argument("--seq", type=int, default=0, help="Sequence number")
    parser.add_argument("--ack", type=int, default=0, help="Acknowledgment number")
    parser.add_argument("--data_offset", type=int, default=5, help="Data offset")
    parser.add_argument("--flags", type=int, default=0x02, help="Flags (e.g., 0x02 for SYN)")
    parser.add_argument("--window", type=int, default=8192, help="Window size")
    parser.add_argument("--urg_ptr", type=int, default=0, help="Urgent pointer")
    args = parser.parse_args()

    custom_protocol_args = vars(args)
    packet = create_packet(args.dst_ip, args.src_ip, args.iface, custom_protocol_args)
    
    # Print the packet to be sent
    print("Sending packet:")
    packet.show2()

    # Send packet using Scapy
    send_custom_packet(packet, args.iface)
    print("Packet sent. Waiting for response...")

if __name__ == "__main__":
    main()
