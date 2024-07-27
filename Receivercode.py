from scapy.all import *
import argparse
import struct

# Define a simple custom protocol class
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("length", 0),
        ShortField("id", 1),
        ShortField("frag_off", 0),
        ByteField("ttl", 64),
        ByteField("proto", 253),
        XShortField("checksum", None),
        IPField("src", "0.0.0.0"),
        IPField("dst", "0.0.0.0"),
        ShortField("sport", 12345),
        ShortField("dport", 80),
        IntField("seq", 0),
        IntField("ack", 0),
        ByteField("dataofs", 5),
        ByteField("reserved", 0),
        FlagsField("flags", 0, 8, ["F", "S", "R", "P", "A", "U", "E", "C"]),
        ShortField("window", 8192),
        XShortField("tcp_chksum", None),
        ShortField("urgptr", 0)
    ]

def calculate_checksum(data):
    if len(data) % 2 != 0:
        data += b'\x00'
    s = sum(struct.unpack('!%sH' % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF

def validate_ip_checksum(ip_header):
    ip_header = bytes(ip_header)
    header_checksum = ip_header[10:12]
    calculated_checksum = calculate_checksum(ip_header[:10] + ip_header[12:])
    return header_checksum == struct.pack('!H', calculated_checksum)

def validate_tcp_checksum(ip_header, tcp_header):
    pseudo_header = struct.pack('!4s4sBBH',
                                ip_header[12:16],
                                ip_header[16:20],
                                0,  # Reserved
                                253,  # Protocol number for custom protocol
                                len(tcp_header))
    tcp_checksum = tcp_header[16:18]
    calculated_checksum = calculate_checksum(pseudo_header + tcp_header[:16] + tcp_header[18:])
    return tcp_checksum == struct.pack('!H', calculated_checksum)

def packet_callback(packet):
    # Print general packet information
    print("Received packet:")
    packet.show()

    # If IP and CustomProtocol layers are present
    if IP in packet and CustomProtocol in packet:
        ip_pkt = packet[IP]
        custom_pkt = packet[CustomProtocol]
        
        # Validate IP checksum
        if validate_ip_checksum(ip_pkt):
            print("IP checksum is valid.")
        else:
            print("IP checksum is invalid.")

        # Validate TCP checksum
        if validate_tcp_checksum(ip_pkt, bytes(custom_pkt)):
            print("TCP checksum is valid.")
        else:
            print("TCP checksum is invalid.")
        
        # Prepare and send a response packet
        response_pkt = CustomProtocol(
            version=4,
            ihl=5,
            tos=0,
            length=40,  # Example length
            id=1,
            frag_off=0,
            ttl=64,
            proto=253,
            src="0.0.0.0",  # Set appropriate values
            dst=ip_pkt.src,
            sport=80,  # Example port
            dport=12345,
            seq=0,
            ack=0,
            dataofs=5,
            flags=0x10,  # ACK flag
            window=8192,
            urgptr=0
        )

        # Send the response packet
        ip_response_pkt = IP(src=response_pkt.src, dst=response_pkt.dst, proto=response_pkt.proto) / response_pkt
        send(ip_response_pkt)
        print("Response sent:")
        response_pkt.show()

def main():
    parser = argparse.ArgumentParser(description="Receive and respond to custom protocol packets.")
    parser.add_argument("sender_ip", help="IP address of the sender to filter")
    parser.add_argument("iface", help="Network interface to use")
    args = parser.parse_args()

    # Create a filter to capture packets only from the specified sender IP
    filter_str = f"src host {args.sender_ip}"

    # Sniff packets on the specified interface with the filter
    sniff(iface=args.iface, prn=packet_callback, filter=filter_str, store=0)

if __name__ == "__main__":
    main()
