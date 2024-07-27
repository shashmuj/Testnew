from scapy.all import Packet, ByteField, ShortField, IntField, XShortField, IPField, FlagsField, send, sniff
import argparse
import socket
import struct
from scapy.layers.inet import IP

# Define the custom protocol (same as sender)
class CustomProtocol(Packet):
    name = "CustomProtocol"
    fields_desc = [
        ByteField("version", 4),
        ByteField("ihl", 5),
        ByteField("tos", 0),
        ShortField("len", 0),
        ShortField("id", 1),
        ShortField("frag_off", 0),
        ByteField("ttl", 64),
        ByteField("proto", 253),
        XShortField("chksum", None),
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

def calculate_checksums(packet):
    ip_header = bytes(packet)[:packet.ihl * 4]
    ip_checksum = calculate_checksum(ip_header)
    packet.chksum = ip_checksum
    
    tcp_header = bytes(packet)[packet.ihl * 4:]
    pseudo_header = b''.join([
        socket.inet_aton(packet.src),
        socket.inet_aton(packet.dst),
        b'\x00\x06',
        struct.pack('!H', len(tcp_header))
    ])
    tcp_checksum = calculate_checksum(pseudo_header + tcp_header)
    packet.tcp_chksum = tcp_checksum

def create_response_packet(src_ip, dst_ip, iface):
    response_packet = CustomProtocol(
        version=4,
        ihl=5,
        tos=0,
        len=60,  # Adjust as necessary
        id=2,
        frag_off=0,
        ttl=64,
        proto=253,
        src=dst_ip,
        dst=src_ip,
        sport=80,
        dport=12345,
        seq=1,
        ack=1,
        dataofs=5,
        flags=0x10,  # ACK flag for example
        window=8192,
        urgptr=0
    )
    calculate_checksums(response_packet)
    return response_packet

def process_packet(pkt):
    if IP in pkt and pkt[IP].src == sender_ip:
        # Display the header details of the received packet
        print("Received packet:")
        pkt.show()

        # Send a response packet back to the sender
        response_packet = create_response_packet(src_ip=pkt[IP].src, dst_ip=pkt[IP].dst, iface=iface)
        print("Response packet to be sent:")
        response_packet.show()
        
        # Send the response packet
        send(IP(src=response_packet.src, dst=response_packet.dst, proto=response_packet.proto)/response_packet, iface=iface)
        print("Response packet sent:")
        response_packet.show()
    else:
        print("Received packet from non-matching source IP:")
        pkt.show()

def main():
    global iface, sender_ip
    parser = argparse.ArgumentParser(description="Receive custom protocol packets from a specific sender and send a response.")
    parser.add_argument("iface", help="Network interface to use")
    parser.add_argument("sender_ip", help="Sender's IP address to filter packets from")
    args = parser.parse_args()
    iface = args.iface
    sender_ip = args.sender_ip

    print("Listening for packets from IP:", sender_ip, "on interface:", iface)
    # Sniff for incoming packets, filtering by sender's IP address
    sniff(iface=iface, prn=process_packet, filter=f"ip src {sender_ip}")

if __name__ == "__main__":
    main()
